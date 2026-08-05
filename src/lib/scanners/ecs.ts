import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AmazonEC2ContainerServiceV20141113';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ECS_RESOURCE_TYPES = ['ecs_cluster', 'ecs_service', 'ecs_task_definition', 'ecs_capacity_provider', 'ecs_task'] as const;

interface EcsCluster {
  clusterArn: string; clusterName: string; status?: string;
  registeredContainerInstancesCount?: number; runningTasksCount?: number; pendingTasksCount?: number; activeServicesCount?: number;
  tags?: { key: string; value: string }[];
}
interface EcsService {
  serviceArn: string; serviceName: string; clusterArn?: string; status?: string;
  desiredCount?: number; runningCount?: number; pendingCount?: number; launchType?: string; taskDefinition?: string; createdAt?: number;
}
interface EcsCapacityProvider {
  capacityProviderArn: string; name: string; status?: string; updateStatus?: string;
}
interface EcsTask {
  taskArn: string; clusterArn?: string; lastStatus?: string; desiredStatus?: string; taskDefinitionArn?: string;
  launchType?: string; cpu?: string; memory?: string; createdAt?: number;
}

/**
 * Clusters, their services, and active task definition families — one
 * JSON-RPC signer, several List/Describe calls. Capped at the first 10
 * clusters and, per cluster, the first 10 services (ECS's own
 * DescribeServices limit is 10 ARNs per call, so this is one call per
 * cluster rather than a paginated loop) — an account with more than that
 * needs a chunked follow-up, not built yet.
 */
export async function scanEcs(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `ecs.${ctx.region}.amazonaws.com`;
  const call = async (action: string, body: Record<string, unknown> = {}) => {
    const result = await callJsonApi(ctx.creds, { service: 'ecs', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.${action}`, body });
    if (!result.ok) {
      console.error(`ECS ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return null;
    }
    return result.body as Record<string, unknown>;
  };

  const out: ScannedResource[] = [];

  const listClusters = await call('ListClusters');
  const clusterArns = ((listClusters?.clusterArns as string[] | undefined) ?? []).slice(0, 10);

  if (clusterArns.length > 0) {
    const describeClusters = await call('DescribeClusters', { clusters: clusterArns, include: ['TAGS'] });
    const clusters = (describeClusters?.clusters as EcsCluster[] | undefined) ?? [];
    for (const cl of clusters) {
      const tags = Object.fromEntries((cl.tags ?? []).map((t) => [t.key, t.value]));
      out.push({
        resourceTypeKey: 'ecs_cluster', resourceId: cl.clusterArn, region: ctx.region, resourceName: cl.clusterName,
        state: cl.status, tags,
        metadata: {
          registeredContainerInstances: cl.registeredContainerInstancesCount, runningTasks: cl.runningTasksCount,
          pendingTasks: cl.pendingTasksCount, activeServices: cl.activeServicesCount,
        },
      });

      const listServices = await call('ListServices', { cluster: cl.clusterArn });
      const serviceArns = ((listServices?.serviceArns as string[] | undefined) ?? []).slice(0, 10);
      if (serviceArns.length > 0) {
        const describeServices = await call('DescribeServices', { cluster: cl.clusterArn, services: serviceArns });
        const services = (describeServices?.services as EcsService[] | undefined) ?? [];
        for (const svc of services) {
          out.push({
            resourceTypeKey: 'ecs_service', resourceId: svc.serviceArn, region: ctx.region, resourceName: svc.serviceName,
            state: svc.status, relationships: { clusterArn: cl.clusterArn, taskDefinitionArn: svc.taskDefinition },
            metadata: {
              desiredCount: svc.desiredCount, runningCount: svc.runningCount, pendingCount: svc.pendingCount,
              launchType: svc.launchType, createdAt: svc.createdAt,
            },
          });
        }
      }
    }

    // Tasks are listed per-cluster too — capped to the first 5 clusters
    // (not all 10 the loop above allows) to leave headroom in Cloudflare's
    // free-tier ~50-subrequest budget alongside the services fan-out above.
    for (const cl of clusters.slice(0, 5)) {
      const listTasks = await call('ListTasks', { cluster: cl.clusterArn, maxResults: 25 });
      const taskArns = (listTasks?.taskArns as string[] | undefined) ?? [];
      if (taskArns.length === 0) continue;
      const describeTasks = await call('DescribeTasks', { cluster: cl.clusterArn, tasks: taskArns });
      for (const t of (describeTasks?.tasks as EcsTask[] | undefined) ?? []) {
        out.push({
          resourceTypeKey: 'ecs_task', resourceId: t.taskArn, region: ctx.region,
          resourceName: t.taskArn.split('/').pop(), state: t.lastStatus,
          metadata: { desiredStatus: t.desiredStatus, launchType: t.launchType, cpu: t.cpu, memory: t.memory, createdAt: t.createdAt },
          relationships: { clusterArn: t.clusterArn ?? cl.clusterArn, taskDefinitionArn: t.taskDefinitionArn },
        });
      }
    }
  }

  const capacityProviders = await call('DescribeCapacityProviders');
  for (const cp of (capacityProviders?.capacityProviders as EcsCapacityProvider[] | undefined) ?? []) {
    // Every account gets the two AWS-managed Fargate capacity providers in
    // every region with zero setup — fixed, well-known names, not something
    // a customer created. Confirmed via a real discovery run: 34 = exactly
    // 2 × 17 scan regions, same AWS-managed-noise problem as prefix lists
    // and patch baselines above.
    if (cp.name === 'FARGATE' || cp.name === 'FARGATE_SPOT') continue;
    out.push({
      resourceTypeKey: 'ecs_capacity_provider', resourceId: cp.capacityProviderArn, region: ctx.region, resourceName: cp.name,
      state: cp.status, metadata: { updateStatus: cp.updateStatus },
    });
  }

  const listTaskDefs = await call('ListTaskDefinitions', { status: 'ACTIVE', maxResults: 45 });
  const taskDefArns = (listTaskDefs?.taskDefinitionArns as string[] | undefined) ?? [];
  for (const arn of taskDefArns) {
    // arn:aws:ecs:region:account:task-definition/family:revision
    const familyRevision = arn.split('/').pop() ?? arn;
    out.push({ resourceTypeKey: 'ecs_task_definition', resourceId: arn, region: ctx.region, resourceName: familyRevision });
  }

  return out;
}
