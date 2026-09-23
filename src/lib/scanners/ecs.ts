import { callJsonApi } from '../awsApi';
import { reportWalk, toIso, walkJsonRpc } from './restJson';
import { mapWithConcurrency, reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AmazonEC2ContainerServiceV20141113';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ECS_RESOURCE_TYPES = ['ecs_cluster', 'ecs_service', 'ecs_task_definition', 'ecs_capacity_provider', 'ecs_task'] as const;

/** Clusters whose services and tasks are enumerated per region-step. */
const MAX_CLUSTERS_ENUMERATED = 25;
/** Running tasks recorded per region-step (tasks are high-churn and numerous). */
const MAX_TASKS = 300;
/** DescribeTaskDefinition follow-ups (latest revision per family). */
const MAX_TASK_DEF_DETAILS = 25;
const CONCURRENCY = 4;

interface EcsCluster {
  clusterArn: string; clusterName: string; status?: string;
  registeredContainerInstancesCount?: number; runningTasksCount?: number; pendingTasksCount?: number; activeServicesCount?: number;
  tags?: { key: string; value: string }[];
  settings?: { name?: string; value?: string }[];
  configuration?: { executeCommandConfiguration?: { kmsKeyId?: string; logging?: string } };
  capacityProviders?: string[];
}
interface EcsService {
  serviceArn: string; serviceName: string; clusterArn?: string; status?: string;
  desiredCount?: number; runningCount?: number; pendingCount?: number; launchType?: string; taskDefinition?: string; createdAt?: number;
  platformVersion?: string; enableExecuteCommand?: boolean; propagateTags?: string; schedulingStrategy?: string;
  networkConfiguration?: { awsvpcConfiguration?: { assignPublicIp?: string; subnets?: string[]; securityGroups?: string[] } };
  deploymentConfiguration?: { deploymentCircuitBreaker?: { enable?: boolean; rollback?: boolean } };
  loadBalancers?: { targetGroupArn?: string }[];
}
interface EcsCapacityProvider { capacityProviderArn: string; name: string; status?: string; updateStatus?: string }
interface EcsTask {
  taskArn: string; clusterArn?: string; lastStatus?: string; desiredStatus?: string; taskDefinitionArn?: string;
  launchType?: string; cpu?: string; memory?: string; createdAt?: number; enableExecuteCommand?: boolean;
}
interface ContainerDefinition {
  name?: string; image?: string; privileged?: boolean; readonlyRootFilesystem?: boolean; user?: string;
  environment?: { name?: string; value?: string }[]; secrets?: { name?: string }[];
  logConfiguration?: { logDriver?: string };
}
export interface TaskDefinition {
  taskDefinitionArn?: string; family?: string; revision?: number;
  networkMode?: string; pidMode?: string; ipcMode?: string;
  taskRoleArn?: string; executionRoleArn?: string; requiresCompatibilities?: string[];
  containerDefinitions?: ContainerDefinition[];
}

/** Environment variable NAMES that suggest a credential. Values are never stored. */
const SECRET_NAME_PATTERN = /(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|access[_-]?key)/i;

/** Container-security evidence for one task definition (FSBP ECS.1/.3/.4/.5/.8/.9). */
export function taskDefinitionEvidence(td: TaskDefinition | undefined) {
  if (!td) return { detailsCollected: false };
  const containers = td.containerDefinitions ?? [];
  const isRoot = (u: string | undefined) => !u || u === 'root' || u === '0' || u.startsWith('0:');
  return {
    detailsCollected: true,
    networkMode: td.networkMode ?? null,
    // ECS.1: host network mode shares the host's network namespace.
    hostNetworkMode: td.networkMode === 'host',
    // ECS.3: sharing the host's process namespace.
    hostPidMode: td.pidMode === 'host',
    hostIpcMode: td.ipcMode === 'host',
    // ECS.4: privileged containers.
    privilegedContainers: containers.filter((c) => c.privileged).map((c) => c.name ?? '?'),
    // ECS.5: read-only root filesystems.
    containersWithWritableRoot: containers.filter((c) => !c.readonlyRootFilesystem).map((c) => c.name ?? '?'),
    containersRunningAsRoot: containers.filter((c) => isRoot(c.user)).map((c) => c.name ?? '?'),
    // ECS.8: secrets belong in `secrets`, not plain-text `environment` (names only).
    plaintextSecretLikeEnvNames: [...new Set(containers.flatMap((c) => (c.environment ?? []).map((e) => e.name).filter((n): n is string => !!n && SECRET_NAME_PATTERN.test(n))))],
    // ECS.9: every container should have a log configuration.
    containersWithoutLogging: containers.filter((c) => !c.logConfiguration?.logDriver).map((c) => c.name ?? '?'),
    images: [...new Set(containers.map((c) => c.image).filter((v): v is string => !!v))],
    requiresCompatibilities: td.requiresCompatibilities ?? [],
  };
}

const chunk = <T>(xs: T[], n: number): T[][] => Array.from({ length: Math.ceil(xs.length / n) }, (_, i) => xs.slice(i * n, i * n + n));

/** `...:task-definition/family:revision` → [family, revision]. */
function familyRevision(arn: string): [string, number] {
  const tail = arn.split('/').pop() ?? arn;
  const idx = tail.lastIndexOf(':');
  return idx < 0 ? [tail, 0] : [tail.slice(0, idx), Number(tail.slice(idx + 1)) || 0];
}

/**
 * Amazon ECS: clusters, services, running tasks, active task definitions and
 * capacity providers (JSON-RPC).
 *
 * What changed, and why:
 *  - Every list paginates, and every Describe* is chunked to its API limit
 *    (clusters/tasks 100, services 10). The previous version capped clusters
 *    at 10, services at 10 per cluster, tasks at 25 in 5 clusters and task
 *    definitions at 45 -- all SILENTLY, so everything past a cap looked
 *    deleted. Remaining bounds (clusters enumerated for services/tasks, total
 *    tasks) are reported as truncation when hit.
 *  - Evidence for FSBP ECS controls: public IPs on services, ECS Exec,
 *    circuit breakers, Container Insights, exec-session logging/KMS, and
 *    task-definition container posture (latest revision per family).
 */
export async function scanEcs(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `ecs.${ctx.region}.amazonaws.com`;
  const call = (action: string, body: Record<string, unknown>) =>
    callJsonApi(ctx.creds, { service: 'ecs', region: ctx.region, host, target: `${TARGET_PREFIX}.${action}`, body });
  const list = <T>(action: string, body: Record<string, unknown>, key: string) =>
    walkJsonRpc<T>(ctx, { service: 'ecs', host, target: `${TARGET_PREFIX}.${action}`, body }, key, { tokenIn: 'nextToken', tokenOut: 'nextToken' });

  const [clusterWalk, tdWalk, cpWalk] = await Promise.all([
    list<string>('ListClusters', { maxResults: 100 }, 'clusterArns'),
    list<string>('ListTaskDefinitions', { status: 'ACTIVE', maxResults: 100 }, 'taskDefinitionArns'),
    list<EcsCapacityProvider>('DescribeCapacityProviders', { maxResults: 10 }, 'capacityProviders'),
  ]);
  reportWalk(ctx, clusterWalk, 'ecs', 'ListClusters');
  reportWalk(ctx, tdWalk, 'ecs', 'ListTaskDefinitions');
  reportWalk(ctx, cpWalk, 'ecs', 'DescribeCapacityProviders');

  const out: ScannedResource[] = [];

  // ── Clusters ──────────────────────────────────────────────────────────────
  const clusterArns = [...new Set(clusterWalk.items.filter((a): a is string => typeof a === 'string'))];
  const clusters: EcsCluster[] = [];
  const clusterBatches = await mapWithConcurrency(chunk(clusterArns, 100), CONCURRENCY, (batch) =>
    call('DescribeClusters', { clusters: batch, include: ['TAGS', 'SETTINGS', 'CONFIGURATIONS'] }));
  for (const r of clusterBatches) {
    if (!r.ok) { reportListingFailure(ctx, { service: 'ecs', action: 'DescribeClusters', region: ctx.region, httpStatus: r.status }); continue; }
    clusters.push(...((r.body as { clusters?: EcsCluster[] } | null)?.clusters ?? []));
  }
  for (const cl of clusters) {
    if (!cl?.clusterArn) continue;
    const tags = Object.fromEntries((cl.tags ?? []).map((t) => [t.key, t.value]));
    const insights = cl.settings?.find((s) => s.name === 'containerInsights')?.value ?? null;
    out.push({
      resourceTypeKey: 'ecs_cluster', resourceId: cl.clusterArn, region: ctx.region, resourceName: cl.clusterName,
      state: cl.status, tags,
      metadata: {
        registeredContainerInstances: cl.registeredContainerInstancesCount, runningTasks: cl.runningTasksCount,
        pendingTasks: cl.pendingTasksCount, activeServices: cl.activeServicesCount,
        // ECS.12: Container Insights ("enabled" or "enhanced").
        containerInsights: insights,
        execCommandLogging: cl.configuration?.executeCommandConfiguration?.logging ?? null,
        execCommandKmsKeyId: cl.configuration?.executeCommandConfiguration?.kmsKeyId ?? null,
        capacityProviders: cl.capacityProviders ?? [],
      },
    });
  }

  // ── Services and tasks (bounded by cluster count and total tasks) ─────────
  const enumerated = clusters.filter((c) => c?.clusterArn).slice(0, MAX_CLUSTERS_ENUMERATED);
  if (clusters.length > enumerated.length) {
    console.error(`ECS ${ctx.region}: ${clusters.length} clusters; services/tasks enumerated for the first ${enumerated.length}.`);
    reportListingFailure(ctx, { service: 'ecs', action: 'ListServices', region: ctx.region, truncated: true });
    reportListingFailure(ctx, { service: 'ecs', action: 'ListTasks', region: ctx.region, truncated: true });
  }

  let taskBudget = MAX_TASKS;
  let tasksTruncated = false;
  for (const cl of enumerated) {
    const svcWalk = await list<string>('ListServices', { cluster: cl.clusterArn, maxResults: 100 }, 'serviceArns');
    reportWalk(ctx, svcWalk, 'ecs', 'ListServices');
    const svcBatches = await mapWithConcurrency(chunk(svcWalk.items, 10), CONCURRENCY, (batch) =>
      call('DescribeServices', { cluster: cl.clusterArn, services: batch }));
    for (const r of svcBatches) {
      if (!r.ok) { reportListingFailure(ctx, { service: 'ecs', action: 'DescribeServices', region: ctx.region, httpStatus: r.status }); continue; }
      for (const svc of (r.body as { services?: EcsService[] } | null)?.services ?? []) {
        if (!svc?.serviceArn) continue;
        const net = svc.networkConfiguration?.awsvpcConfiguration;
        out.push({
          resourceTypeKey: 'ecs_service', resourceId: svc.serviceArn, region: ctx.region, resourceName: svc.serviceName,
          state: svc.status,
          metadata: {
            desiredCount: svc.desiredCount, runningCount: svc.runningCount, pendingCount: svc.pendingCount,
            launchType: svc.launchType, createdAt: svc.createdAt, createdAtIso: toIso(svc.createdAt),
            // ECS.2: services should not auto-assign public IPs.
            assignPublicIp: net?.assignPublicIp ?? null,
            platformVersion: svc.platformVersion ?? null,
            enableExecuteCommand: svc.enableExecuteCommand ?? false,
            deploymentCircuitBreaker: svc.deploymentConfiguration?.deploymentCircuitBreaker?.enable ?? null,
            propagateTags: svc.propagateTags ?? null,
            schedulingStrategy: svc.schedulingStrategy ?? null,
          },
          relationships: {
            clusterArn: cl.clusterArn, taskDefinitionArn: svc.taskDefinition,
            subnetIds: net?.subnets ?? [], securityGroupIds: net?.securityGroups ?? [],
            targetGroupArns: (svc.loadBalancers ?? []).map((l) => l.targetGroupArn).filter((v): v is string => !!v),
          },
        });
      }
    }

    if (taskBudget <= 0) { tasksTruncated = true; continue; }
    const taskWalk = await walkJsonRpc<string>(ctx, { service: 'ecs', host, target: `${TARGET_PREFIX}.ListTasks`, body: { cluster: cl.clusterArn, maxResults: 100 } },
      'taskArns', { tokenIn: 'nextToken', tokenOut: 'nextToken', maxPages: Math.max(1, Math.ceil(taskBudget / 100)) });
    let taskArns = taskWalk.items;
    if (taskArns.length > taskBudget || !taskWalk.complete) tasksTruncated = true;
    taskArns = taskArns.slice(0, taskBudget);
    taskBudget -= taskArns.length;
    const taskBatches = await mapWithConcurrency(chunk(taskArns, 100), CONCURRENCY, (batch) =>
      call('DescribeTasks', { cluster: cl.clusterArn, tasks: batch }));
    for (const r of taskBatches) {
      if (!r.ok) { tasksTruncated = true; continue; }
      for (const t of (r.body as { tasks?: EcsTask[] } | null)?.tasks ?? []) {
        if (!t?.taskArn) continue;
        out.push({
          resourceTypeKey: 'ecs_task', resourceId: t.taskArn, region: ctx.region,
          resourceName: t.taskArn.split('/').pop(), state: t.lastStatus,
          metadata: {
            desiredStatus: t.desiredStatus, launchType: t.launchType, cpu: t.cpu, memory: t.memory, createdAt: t.createdAt,
            enableExecuteCommand: t.enableExecuteCommand ?? false,
          },
          relationships: { clusterArn: t.clusterArn ?? cl.clusterArn, taskDefinitionArn: t.taskDefinitionArn },
        });
      }
    }
  }
  if (tasksTruncated) {
    console.error(`ECS ${ctx.region}: running tasks not fully enumerated (cap ${MAX_TASKS}); coverage degraded.`);
    reportListingFailure(ctx, { service: 'ecs', action: 'ListTasks', region: ctx.region, truncated: true });
  }

  // ── Capacity providers ────────────────────────────────────────────────────
  for (const cp of cpWalk.items) {
    // Every account gets the two AWS-managed Fargate providers in every
    // region with zero setup -- fixed, well-known names, not customer resources.
    if (!cp?.capacityProviderArn || cp.name === 'FARGATE' || cp.name === 'FARGATE_SPOT') continue;
    out.push({
      resourceTypeKey: 'ecs_capacity_provider', resourceId: cp.capacityProviderArn, region: ctx.region, resourceName: cp.name,
      state: cp.status, metadata: { updateStatus: cp.updateStatus },
    });
  }

  // ── Task definitions (every ACTIVE revision; details for the latest per family) ──
  const tdArns = [...new Set(tdWalk.items.filter((a): a is string => typeof a === 'string'))];
  const latestByFamily = new Map<string, { arn: string; rev: number }>();
  for (const arn of tdArns) {
    const [family, rev] = familyRevision(arn);
    const cur = latestByFamily.get(family);
    if (!cur || rev > cur.rev) latestByFamily.set(family, { arn, rev });
  }
  const tdDetails = new Map<string, TaskDefinition>();
  await mapWithConcurrency([...latestByFamily.values()].slice(0, MAX_TASK_DEF_DETAILS), CONCURRENCY, async ({ arn }) => {
    const r = await call('DescribeTaskDefinition', { taskDefinition: arn });
    const td = r.ok ? (r.body as { taskDefinition?: TaskDefinition } | null)?.taskDefinition : undefined;
    if (td) tdDetails.set(arn, td);
  });
  for (const arn of tdArns) {
    const [family, rev] = familyRevision(arn);
    const td = tdDetails.get(arn);
    out.push({
      resourceTypeKey: 'ecs_task_definition', resourceId: arn, region: ctx.region, resourceName: `${family}:${rev}`,
      metadata: { family, revision: rev, isLatestRevision: latestByFamily.get(family)?.arn === arn, ...taskDefinitionEvidence(td) },
      relationships: { taskRoleArn: td?.taskRoleArn ?? null, executionRoleArn: td?.executionRoleArn ?? null },
    });
  }

  return out;
}
