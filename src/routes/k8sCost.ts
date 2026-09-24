import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, guarded, okJson, errJson } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { resolveCredentials, type ResolvableConnection } from './permissions';
import { parseCpuMillicores } from '../lib/k8sQuantity';
import { resolveNodeMonthlyCost, computeClusterAllocation, type NodeInput, type PodInput } from '../lib/k8sCostAllocation';

export const k8sCostRoutes = new Hono<{ Bindings: Env }>();

interface EksNodeRow {
  resource_id: string; resource_name: string; region: string;
  relationships: { clusterName?: string } | null;
  metadata: { instanceType?: string; ec2InstanceId?: string; allocatableCpu?: string; allocatableMemory?: string } | null;
}
interface EksPodRow {
  resource_name: string; state: string | null;
  relationships: { clusterName?: string } | null;
  metadata: {
    namespace?: string; nodeName?: string; cpuRequestMillicores?: number; hasResourceRequest?: boolean;
    workloadOwner?: { kind: string; name: string };
  } | null;
}

/**
 * GET /api/aws-accounts/accounts/:id/eks/cost-allocation?clusterId=<region>/<clusterName>
 *
 * Real, per-pod Kubernetes cost allocation for EKS -- the OpenCost/CNCF
 * technique (see k8sCostAllocation.ts's own doc comment for the full
 * methodology and why every number here traces to a real source). Reads
 * already-synced eks_node/eks_pod inventory (run Discovery/Sync first if
 * a cluster was only just connected or the scanner was only just extended
 * to capture the fields this needs) -- this route does no K8s API calls of
 * its own, only AWS's Pricing API as a cost-resolution fallback.
 *
 * `clusterId` (optional) scopes to one cluster (format matches the
 * scanner's own resource_id prefix: "<region>/<clusterName>"); omitted
 * aggregates every EKS cluster on this connection.
 */
k8sCostRoutes.get('/accounts/:id/eks/cost-allocation', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'containers', 'read');

    const connectionId = c.req.param('id');
    const clusterId = c.req.query('clusterId'); // "<region>/<clusterName>" or undefined for all clusters
    const clusterName = clusterId?.split('/').slice(1).join('/'); // clusterId's region prefix isn't needed beyond validating shape

    const rows = await db.select<(ResolvableConnection & { id: string })[]>('cloud_connections', {
      select: 'id,connection_method,credentials_encrypted,role_arn,external_id,default_region',
      filters: { id: `eq.${connectionId}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const connection = rows[0];
    if (!connection) return errJson(404, 'Account not found');

    const resolved = await resolveCredentials(c.env, connection);
    if ('error' in resolved) return errJson(400, resolved.error);
    const { creds } = resolved;

    const [nodeRows, podRows] = await Promise.all([
      db.select<EksNodeRow[]>('cloud_resources', {
        select: 'resource_id,resource_name,region,relationships,metadata',
        filters: { connection_id: `eq.${connectionId}`, resource_type_key: 'eq.eks_node', deleted_at: 'is.null' },
        limit: 5000,
      }),
      db.select<EksPodRow[]>('cloud_resources', {
        select: 'resource_name,state,relationships,metadata',
        filters: { connection_id: `eq.${connectionId}`, resource_type_key: 'eq.eks_pod', deleted_at: 'is.null' },
        limit: 5000,
      }),
    ]);

    const scopedNodes = clusterName ? nodeRows.filter((n) => n.relationships?.clusterName === clusterName) : nodeRows;
    // Only pods actually Running consume node resources right now -- a
    // Pending/Failed/Succeeded pod isn't holding a real allocation.
    const scopedPods = (clusterName ? podRows.filter((p) => p.relationships?.clusterName === clusterName) : podRows)
      .filter((p) => p.state === 'Running');

    // Resolve each distinct node's real monthly cost once (nodes can host
    // many pods; never re-resolve per-pod).
    const nodeInputs: NodeInput[] = await Promise.all(
      scopedNodes.map(async (n): Promise<NodeInput> => {
        const cost = await resolveNodeMonthlyCost(
          db, creds, connectionId, n.region, n.metadata?.instanceType, n.metadata?.ec2InstanceId,
        );
        return {
          nodeName: n.resource_name,
          allocatableCpuMillicores: parseCpuMillicores(n.metadata?.allocatableCpu),
          monthlyCost: cost?.monthlyCost ?? null,
          costSource: cost?.source,
        };
      }),
    );

    const podInputs: PodInput[] = scopedPods.map((p): PodInput => ({
      podName: p.resource_name,
      namespace: p.metadata?.namespace ?? 'default',
      nodeName: p.metadata?.nodeName,
      cpuRequestMillicores: p.metadata?.cpuRequestMillicores ?? 0,
      hasResourceRequest: p.metadata?.hasResourceRequest ?? false,
      workloadOwner: p.metadata?.workloadOwner,
    }));

    const allocation = computeClusterAllocation(nodeInputs, podInputs);

    return okJson({
      ...allocation,
      nodeCostSources: nodeInputs.reduce(
        (acc, n) => { if (n.costSource) acc[n.costSource] = (acc[n.costSource] ?? 0) + 1; return acc; },
        {} as Record<string, number>,
      ),
      totalNodes: scopedNodes.length,
      totalPods: scopedPods.length,
    });
  }),
);
