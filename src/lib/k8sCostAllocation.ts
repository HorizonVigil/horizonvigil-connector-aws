import type { Db } from '@horizonvigil/shared-lib';
import { callJsonApi, type AwsCreds } from './awsApi';

/**
 * Kubernetes cost allocation for EKS -- the OpenCost/CNCF technique:
 *   pod_cost = node_monthly_cost x (pod_cpu_request / node_allocatable_cpu)
 * CPU-request-proportional only for v1 (memory-weighted blending is a
 * documented fast-follow, not silently claimed here). Every dollar figure
 * traces to either this month's real CUR-billed cost or AWS's own published
 * on-demand rate -- never a locally invented number -- and a pod/node this
 * can't resolve a real cost for is excluded and counted, never shown as $0.
 */

// Scoped to exactly the ~15 regions this product's Cloud Accounts region
// filter already supports -- the AWS Pricing API's `location` filter takes
// this friendly name, not a region code, and there's no documented
// region-code filter to use instead. A region outside this table falls back
// to "pricing unavailable" (excluded, disclosed), not silently guessed.
export const AWS_REGION_TO_PRICING_LOCATION: Record<string, string> = {
  'us-east-1': 'US East (N. Virginia)',
  'us-east-2': 'US East (Ohio)',
  'us-west-1': 'US West (N. California)',
  'us-west-2': 'US West (Oregon)',
  'ca-central-1': 'Canada (Central)',
  'sa-east-1': 'South America (Sao Paulo)',
  'eu-west-1': 'EU (Ireland)',
  'eu-west-2': 'EU (London)',
  'eu-central-1': 'EU (Frankfurt)',
  'eu-north-1': 'EU (Stockholm)',
  'ap-south-1': 'Asia Pacific (Mumbai)',
  'ap-southeast-1': 'Asia Pacific (Singapore)',
  'ap-southeast-2': 'Asia Pacific (Sydney)',
  'ap-northeast-1': 'Asia Pacific (Tokyo)',
  'ap-northeast-2': 'Asia Pacific (Seoul)',
};

// The Pricing API's signed endpoint is only real in us-east-1/ap-south-1,
// regardless of which region's instance pricing you're actually querying
// for -- that's expressed via the `location` filter in the request body,
// not the call's own SigV4 region.
const PRICING_HOST = 'api.pricing.us-east-1.amazonaws.com';
const PRICING_CALL_REGION = 'us-east-1';

export interface NodeCostResult {
  monthlyCost: number;
  /** 'cur_actual': this month's real AWS-billed cost for this exact instance (CUR). 'ondemand_estimate': AWS's published on-demand list price -- not the customer's actual (possibly RI/Savings-Plan-discounted) rate. */
  source: 'cur_actual' | 'ondemand_estimate';
}

interface ResourceCostRow { unblended_cost: string; usage_date: string }

/** Real Price List API response shape: PriceList is an array of JSON-encoded STRINGS, not nested objects -- each needs its own JSON.parse. */
interface PricingGetProductsBody { PriceList?: string[] }
interface PricingProductTerms {
  terms?: { OnDemand?: Record<string, { priceDimensions?: Record<string, { pricePerUnit?: { USD?: string } }> }> };
}

function extractOnDemandHourlyRate(body: unknown): number | null {
  const priceList = (body as PricingGetProductsBody)?.PriceList;
  if (!priceList || priceList.length === 0) return null;
  let parsed: PricingProductTerms;
  try { parsed = JSON.parse(priceList[0]); } catch { return null; }
  const onDemand = parsed.terms?.OnDemand;
  if (!onDemand) return null;
  for (const term of Object.values(onDemand)) {
    for (const dim of Object.values(term.priceDimensions ?? {})) {
      const usd = dim.pricePerUnit?.USD;
      if (usd == null) continue;
      const n = Number(usd);
      if (Number.isFinite(n)) return n;
    }
  }
  return null;
}

/**
 * Resolves one EKS node's real monthly cost, in priority order:
 *  1. This month's actual CUR-billed cost for its underlying EC2 instance
 *     (resource_costs) -- average of the days billed so far this month x 30.
 *     Real, but only present for accounts that enabled CUR ingestion.
 *  2. AWS's public on-demand list price for the instance type/region via
 *     the Pricing API (already-granted `pricing:GetProducts` -- see
 *     leastPrivilegePolicy.ts) x 730 hours/month.
 * Returns null (never a guessed number) when neither source can answer --
 * the caller must exclude that node from allocation, not zero-fill it.
 */
export async function resolveNodeMonthlyCost(
  db: Db, creds: AwsCreds, connectionId: string, region: string, instanceType: string | undefined, ec2InstanceId: string | undefined,
): Promise<NodeCostResult | null> {
  if (ec2InstanceId) {
    const monthStart = new Date();
    monthStart.setUTCDate(1);
    const rows = await db.select<ResourceCostRow[]>('resource_costs', {
      select: 'unblended_cost,usage_date',
      filters: { connection_id: `eq.${connectionId}`, resource_id: `eq.${ec2InstanceId}`, usage_date: `gte.${monthStart.toISOString().slice(0, 10)}` },
      limit: 31,
    });
    if (rows.length > 0) {
      const total = rows.reduce((sum, r) => sum + Number(r.unblended_cost || 0), 0);
      const avgDaily = total / rows.length;
      return { monthlyCost: Math.round(avgDaily * 30 * 100) / 100, source: 'cur_actual' };
    }
  }

  if (!instanceType) return null;
  const location = AWS_REGION_TO_PRICING_LOCATION[region];
  if (!location) return null;

  const result = await callJsonApi(creds, {
    service: 'pricing', region: PRICING_CALL_REGION, host: PRICING_HOST,
    target: 'AWSPriceListService.GetProducts',
    body: {
      ServiceCode: 'AmazonEC2',
      Filters: [
        { Type: 'TERM_MATCH', Field: 'instanceType', Value: instanceType },
        { Type: 'TERM_MATCH', Field: 'location', Value: location },
        { Type: 'TERM_MATCH', Field: 'tenancy', Value: 'Shared' },
        { Type: 'TERM_MATCH', Field: 'operatingSystem', Value: 'Linux' },
        { Type: 'TERM_MATCH', Field: 'preInstalledSw', Value: 'NA' },
        { Type: 'TERM_MATCH', Field: 'capacitystatus', Value: 'Used' },
      ],
      FormatVersion: 'aws_v1', MaxResults: 1,
    },
  });
  if (!result.ok) return null;
  const hourly = extractOnDemandHourlyRate(result.body);
  return hourly != null ? { monthlyCost: Math.round(hourly * 730 * 100) / 100, source: 'ondemand_estimate' } : null;
}

// ── Pure allocation math (no I/O -- fully unit-testable) ──────────────────

export interface NodeInput {
  nodeName: string; // matches K8s Node.metadata.name / Pod.spec.nodeName
  allocatableCpuMillicores: number | null;
  monthlyCost: number | null; // null = cost unresolved -- excluded, see resolveNodeMonthlyCost
  costSource?: 'cur_actual' | 'ondemand_estimate';
}
export interface PodInput {
  podName: string;
  namespace: string;
  nodeName?: string;
  cpuRequestMillicores: number;
  hasResourceRequest: boolean;
  workloadOwner?: { kind: string; name: string };
}
export interface PodAllocation {
  podName: string; namespace: string; nodeName?: string;
  monthlyCost: number | null;
  excludedReason?: 'no_matching_node' | 'node_cost_unavailable' | 'node_allocatable_unknown' | 'no_cpu_request';
}
export interface NamespaceCost { namespace: string; monthlyCost: number; podCount: number }
export interface WorkloadCost { key: string; kind: string; name: string; namespace: string; monthlyCost: number; podCount: number }
export interface ClusterAllocationResult {
  totalNodeCost: number;
  totalAllocatedCost: number;
  /** Node cost not attributed to any pod -- real spare capacity plus any pod excluded above (e.g. no declared CPU request). A real, meaningful number, not a rounding artifact. */
  totalIdleCost: number;
  byNamespace: NamespaceCost[];
  byWorkload: WorkloadCost[];
  pods: PodAllocation[];
  excludedNodeCount: number;
  excludedPodCount: number;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

export function computeClusterAllocation(nodes: NodeInput[], pods: PodInput[]): ClusterAllocationResult {
  const nodeByName = new Map(nodes.map((n) => [n.nodeName, n]));

  let totalNodeCost = 0;
  let excludedNodeCount = 0;
  for (const n of nodes) {
    if (n.monthlyCost != null) totalNodeCost += n.monthlyCost;
    else excludedNodeCount++;
  }

  const namespaceMap = new Map<string, { monthlyCost: number; podCount: number }>();
  const workloadMap = new Map<string, WorkloadCost>();
  const pods_: PodAllocation[] = [];
  let totalAllocatedCost = 0;
  let excludedPodCount = 0;

  for (const p of pods) {
    const node = p.nodeName ? nodeByName.get(p.nodeName) : undefined;
    if (!node) {
      pods_.push({ podName: p.podName, namespace: p.namespace, nodeName: p.nodeName, monthlyCost: null, excludedReason: 'no_matching_node' });
      excludedPodCount++;
      continue;
    }
    if (node.monthlyCost == null) {
      pods_.push({ podName: p.podName, namespace: p.namespace, nodeName: p.nodeName, monthlyCost: null, excludedReason: 'node_cost_unavailable' });
      excludedPodCount++;
      continue;
    }
    if (!node.allocatableCpuMillicores || node.allocatableCpuMillicores <= 0) {
      pods_.push({ podName: p.podName, namespace: p.namespace, nodeName: p.nodeName, monthlyCost: null, excludedReason: 'node_allocatable_unknown' });
      excludedPodCount++;
      continue;
    }
    if (!p.hasResourceRequest || p.cpuRequestMillicores <= 0) {
      pods_.push({ podName: p.podName, namespace: p.namespace, nodeName: p.nodeName, monthlyCost: null, excludedReason: 'no_cpu_request' });
      excludedPodCount++;
      continue;
    }

    const share = p.cpuRequestMillicores / node.allocatableCpuMillicores;
    const cost = round2(node.monthlyCost * share);
    pods_.push({ podName: p.podName, namespace: p.namespace, nodeName: p.nodeName, monthlyCost: cost });
    totalAllocatedCost += cost;

    const ns = namespaceMap.get(p.namespace) ?? { monthlyCost: 0, podCount: 0 };
    ns.monthlyCost += cost; ns.podCount += 1;
    namespaceMap.set(p.namespace, ns);

    if (p.workloadOwner) {
      const key = `${p.namespace}/${p.workloadOwner.kind}/${p.workloadOwner.name}`;
      const wl = workloadMap.get(key) ?? { key, kind: p.workloadOwner.kind, name: p.workloadOwner.name, namespace: p.namespace, monthlyCost: 0, podCount: 0 };
      wl.monthlyCost += cost; wl.podCount += 1;
      workloadMap.set(key, wl);
    }
  }

  return {
    totalNodeCost: round2(totalNodeCost),
    totalAllocatedCost: round2(totalAllocatedCost),
    totalIdleCost: round2(totalNodeCost - totalAllocatedCost),
    byNamespace: [...namespaceMap.entries()]
      .map(([namespace, v]) => ({ namespace, monthlyCost: round2(v.monthlyCost), podCount: v.podCount }))
      .sort((a, b) => b.monthlyCost - a.monthlyCost),
    byWorkload: [...workloadMap.values()]
      .map((w) => ({ ...w, monthlyCost: round2(w.monthlyCost) }))
      .sort((a, b) => b.monthlyCost - a.monthlyCost),
    pods: pods_,
    excludedNodeCount,
    excludedPodCount,
  };
}
