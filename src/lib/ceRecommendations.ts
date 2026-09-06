import { callJsonApi, type AwsCreds } from './awsApi';

// Same proven protocol ce.ts already uses for ListCostCategoryDefinitions/
// GetAnomalyMonitors -- same host, same JSON-RPC target prefix, only the
// Action name and body shape differ per API.
const TARGET_PREFIX = 'AWSInsightsIndexService';
const HOST = 'ce.us-east-1.amazonaws.com';
const REGION = 'us-east-1';

export interface CostRecommendationInsert {
  connection_id: string;
  resource_id: string | null;
  category: 'reserved_instance' | 'savings_plan' | 'rightsizing';
  issue: string;
  recommended_action: string;
  potential_monthly_savings: number;
  priority: 'high' | 'medium' | 'low';
  external_key: string;
  source: 'aws_ce_reservation' | 'aws_ce_savings_plan' | 'aws_ce_rightsizing';
  commitment_term?: string | null;
  payment_option?: string | null;
  estimated_upfront_cost?: number | null;
  account_scope?: string | null;
}

// Same thresholds horizonvigil-cost's generateRecommendations.ts already
// uses for its homegrown heuristic rows -- kept as a local copy (cross-repo
// import isn't possible here) rather than introducing a shared dependency
// for a three-line pure function.
function priorityFor(savings: number): 'high' | 'medium' | 'low' {
  return savings >= 50 ? 'high' : savings >= 10 ? 'medium' : 'low';
}

// ── GetReservationPurchaseRecommendation ────────────────────────────────

/** Phase 1 scope -- extensible later to ElastiCache/Redshift/OpenSearch etc. */
export const RI_SERVICES = ['AmazonEC2', 'AmazonRDS'] as const;

interface RIInstanceDetails {
  EC2InstanceDetails?: { Family?: string; InstanceType?: string; Region?: string };
  RDSInstanceDetails?: { Family?: string; InstanceType?: string; Region?: string; DatabaseEngine?: string };
}
interface RIRecommendationDetail {
  AccountId?: string;
  InstanceDetails?: RIInstanceDetails;
  RecommendedNumberOfInstancesToPurchase?: string;
  RecommendedNormalizedUnitsToPurchase?: string;
  EstimatedMonthlySavingsAmount?: string;
  EstimatedMonthlyOnDemandCost?: string;
  UpfrontCost?: string;
}
export interface RIRecommendation {
  AccountScope?: string;
  TermInYears?: string;
  PaymentOption?: string;
  RecommendationDetails?: RIRecommendationDetail[];
}
export interface ReservationPurchaseRecommendationBody {
  Recommendations?: RIRecommendation[];
}

export async function fetchReservationRecommendations(
  creds: AwsCreds, service: typeof RI_SERVICES[number],
): Promise<{ ok: true; body: ReservationPurchaseRecommendationBody } | { ok: false; error: string }> {
  const result = await callJsonApi(creds, {
    service: 'ce', region: REGION, host: HOST,
    target: `${TARGET_PREFIX}.GetReservationPurchaseRecommendation`,
    body: { Service: service, LookbackPeriodInDays: 'SIXTY_DAYS', TermInYears: 'ONE_YEAR', PaymentOption: 'NO_UPFRONT' },
  });
  if (!result.ok) return { ok: false, error: result.errorMessage ?? result.errorCode ?? `GetReservationPurchaseRecommendation failed (HTTP ${result.status})` };
  return { ok: true, body: result.body as ReservationPurchaseRecommendationBody };
}

function instanceDescriptor(detail: RIRecommendationDetail): string {
  const ec2 = detail.InstanceDetails?.EC2InstanceDetails;
  if (ec2) return `${ec2.InstanceType ?? ec2.Family ?? 'instance'} in ${ec2.Region ?? 'unknown region'}`;
  const rds = detail.InstanceDetails?.RDSInstanceDetails;
  if (rds) return `${rds.InstanceType ?? rds.Family ?? 'instance'} (${rds.DatabaseEngine ?? 'RDS'}) in ${rds.Region ?? 'unknown region'}`;
  return 'instance';
}

/** Dollar figures are copied verbatim from AWS's own response -- never recomputed. Returns null rather than a zero-savings row. */
export function mapReservationRecommendation(rec: RIRecommendation, detail: RIRecommendationDetail, service: string, connectionId: string): CostRecommendationInsert | null {
  const savings = Number(detail.EstimatedMonthlySavingsAmount ?? 0);
  if (!(savings > 0)) return null;
  const count = detail.RecommendedNumberOfInstancesToPurchase ?? detail.RecommendedNormalizedUnitsToPurchase ?? '1';
  const term = rec.TermInYears ?? 'ONE_YEAR';
  const paymentOption = rec.PaymentOption ?? 'NO_UPFRONT';
  const descriptor = instanceDescriptor(detail);
  const onDemand = Number(detail.EstimatedMonthlyOnDemandCost ?? 0);
  return {
    connection_id: connectionId,
    resource_id: null, // RI recommendations are account/payer-scoped, not tied to one resource.
    category: 'reserved_instance',
    issue: `AWS Cost Explorer recommends purchasing ${count} Reserved Instance(s) for ${descriptor} (${service}) — estimated on-demand cost is $${onDemand.toFixed(2)}/month at current usage.`,
    recommended_action: `Purchase ${count} ${term === 'THREE_YEARS' ? '3-year' : '1-year'} Reserved Instance(s), ${paymentOption.toLowerCase().replace(/_/g, ' ')}, via the AWS Console or Cost Explorer.`,
    potential_monthly_savings: Math.round(savings * 100) / 100,
    priority: priorityFor(savings),
    external_key: `ri:${service}:${term}:${paymentOption}:${detail.AccountId ?? 'payer'}`,
    source: 'aws_ce_reservation',
    commitment_term: term,
    payment_option: paymentOption,
    estimated_upfront_cost: detail.UpfrontCost != null ? Number(detail.UpfrontCost) : null,
    account_scope: detail.AccountId ?? rec.AccountScope ?? null,
  };
}

// ── GetRightsizingRecommendation ────────────────────────────────────────

export interface RightsizingRecommendation {
  CurrentInstance?: { ResourceId?: string; InstanceType?: string; Region?: string };
  RightsizingType?: 'Terminate' | 'Modify' | 'None';
  ModifyRecommendationDetail?: { TargetInstances?: Array<{ EstimatedMonthlySavings?: string; ResourceDetails?: { EC2ResourceDetails?: { InstanceType?: string } } }> };
  TerminateRecommendationDetail?: { EstimatedMonthlySavings?: string };
}
export interface RightsizingRecommendationBody {
  RightsizingRecommendations?: RightsizingRecommendation[];
}

export async function fetchRightsizingRecommendations(creds: AwsCreds): Promise<{ ok: true; body: RightsizingRecommendationBody } | { ok: false; error: string }> {
  const result = await callJsonApi(creds, {
    service: 'ce', region: REGION, host: HOST,
    target: `${TARGET_PREFIX}.GetRightsizingRecommendation`,
    body: { Service: 'AmazonEC2' },
  });
  if (!result.ok) return { ok: false, error: result.errorMessage ?? result.errorCode ?? `GetRightsizingRecommendation failed (HTTP ${result.status})` };
  return { ok: true, body: result.body as RightsizingRecommendationBody };
}

/** `resourceRowId` is the real cloud_resources.id this EC2 instance already
 * has (resolved by the caller, same lookup pattern the existing Auto-PR
 * route already uses) -- null if the instance isn't in inventory yet, in
 * which case the row is still written (real recommendation either way) but
 * without a resource link. */
export function mapRightsizingRecommendation(rec: RightsizingRecommendation, connectionId: string, resourceRowId: string | null): CostRecommendationInsert | null {
  const resourceId = rec.CurrentInstance?.ResourceId;
  if (!resourceId) return null;
  const instanceType = rec.CurrentInstance?.InstanceType ?? 'unknown type';
  const region = rec.CurrentInstance?.Region ?? 'unknown region';

  if (rec.RightsizingType === 'Terminate') {
    const savings = Number(rec.TerminateRecommendationDetail?.EstimatedMonthlySavings ?? 0);
    if (!(savings > 0)) return null;
    return {
      connection_id: connectionId, resource_id: resourceRowId, category: 'rightsizing',
      issue: `AWS Cost Explorer's own analysis recommends terminating instance ${resourceId} (${instanceType}) in ${region} — it appears unused based on real utilization history, not a local CPU-threshold heuristic.`,
      recommended_action: 'Terminate the instance if confirmed unused, or investigate why AWS flagged it as idle.',
      potential_monthly_savings: Math.round(savings * 100) / 100, priority: priorityFor(savings),
      external_key: `ce-rightsizing:${resourceId}`, source: 'aws_ce_rightsizing',
    };
  }

  const target = rec.ModifyRecommendationDetail?.TargetInstances?.[0];
  if (!target) return null;
  const savings = Number(target.EstimatedMonthlySavings ?? 0);
  if (!(savings > 0)) return null;
  const targetType = target.ResourceDetails?.EC2ResourceDetails?.InstanceType ?? 'a smaller type';
  return {
    connection_id: connectionId, resource_id: resourceRowId, category: 'rightsizing',
    issue: `AWS Cost Explorer's own analysis recommends downsizing instance ${resourceId} (${instanceType}) in ${region} to ${targetType}, based on real utilization history.`,
    recommended_action: `Downsize to ${targetType} — savings estimate computed directly by AWS Cost Explorer, not a local heuristic.`,
    potential_monthly_savings: Math.round(savings * 100) / 100, priority: priorityFor(savings),
    external_key: `ce-rightsizing:${resourceId}`, source: 'aws_ce_rightsizing',
  };
}

// ── Savings Plans -- genuinely async (Start...Generation, then poll) ────

export async function startSavingsPlansGeneration(creds: AwsCreds): Promise<{ ok: true; recommendationId: string } | { ok: false; error: string }> {
  const result = await callJsonApi(creds, {
    service: 'ce', region: REGION, host: HOST,
    target: `${TARGET_PREFIX}.StartSavingsPlansPurchaseRecommendationGeneration`, body: {},
  });
  if (!result.ok) return { ok: false, error: result.errorMessage ?? result.errorCode ?? `StartSavingsPlansPurchaseRecommendationGeneration failed (HTTP ${result.status}) — check the connection's IAM policy includes ce:StartSavingsPlansPurchaseRecommendationGeneration, a ce:Start* action not covered by the existing ce:Get*/ce:Describe* grant.` };
  const id = (result.body as { RecommendationId?: string }).RecommendationId;
  if (!id) return { ok: false, error: 'AWS did not return a RecommendationId.' };
  return { ok: true, recommendationId: id };
}

export async function pollSavingsPlansGeneration(creds: AwsCreds, recommendationId: string): Promise<{ ok: true; status: 'PROCESSING' | 'SUCCEEDED' | 'FAILED' } | { ok: false; error: string }> {
  const result = await callJsonApi(creds, {
    service: 'ce', region: REGION, host: HOST,
    target: `${TARGET_PREFIX}.GetSavingsPlansPurchaseRecommendationGeneration`,
    body: { RecommendationIds: [recommendationId] },
  });
  if (!result.ok) return { ok: false, error: result.errorMessage ?? result.errorCode ?? `GetSavingsPlansPurchaseRecommendationGeneration failed (HTTP ${result.status})` };
  const status = (result.body as { GenerationSummaryList?: Array<{ GenerationStatus?: string }> }).GenerationSummaryList?.[0]?.GenerationStatus;
  if (status !== 'PROCESSING' && status !== 'SUCCEEDED' && status !== 'FAILED') return { ok: false, error: `Unexpected generation status from AWS: ${status ?? '(none returned)'}` };
  return { ok: true, status };
}

interface SPRecommendationDetail {
  AccountId?: string;
  HourlyCommitmentToPurchase?: string;
  EstimatedMonthlySavingsAmount?: string;
  EstimatedSavingsPercentage?: string;
  UpfrontCost?: string;
}
export interface SavingsPlansPurchaseRecommendationBody {
  SavingsPlansPurchaseRecommendation?: {
    SavingsPlansType?: string;
    TermInYears?: string;
    PaymentOption?: string;
    SavingsPlansPurchaseRecommendationDetails?: SPRecommendationDetail[];
  };
}

export async function fetchSavingsPlansRecommendation(creds: AwsCreds): Promise<{ ok: true; body: SavingsPlansPurchaseRecommendationBody } | { ok: false; error: string }> {
  const result = await callJsonApi(creds, {
    service: 'ce', region: REGION, host: HOST,
    target: `${TARGET_PREFIX}.GetSavingsPlansPurchaseRecommendation`,
    body: { SavingsPlansType: 'COMPUTE_SP', TermInYears: 'ONE_YEAR', PaymentOption: 'NO_UPFRONT', LookbackPeriodInDays: 'SIXTY_DAYS' },
  });
  if (!result.ok) return { ok: false, error: result.errorMessage ?? result.errorCode ?? `GetSavingsPlansPurchaseRecommendation failed (HTTP ${result.status})` };
  return { ok: true, body: result.body as SavingsPlansPurchaseRecommendationBody };
}

export function mapSavingsPlanRecommendation(detail: SPRecommendationDetail, planType: string, term: string, paymentOption: string, connectionId: string): CostRecommendationInsert | null {
  const savings = Number(detail.EstimatedMonthlySavingsAmount ?? 0);
  if (!(savings > 0)) return null;
  const hourly = detail.HourlyCommitmentToPurchase ?? '0';
  const pct = Number(detail.EstimatedSavingsPercentage ?? 0);
  return {
    connection_id: connectionId, resource_id: null, category: 'savings_plan',
    issue: `AWS Cost Explorer recommends a ${planType} Savings Plan with a $${hourly}/hour commitment — estimated ${pct.toFixed(1)}% savings vs on-demand at current usage.`,
    recommended_action: `Purchase a ${term === 'THREE_YEARS' ? '3-year' : '1-year'} ${planType} Savings Plan, ${paymentOption.toLowerCase().replace(/_/g, ' ')}, via the AWS Console or Cost Explorer.`,
    potential_monthly_savings: Math.round(savings * 100) / 100, priority: priorityFor(savings),
    external_key: `sp:${planType}:${term}:${paymentOption}:${detail.AccountId ?? 'payer'}`,
    source: 'aws_ce_savings_plan', commitment_term: term, payment_option: paymentOption,
    estimated_upfront_cost: detail.UpfrontCost != null ? Number(detail.UpfrontCost) : null,
    account_scope: detail.AccountId ?? null,
  };
}
