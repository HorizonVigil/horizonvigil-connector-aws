export type EvidenceCapabilityState =
  | 'available'
  | 'permission_denied'
  | 'not_enabled'
  | 'unsupported'
  | 'service_unavailable'
  | 'partial'
  | 'stale'
  | 'unknown';

export type EvidenceCompleteness = 'complete' | 'partial' | 'failed' | 'running' | 'never_run' | 'unknown';

export interface AwsEvidenceItem {
  evidenceId: string;
  organizationId: string;
  connectionId: string;
  provider: 'aws';
  awsAccountId: string;
  region: string | null;
  resourceId: string | null;
  sourceService: string;
  capabilityState: EvidenceCapabilityState;
  collectionRunId: string | null;
  observedAt: string | null;
  retrievedAt: string;
  freshness: 'fresh' | 'stale' | 'unknown';
  completeness: EvidenceCompleteness;
  rawEvidenceReference: string;
  limitation: string | null;
  summary: string;
}

export interface InventoryRunFact {
  id: string;
  status: string;
  total_steps: number | null;
  completed_steps: number | null;
  failed_steps: number | null;
  degraded_resource_types: string[] | null;
  finished_at: string | null;
  started_at: string | null;
}

export interface CapabilityFact {
  capability: string;
  state: string;
  reason_code: string | null;
  last_attempt_at: string | null;
  last_success_at: string | null;
  freshness_slo_seconds: number | null;
  permission_snapshot_id: string | null;
  updated_at: string | null;
}

export interface CostSourceFact {
  source_type: string;
  state: string;
  reason_code: string | null;
  covered_period_start: string | null;
  covered_period_end: string | null;
  last_attempt_at: string | null;
  last_success_at: string | null;
  source_observed_at: string | null;
  freshness_slo_seconds: number | null;
  record_count: number | null;
  updated_at: string | null;
}

function ageState(observedAt: string | null, sloSeconds: number | null, now: number): 'fresh' | 'stale' | 'unknown' {
  if (!observedAt || !sloSeconds) return 'unknown';
  const observed = Date.parse(observedAt);
  if (!Number.isFinite(observed)) return 'unknown';
  return now - observed > sloSeconds * 1000 ? 'stale' : 'fresh';
}

export function normalizedCapabilityState(state: string, freshness: 'fresh' | 'stale' | 'unknown'): EvidenceCapabilityState {
  if (freshness === 'stale' && state === 'available') return 'stale';
  if (freshness === 'unknown' && state === 'available') return 'unknown';
  switch (state.toLowerCase()) {
    case 'available': return 'available';
    case 'permission_denied': return 'permission_denied';
    case 'not_enabled':
    case 'not_configured': return 'not_enabled';
    case 'unsupported': return 'unsupported';
    case 'service_unavailable':
    case 'failed': return 'service_unavailable';
    case 'partial': return 'partial';
    case 'stale': return 'stale';
    default: return 'unknown';
  }
}

export function inventoryEvidence(input: {
  orgId: string; connectionId: string; awsAccountId: string; run: InventoryRunFact | null; retrievedAt: string; now?: number;
}): AwsEvidenceItem {
  const { orgId, connectionId, awsAccountId, run, retrievedAt } = input;
  const degraded = run?.degraded_resource_types ?? [];
  const failed = run?.failed_steps ?? 0;
  const status = run?.status ?? '';
  let completeness: EvidenceCompleteness = 'unknown';
  let capabilityState: EvidenceCapabilityState = 'unknown';
  let limitation: string | null = null;

  if (!run) {
    completeness = 'never_run';
    limitation = 'Inventory has not been collected for this account.';
  } else if (['QUEUED', 'RUNNING', 'WAITING_RETRY', 'PAUSED', 'PAUSING', 'CANCEL_REQUESTED'].includes(status)) {
    completeness = 'running';
    capabilityState = 'partial';
    limitation = 'Inventory collection is still in progress; counts may describe an earlier run.';
  } else if (status === 'FAILED' || status === 'CANCELED') {
    completeness = 'failed';
    capabilityState = 'service_unavailable';
    limitation = 'The latest inventory collection did not complete.';
  } else if (status === 'PARTIALLY_SUCCEEDED' || failed > 0 || degraded.length > 0) {
    completeness = 'partial';
    capabilityState = 'partial';
    limitation = degraded.length > 0
      ? `${degraded.length} resource type(s) were not fully read; inventory counts are lower bounds.`
      : `${failed} collection step(s) failed; inventory counts are lower bounds.`;
  } else if (status === 'SUCCEEDED') {
    completeness = 'complete';
    capabilityState = 'available';
  }

  const observedAt = run?.finished_at ?? run?.started_at ?? null;
  const freshness = ageState(observedAt, 36 * 60 * 60, input.now ?? Date.now());
  if (freshness === 'stale' && capabilityState === 'available') {
    capabilityState = 'stale';
    limitation = 'The latest complete inventory is outside the 36-hour freshness window.';
  } else if (freshness === 'unknown' && capabilityState === 'available') {
    capabilityState = 'unknown';
    limitation = 'The inventory run has no trustworthy observation timestamp, so freshness cannot be verified.';
  }

  return {
    evidenceId: `aws:${connectionId}:inventory`, organizationId: orgId, connectionId, provider: 'aws', awsAccountId,
    region: null, resourceId: null, sourceService: 'aws_inventory', capabilityState,
    collectionRunId: run?.id ?? null, observedAt, retrievedAt, freshness, completeness,
    rawEvidenceReference: `/api/v1/aws/accounts/${connectionId}/scan-health`, limitation,
    summary: run ? `${run.completed_steps ?? 0} of ${run.total_steps ?? 0} inventory steps completed.` : 'Inventory has never run.',
  };
}

export function capabilityEvidence(input: {
  orgId: string; connectionId: string; awsAccountId: string; row: CapabilityFact; retrievedAt: string; now?: number;
}): AwsEvidenceItem {
  const observedAt = input.row.last_success_at ?? input.row.last_attempt_at ?? input.row.updated_at;
  const freshness = ageState(observedAt, input.row.freshness_slo_seconds, input.now ?? Date.now());
  const state = normalizedCapabilityState(input.row.state, freshness);
  return {
    evidenceId: `aws:${input.connectionId}:capability:${input.row.capability}`,
    organizationId: input.orgId, connectionId: input.connectionId, provider: 'aws', awsAccountId: input.awsAccountId,
    region: null, resourceId: null, sourceService: input.row.capability, capabilityState: state,
    collectionRunId: input.row.permission_snapshot_id, observedAt, retrievedAt: input.retrievedAt, freshness,
    completeness: state === 'available' ? 'complete' : state === 'partial' ? 'partial' : 'unknown',
    rawEvidenceReference: `/api/v1/aws/accounts/${input.connectionId}/capabilities`,
    limitation: state === 'available' ? null : `Capability is ${state}${input.row.reason_code ? ` (${input.row.reason_code})` : ''}.`,
    summary: `${input.row.capability} capability is ${state}.`,
  };
}

export function costSourceEvidence(input: {
  orgId: string; connectionId: string; awsAccountId: string; row: CostSourceFact; retrievedAt: string; now?: number;
}): AwsEvidenceItem {
  const observedAt = input.row.source_observed_at ?? input.row.last_success_at ?? input.row.last_attempt_at ?? input.row.updated_at;
  const freshness = ageState(observedAt, input.row.freshness_slo_seconds, input.now ?? Date.now());
  const state = normalizedCapabilityState(input.row.state, freshness);
  const source = input.row.source_type.toLowerCase();
  return {
    evidenceId: `aws:${input.connectionId}:billing:${source}`,
    organizationId: input.orgId, connectionId: input.connectionId, provider: 'aws', awsAccountId: input.awsAccountId,
    region: null, resourceId: null, sourceService: source, capabilityState: state,
    collectionRunId: null, observedAt, retrievedAt: input.retrievedAt, freshness,
    completeness: state === 'available' ? 'complete' : state === 'partial' ? 'partial' : 'unknown',
    rawEvidenceReference: `/api/v1/aws/accounts/${input.connectionId}/cost`,
    limitation: state === 'available' ? null : `Billing evidence is ${state}${input.row.reason_code ? ` (${input.row.reason_code})` : ''}; a numeric zero is not verified.`,
    summary: `${input.row.source_type} is ${state}; ${input.row.record_count ?? 0} evidence record(s) cover ${input.row.covered_period_start ?? 'an unknown start'} to ${input.row.covered_period_end ?? 'an unknown end'}.`,
  };
}
