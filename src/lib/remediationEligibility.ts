import type { RemediationActionType } from './remediationActions';

/**
 * Pure eligibility check against cached (discovery-scan) resource state,
 * extracted from routes/remediation.ts so it's unit-testable without a
 * database. This is only the *pre-check* at request time — the
 * authoritative check happens live against real AWS state at dry-run/
 * execute time (describeCurrentState in remediationActions.ts), which
 * needs real AWS credentials and isn't unit-testable the same way.
 */
export interface CachedResourceRow {
  id: string;
  connection_id: string;
  resource_type_key: string;
  resource_id: string;
  region: string | null;
  state: string | null;
  relationships: Record<string, unknown> | null;
}

export interface EligibilityResult {
  eligible: boolean;
  reason?: string;
}

export function checkCachedEligibility(actionType: RemediationActionType, resource: CachedResourceRow): EligibilityResult {
  if (actionType === 'stop_instance') {
    return resource.state === 'running' ? { eligible: true } : { eligible: false, reason: `Instance is '${resource.state}', not 'running'.` };
  }
  if (actionType === 'start_instance') {
    return resource.state === 'stopped' ? { eligible: true } : { eligible: false, reason: `Instance is '${resource.state}', not 'stopped'.` };
  }
  if (actionType === 'release_eip') {
    const assoc = resource.relationships?.instanceId ?? resource.relationships?.networkInterfaceId;
    return assoc ? { eligible: false, reason: 'Elastic IP is associated with an instance/network interface.' } : { eligible: true };
  }
  if (actionType === 'delete_volume') {
    const attached = ((resource.relationships?.attachedInstanceIds as unknown[] | undefined) ?? []).filter(Boolean);
    return attached.length > 0 ? { eligible: false, reason: 'Volume is attached to an instance.' } : { eligible: true };
  }
  if (actionType === 'delete_snapshot') {
    // A snapshot backing a registered AMI can't actually be deleted — AWS
    // rejects it server-side at dry-run time, same as noted in
    // remediationActions.ts's live describeCurrentState for this action.
    return resource.state === 'completed' ? { eligible: true } : { eligible: false, reason: `Snapshot is '${resource.state}', not 'completed'.` };
  }
  if (actionType === 'resize_instance') {
    return resource.state === 'running' || resource.state === 'stopped'
      ? { eligible: true }
      : { eligible: false, reason: `Instance is '${resource.state}' — must be 'running' or 'stopped' to resize.` };
  }
  // deregister_ami
  return resource.state === 'available' ? { eligible: true } : { eligible: false, reason: `AMI is '${resource.state}', not 'available'.` };
}
