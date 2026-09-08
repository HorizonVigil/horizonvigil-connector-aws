import { describe, it, expect } from 'vitest';
import { computeFinalizeResult, type FinalizeCandidateResource } from './discoveryFinalize';

const EC2_TYPES = ['ec2_instance', 'ebs_volume', 'vpc'] as const;
const RUN_STARTED_AT = '2026-07-31T00:00:00.000Z';
const BEFORE_RUN = '2026-07-30T00:00:00.000Z';
const DURING_RUN = '2026-07-31T00:05:00.000Z';

function resource(overrides: Partial<FinalizeCandidateResource>): FinalizeCandidateResource {
  return {
    id: 'r1', resource_type_key: 'ec2_instance', category: 'Compute',
    last_seen_at: DURING_RUN, deleted_at: null,
    ...overrides,
  };
}

describe('computeFinalizeResult', () => {
  it('regression: a resource type no covered scanner checked is never marked vanished, even if stale', () => {
    // This is the exact shape of the real bug fixed 2026-07-31: an EC2-only
    // discovery run against an account whose cloud_resources table still had
    // 300+ rows from a broader, older scanner (kms_alias, iam_role, s3_bucket, ...).
    const existing: FinalizeCandidateResource[] = [
      resource({ id: 'kms-1', resource_type_key: 'kms_alias', category: 'Security', last_seen_at: BEFORE_RUN }),
      resource({ id: 'iam-1', resource_type_key: 'iam_role', category: 'Security', last_seen_at: BEFORE_RUN }),
      resource({ id: 's3-1', resource_type_key: 's3_bucket', category: 'Storage', last_seen_at: BEFORE_RUN }),
      resource({ id: 'ec2-1', resource_type_key: 'ec2_instance', category: 'Compute', last_seen_at: DURING_RUN }),
    ];

    const result = computeFinalizeResult(existing, EC2_TYPES, RUN_STARTED_AT);

    expect(result.vanishedIds).toEqual([]);
    expect(result.activeCount).toBe(4);
  });

  it('marks a covered-type resource vanished when it predates the run and was not touched', () => {
    const existing: FinalizeCandidateResource[] = [
      resource({ id: 'ec2-old', resource_type_key: 'ec2_instance', last_seen_at: BEFORE_RUN }),
      resource({ id: 'ec2-fresh', resource_type_key: 'ec2_instance', last_seen_at: DURING_RUN }),
    ];

    const result = computeFinalizeResult(existing, EC2_TYPES, RUN_STARTED_AT);

    expect(result.vanishedIds).toEqual(['ec2-old']);
    expect(result.activeCount).toBe(1);
  });

  it('never re-marks an already-deleted resource', () => {
    const existing: FinalizeCandidateResource[] = [
      resource({ id: 'ec2-deleted', resource_type_key: 'ec2_instance', last_seen_at: BEFORE_RUN, deleted_at: '2026-07-01T00:00:00.000Z' }),
    ];

    const result = computeFinalizeResult(existing, EC2_TYPES, RUN_STARTED_AT);

    expect(result.vanishedIds).toEqual([]);
    expect(result.activeCount).toBe(0);
  });

  it('computes category counts only over active (non-vanished, non-deleted) resources', () => {
    const existing: FinalizeCandidateResource[] = [
      resource({ id: 'a', category: 'Compute', last_seen_at: DURING_RUN }),
      resource({ id: 'b', category: 'Compute', last_seen_at: DURING_RUN }),
      resource({ id: 'c', category: 'Networking', resource_type_key: 'vpc', last_seen_at: BEFORE_RUN }), // vanishes (covered type, stale)
      resource({ id: 'd', category: 'Security', resource_type_key: 'kms_alias', last_seen_at: BEFORE_RUN }), // not covered, stays active
    ];

    const result = computeFinalizeResult(existing, EC2_TYPES, RUN_STARTED_AT);

    expect(result.activeCategoryCounts).toEqual({ Compute: 2, Security: 1 });
    expect(result.activeCount).toBe(3);
  });
});

/**
 * The 2026-09-08 data-loss guard.
 *
 * "Absent from the scan" was treated as proof of "deleted in AWS". But a
 * scanner reports absence for two very different reasons: the resource is
 * genuinely gone, or the API call that would have listed it failed. Scanners
 * swallow a failed sub-call and return an empty body, so one throttled
 * DescribeInstances made every EC2 instance look vanished -- and finalize
 * soft-deleted the customer's entire live inventory while the connection
 * still said `connected` and the run still said `succeeded`.
 */
describe('computeFinalizeResult — degraded coverage must not delete', () => {
  const runStartedAt = '2026-09-08T12:00:00Z';
  const stale = '2026-09-08T11:00:00Z'; // not seen this run

  const inventory: FinalizeCandidateResource[] = [
    { id: 'i-1', resource_type_key: 'ec2_instance', category: 'Compute', last_seen_at: stale, deleted_at: null },
    { id: 'i-2', resource_type_key: 'ec2_instance', category: 'Compute', last_seen_at: stale, deleted_at: null },
    { id: 'v-1', resource_type_key: 'ebs_volume', category: 'Storage', last_seen_at: stale, deleted_at: null },
    { id: 'b-1', resource_type_key: 's3_bucket', category: 'Storage', last_seen_at: stale, deleted_at: null },
  ];

  it('still deletes vanished resources when coverage was clean (unchanged behaviour)', () => {
    const r = computeFinalizeResult(inventory, ['ec2_instance', 'ebs_volume'], runStartedAt, []);
    expect(r.vanishedIds.sort()).toEqual(['i-1', 'i-2', 'v-1']);
  });

  it('deletes NOTHING of a degraded type — the throttled-EC2 mass-delete case', () => {
    const r = computeFinalizeResult(inventory, ['ec2_instance', 'ebs_volume'], runStartedAt, ['ec2_instance', 'ebs_volume']);
    expect(r.vanishedIds).toEqual([]);
  });

  it('protects only the degraded types, so unrelated cleanup still runs', () => {
    // A failed DescribeInstances must not freeze cleanup for every other
    // service scanned in the same run.
    const r = computeFinalizeResult(inventory, ['ec2_instance', 'ebs_volume', 's3_bucket'], runStartedAt, ['ec2_instance']);
    expect(r.vanishedIds.sort()).toEqual(['b-1', 'v-1']);
    expect(r.vanishedIds).not.toContain('i-1');
  });

  it('keeps degraded resources counted as ACTIVE, so the total does not silently drop', () => {
    // If they were excluded from deletion but also dropped from the count,
    // the customer would still see their estate shrink for no stated reason.
    const r = computeFinalizeResult(inventory, ['ec2_instance'], runStartedAt, ['ec2_instance']);
    expect(r.activeCount).toBe(4);
    expect(r.activeCategoryCounts.Compute).toBe(2);
  });

  it('defaults to the previous behaviour when no degraded list is passed', () => {
    // Backwards compatibility for any caller not yet threading the list.
    const r = computeFinalizeResult(inventory, ['ec2_instance'], runStartedAt);
    expect(r.vanishedIds.sort()).toEqual(['i-1', 'i-2']);
  });
});
