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
