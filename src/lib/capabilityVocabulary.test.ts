import { describe, expect, it } from 'vitest';

import type { CapabilityState } from './capabilityMatrix';

/**
 * AWS-P2 — `connector_capability_status.state` is validated ONLY by a
 * database CHECK constraint.
 *
 * A value the TypeScript union permits and the constraint does not passes
 * tsc, passes lint, passes the unit suite, and fails on first contact with
 * production. That has now happened five separate times in this codebase
 * (`collection_runs.trigger`, `cloud_resource_edges.relationship_type`,
 * `compliance_frameworks.evidence_basis`, and two more), which is why the
 * same guard `edgeVocabulary.test.ts` applies to edge types is applied here.
 *
 * The list below is copied VERBATIM from the live constraint, read on
 * 2026-09-22 after migration 20260922084500:
 *
 *   CHECK ((state = ANY (ARRAY['not_configured'::text, 'not_enabled'::text,
 *     'unsupported'::text, 'validating'::text, 'available'::text,
 *     'partial'::text, 'stale'::text, 'permission_denied'::text,
 *     'throttled'::text, 'failed'::text, 'disconnected'::text,
 *     'service_unavailable'::text, 'unknown'::text])))
 *
 * If you change the constraint, change this list in the same commit.
 */
const DB_CONSTRAINT_VALUES = [
  'not_configured', 'not_enabled', 'unsupported', 'validating', 'available',
  'partial', 'stale', 'permission_denied', 'throttled', 'failed', 'disconnected',
  'service_unavailable', 'unknown',
] as const;

/** Every state the capability matrix can produce. */
const MATRIX_STATES: CapabilityState[] = [
  'available', 'permission_denied', 'not_enabled', 'unsupported',
  'service_unavailable', 'partial', 'stale', 'unknown',
];

describe('capability state vocabulary', () => {
  it('every state the matrix produces is writable to the database', () => {
    const rejected = MATRIX_STATES.filter((s) => !DB_CONSTRAINT_VALUES.includes(s as never));
    expect(
      rejected,
      `these states would be rejected by the CHECK constraint on first write: ${rejected.join(', ')}`,
    ).toEqual([]);
  });

  it('covers all eight states the AWS V1 brief enumerates', () => {
    for (const required of [
      'available', 'permission_denied', 'not_enabled', 'unsupported',
      'service_unavailable', 'partial', 'stale', 'unknown',
    ]) {
      expect(MATRIX_STATES, `brief requires ${required}`).toContain(required);
    }
  });

  it('the two states added by AWS-P2 are present in the constraint', () => {
    // These are the ones migration 20260922084500 added; without it the
    // matrix could produce a value the database refuses.
    expect(DB_CONSTRAINT_VALUES).toContain('service_unavailable');
    expect(DB_CONSTRAINT_VALUES).toContain('unknown');
  });

  it('keeps the pre-existing values, so the migration is backward compatible', () => {
    // Rows written before AWS-P2 must stay valid; dropping any of these would
    // orphan live data.
    for (const legacy of ['not_configured', 'validating', 'throttled', 'failed', 'disconnected']) {
      expect(DB_CONSTRAINT_VALUES, `removing ${legacy} would orphan existing rows`).toContain(legacy);
    }
  });

  it('does not let the matrix silently gain a state nobody declared', () => {
    // A ninth state added to CapabilityState without updating this list is
    // exactly the drift this file exists to catch.
    expect(MATRIX_STATES).toHaveLength(8);
    expect(new Set(MATRIX_STATES).size).toBe(8);
  });
});
