import type { Db, AvailabilityState } from '@horizonvigil/shared-lib';
import type { PermissionCheckResult } from './permissionChecks';

/**
 * Per-capability health, derived from real permission evidence (§2.3, §6.2).
 *
 * Health used to be one blended score per connection. That cannot express
 * "inventory is fine but Cost Explorer is denied", which is exactly what a
 * customer needs in order to act — and blending is how a connection with an
 * unevaluated capability still reported healthy overall.
 *
 * Verified in production before building this: both AWS connections carry 8
 * real permission checks each (sts, iam, organizations, cloudwatch,
 * cloudtrail, tagging, cost_explorer, eks), and none of it reached the UI
 * because the permissions query was reading the wrong run.
 */

/** The capabilities a customer actually thinks in terms of, mapped to the probes that prove them. */
export const CAPABILITY_PROBES: Record<string, readonly string[]> = {
  inventory: ['sts'],
  identity: ['iam'],
  metrics: ['cloudwatch'],
  billing_cost_explorer: ['cost_explorer'],
  activity_cloudtrail: ['cloudtrail'],
  posture_config: ['config'],
  exposure_access_analyzer: ['sts'],
  compliance_config: ['config'],
  recommendations: ['compute_optimizer', 'trusted_advisor'],
  organizations: ['organizations'],
  governance_tags: ['tagging'],
  kubernetes_eks: ['eks'],
};

/**
 * Maps a probe result onto the shared availability vocabulary.
 *
 * `not_applicable` becomes `not_enabled` rather than `failed` on purpose: an
 * account that has not turned on Security Hub, or is not part of an AWS
 * Organization, is not broken. Reporting it as a failure sends someone to fix
 * an IAM policy that is already correct.
 */
export function stateForCheck(check: PermissionCheckResult | undefined): { state: AvailabilityState; reasonCode?: string } {
  if (!check) return { state: 'not_configured', reasonCode: 'never_evaluated' };
  switch (check.status) {
    case 'granted': return { state: 'available' };
    case 'denied': return { state: 'permission_denied', reasonCode: `${check.service}_denied` };
    case 'not_applicable': return { state: 'not_enabled', reasonCode: `${check.service}_not_enabled` };
    case 'error':
    default: return { state: 'failed', reasonCode: `${check.service}_probe_failed` };
  }
}

/**
 * Rolls the probes for one capability into a single state.
 *
 * Conservative by design: a capability needing several probes is only
 * `available` when ALL of them are. A capability proven by one probe out of
 * two is `partial`, because half the data being collectable is not the same
 * as the capability working.
 */
export function capabilityState(capability: string, checks: PermissionCheckResult[]): { state: AvailabilityState; reasonCode?: string; covered: number; expected: number } {
  const probes = CAPABILITY_PROBES[capability] ?? [];
  const byService = new Map(checks.map((c) => [c.service, c]));
  const results = probes.map((p) => stateForCheck(byService.get(p)));

  const expected = probes.length;
  const covered = results.filter((r) => r.state === 'available').length;

  if (expected === 0) return { state: 'unsupported', reasonCode: 'no_probe_defined', covered: 0, expected: 0 };
  if (covered === expected) return { state: 'available', covered, expected };
  if (covered > 0) return { state: 'partial', reasonCode: 'some_probes_unavailable', covered, expected };

  // Nothing available: report WHY, preserving a shared reason when every
  // probe failed the same way rather than flattening to a generic failure.
  const states = new Set(results.map((r) => r.state));
  const single = states.size === 1 ? [...results][0] : null;
  return {
    state: single ? single.state : 'failed',
    reasonCode: single?.reasonCode ?? 'multiple_probes_unavailable',
    covered,
    expected,
  };
}

export interface CapabilityStatusRow {
  org_id: string;
  connection_id: string;
  capability: string;
  state: AvailabilityState;
  reason_code: string | null;
  source: string;
  expected_scope: number;
  covered_scope: number;
  last_attempt_at: string;
  /**
   * OMIT this key to leave whatever is already stored.
   *
   * These rows are written with `resolution=merge-duplicates`, so an explicit
   * `null` OVERWRITES a real previous success and makes a source that worked
   * yesterday look like it has never worked at all. A caller that has nothing
   * new to say about success must say nothing, not say null.
   */
  last_success_at?: string | null;
  permission_snapshot_id: string | null;
  updated_at: string;
}

/** Builds one row per capability from a completed permission-validation snapshot. */
export function buildCapabilityStatuses(
  input: {
    orgId: string; connectionId: string; checks: PermissionCheckResult[];
    snapshotId: string | null; connectionStatus: string;
    /**
     * `last_success_at` as it stands in the database, by capability.
     *
     * Required because this is written as an UPSERT: the previous value was
     * being overwritten with null on every run where a capability was not
     * currently available, so "when did this last work?" was destroyed the
     * moment it stopped working. Measured in production 2026-09-22: 9 AWS
     * capability rows carry a null last_success_at, including
     * `billing_cost_explorer` on a connection where Cost Explorer demonstrably
     * used to answer -- so nothing can now say whether it ever did.
     *
     * A last-success that is erased on first failure is not durable, and it is
     * the exact field staleness evaluation and recovery detection read.
     */
    previousSuccessAt?: Record<string, string | null>;
  },
  now: number = Date.now(),
): CapabilityStatusRow[] {
  const at = new Date(now).toISOString();
  return Object.keys(CAPABILITY_PROBES).map((capability) => {
    // A disconnected connection is not collecting anything, and saying
    // "available" for its capabilities would be the same false-health claim
    // the audit found at the connection level.
    const resolved = input.connectionStatus === 'disconnected'
      ? { state: 'disconnected' as AvailabilityState, reasonCode: 'connection_disconnected', covered: 0, expected: (CAPABILITY_PROBES[capability] ?? []).length }
      : capabilityState(capability, input.checks);

    return {
      org_id: input.orgId,
      connection_id: input.connectionId,
      capability,
      state: resolved.state,
      reason_code: resolved.reasonCode ?? null,
      source: 'permission_validation',
      expected_scope: resolved.expected,
      covered_scope: resolved.covered,
      last_attempt_at: at,
      /*
       * Advanced on success; otherwise the previous value is CARRIED FORWARD,
       * never nulled. "Available now" and "last worked on the 15th" are
       * different facts and the product needs both -- the second is what tells
       * a customer whether a capability is newly broken or never configured.
       */
      last_success_at: resolved.state === 'available' ? at : (input.previousSuccessAt?.[capability] ?? null),
      permission_snapshot_id: input.snapshotId,
      updated_at: at,
    };
  });
}

/**
 * Upserts capability status after a validation run. Best-effort: a telemetry
 * write must never fail the validation itself.
 *
 * THE CONFLICT TARGET IS LOAD-BEARING.
 *
 * This call had none, and every write it ever made failed. The table's PRIMARY
 * KEY is a surrogate `id`; the uniqueness that matters is a separate index on
 * `(connection_id, capability)`. PostgREST's `resolution=merge-duplicates`
 * resolves against the PRIMARY KEY unless told otherwise, so each row got a
 * fresh id, found no primary-key conflict to merge, and was attempted as an
 * INSERT -- which then violated the unique index.
 *
 * The catch below turned that into one console line and a `void` return, so:
 *
 *   - `connector_capability_status` froze on 2026-09-09 and 2026-09-15
 *   - every capability state a customer saw was days stale
 *   - a validation that ran minutes ago left the table untouched and said
 *     nothing
 *
 * Measured 2026-09-22: a validation completed at 18:50:47 and the logs show
 * `[capability-status] write failed` at 18:50:47.666 for both connections.
 * It was found only because the account was granted admin and the capability
 * rows still did not move.
 *
 * Every other upsert in this codebase names its conflict target. This was the
 * only one that did not.
 */
export async function writeCapabilityStatuses(db: Db, rows: CapabilityStatusRow[]): Promise<void> {
  if (rows.length === 0) return;
  try {
    await db.insert('connector_capability_status?on_conflict=connection_id,capability', rows, 'resolution=merge-duplicates,return=minimal');
  } catch (err) {
    // Still non-fatal -- a capability row must not take down the validation
    // that produced it -- but the line now says how much was lost, so a
    // silent freeze is at least countable in the logs.
    console.error(
      `[capability-status] write failed for ${rows.length} row(s) (validation itself is unaffected):`,
      err instanceof Error ? err.message : err,
    );
  }
}
