/**
 * Freshness applied to a stored capability state at READ time.
 *
 * THE DEFECT
 *
 * `connector_capability_status.state` is a verdict recorded at the moment a
 * probe last ran. It does not decay. `GET /accounts/:id/capabilities` returned
 * that stored verdict verbatim, so a capability proven once and never proven
 * again kept answering `available` indefinitely.
 *
 * Measured in production on 2026-09-22: `billing_cost_explorer` on the
 * `kamal-k8s` connection read `state: available` with
 * `last_success_at: 2026-09-15` -- seven days old against the 48-hour SLO
 * stored on that very row. Cost collection had in fact been failing closed
 * since 09-16 (a wiped INTERNAL_COST_SYNC_SECRET), so the one field a client
 * would read to ask "is billing working?" said yes for six days while it was
 * not.
 *
 * The row already carried everything needed to know better: `last_success_at`
 * and `freshness_slo_seconds`. Nothing compared them.
 *
 * WHAT THIS DOES
 *
 * Only ever DOWNGRADES. A capability that is `failed` or `not_enabled` stays
 * that way -- recency cannot rescue a negative verdict, and a stale failure is
 * still a failure. The single transition is `available` -> `stale`, which is
 * the §1.4 availability vocabulary's own word for "was true once, not proven
 * now".
 *
 * A capability that has never succeeded has no freshness to judge. It is left
 * exactly as recorded rather than being called stale, because "never worked"
 * and "worked, but not lately" are different answers and its own state already
 * says which.
 */

/** Used when a row carries no SLO of its own. Matches the cost service's 48h. */
export const DEFAULT_FRESHNESS_SLO_SECONDS = 48 * 60 * 60;

export interface CapabilityRow {
  state: string;
  last_success_at?: string | null;
  freshness_slo_seconds?: number | null;
}

export interface CapabilityFreshness {
  /** What the caller should believe now. `available` only if still within SLO. */
  state: string;
  /** The verdict as stored, so a client can tell a downgrade from a fresh failure. */
  recordedState: string;
  stale: boolean;
  /** Seconds since the last proven success, or null if it has never succeeded. */
  ageSeconds: number | null;
  sloSeconds: number;
  /** Customer-safe sentence. No account ids, no provider text. */
  reason: string | null;
}

export function evaluateFreshness(row: CapabilityRow, now: number = Date.now()): CapabilityFreshness {
  const sloSeconds = row.freshness_slo_seconds ?? DEFAULT_FRESHNESS_SLO_SECONDS;
  const recordedState = row.state;

  const parsed = row.last_success_at ? Date.parse(row.last_success_at) : Number.NaN;
  const hasSuccess = Number.isFinite(parsed);

  /*
   * A future timestamp means clock skew, not freshness. Clamping at 0 keeps a
   * skewed row from reading as "aged negatively" and silently passing.
   */
  const ageSeconds = hasSuccess ? Math.max(0, Math.round((now - parsed) / 1000)) : null;

  const base = { recordedState, sloSeconds, ageSeconds };

  // Only a currently-positive verdict can go stale.
  if (recordedState !== 'available') {
    return { ...base, state: recordedState, stale: false, reason: null };
  }

  if (!hasSuccess) {
    /*
     * `available` with no recorded success is not something to pass through.
     * The verdict claims proof that the row does not carry, so it is reported
     * as unproven rather than as working.
     */
    return {
      ...base,
      state: 'stale',
      stale: true,
      reason: 'This capability is recorded as available but has no successful check on record.',
    };
  }

  if ((ageSeconds as number) > sloSeconds) {
    return {
      ...base,
      state: 'stale',
      stale: true,
      reason: `Last confirmed ${describeAge(ageSeconds as number)} ago, beyond the ${describeAge(sloSeconds)} freshness policy for this capability.`,
    };
  }

  return { ...base, state: 'available', stale: false, reason: null };
}

/** Coarse, human units. Deliberately not precise — the point is the order of magnitude. */
function describeAge(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  if (days >= 1) return `${days} day${days === 1 ? '' : 's'}`;
  const hours = Math.floor(seconds / 3600);
  if (hours >= 1) return `${hours} hour${hours === 1 ? '' : 's'}`;
  const minutes = Math.max(1, Math.floor(seconds / 60));
  return `${minutes} minute${minutes === 1 ? '' : 's'}`;
}
