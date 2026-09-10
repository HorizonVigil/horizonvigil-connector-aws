import type { Db } from '@horizonvigil/shared-lib';

/**
 * Phase 3c — the typed billing-source state.
 *
 * This is what makes a numeric zero safe to print. Today the product can tell
 * "we have cost data" from "we do not", but not:
 *
 *   NOT_CONFIGURED     you never set up a billing source
 *   PERMISSION_DENIED  the source exists; AWS refused us
 *   WAITING_FOR_EXPORT configured, but AWS has not produced data yet
 *   FAILED             we tried and errored
 *   STALE              the last success is outside the freshness policy
 *   PARTIAL            we covered some of the requested scope
 *   AVAILABLE          current, complete, trustworthy
 *
 * All of those currently render identically, and several of them render as
 * `$0`. §3 is explicit that a numeric zero is a financial fact and may be
 * shown only when the source genuinely proves zero.
 */

export type CostSourceType = 'COST_EXPLORER' | 'CUR_DATA_EXPORT';

export type CostSourceState =
  | 'NOT_CONFIGURED'
  | 'VALIDATING'
  | 'WAITING_FOR_EXPORT'
  | 'INGESTING'
  | 'AVAILABLE'
  | 'PARTIAL'
  | 'STALE'
  | 'PERMISSION_DENIED'
  | 'FAILED'
  | 'UNSUPPORTED';

/** 48h, matching the cost service. Cost Explorer's own lag is roughly a day. */
export const COST_FRESHNESS_SLO_SECONDS = 48 * 60 * 60;

export interface CostSourceOutcome {
  state: CostSourceState;
  reasonCode?: string | null;
  errorCode?: string | null;
  /** Redacted before it reaches here. Raw AWS text can carry account ids. */
  errorDetailSafe?: string | null;
  retryable?: boolean;
  recordCount?: number | null;
  currency?: string | null;
  coveredPeriodStart?: string | null;
  coveredPeriodEnd?: string | null;
  sourceObservedAt?: string | null;
}

/**
 * Maps an AWS failure to a state.
 *
 * The distinction that matters most is PERMISSION_DENIED versus FAILED versus
 * UNSUPPORTED. "Cost Explorer is not enabled for this account" is an opt-in
 * state the customer can fix in one click; a 403 on a configured source is a
 * policy problem; a 500 is ours or AWS's. Collapsing them sends people to fix
 * an IAM policy that is already correct.
 */
export function stateForFailure(status: number, message: string): CostSourceOutcome {
  const text = (message || '').toLowerCase();

  // AWS's own wording when the account has never opted in to Cost Explorer.
  if (text.includes('not enabled for cost explorer') || text.includes('user not enabled')) {
    return {
      state: 'NOT_CONFIGURED',
      reasonCode: 'cost_explorer_not_enabled',
      retryable: false,
      errorDetailSafe: 'Cost Explorer has not been enabled for this AWS account.',
    };
  }
  if (status === 403 || text.includes('accessdenied') || text.includes('not authorized')) {
    return {
      state: 'PERMISSION_DENIED',
      reasonCode: 'access_denied',
      retryable: false,
      errorCode: 'AccessDenied',
      errorDetailSafe: 'The connection is not permitted to read Cost Explorer data.',
    };
  }
  if (status === 429 || text.includes('throttl') || text.includes('rate exceeded')) {
    return { state: 'FAILED', reasonCode: 'throttled', retryable: true, errorCode: 'Throttling' };
  }
  return { state: 'FAILED', reasonCode: 'provider_error', retryable: true, errorCode: String(status) };
}

/**
 * Decides between AVAILABLE, PARTIAL and STALE for a successful sync.
 *
 * A success is not automatically AVAILABLE. Cost Explorer answering for 8 of
 * 10 requested accounts is PARTIAL, and a total built from it must not be
 * presented as the organisation's spend (§22) -- nor as `$0` if those two
 * accounts held all the cost.
 */
export function stateForSuccess(opts: {
  requestedAccountIds: readonly string[];
  coveredAccountIds: readonly string[];
  sourceObservedAt: string | null;
  now?: number;
  freshnessSloSeconds?: number;
}): CostSourceOutcome {
  const now = opts.now ?? Date.now();
  const slo = (opts.freshnessSloSeconds ?? COST_FRESHNESS_SLO_SECONDS) * 1000;

  const missing = opts.requestedAccountIds.filter((a) => !opts.coveredAccountIds.includes(a));
  if (missing.length > 0) {
    return {
      state: 'PARTIAL',
      reasonCode: 'accounts_not_covered',
      retryable: true,
      errorDetailSafe: `${missing.length} of ${opts.requestedAccountIds.length} requested account(s) returned no billing data.`,
    };
  }

  // Freshness is judged on what the PROVIDER observed, not on when we ran.
  // A sync that succeeded five minutes ago against data AWS last updated a
  // week ago is a fresh request over stale facts.
  if (opts.sourceObservedAt) {
    const age = now - Date.parse(opts.sourceObservedAt);
    if (Number.isFinite(age) && age > slo) {
      return { state: 'STALE', reasonCode: 'outside_freshness_slo', retryable: true };
    }
  }

  return { state: 'AVAILABLE', reasonCode: null, retryable: false };
}

/**
 * Records the outcome. One row per (connection, source), upserted.
 *
 * `last_success_at` is advanced ONLY on a state that actually represents
 * usable data. Advancing it on a failure would make a broken source look
 * freshly synced, which is precisely how a stale number keeps being
 * presented as current.
 */
export async function recordCostSourceState(
  db: Db,
  ctx: { orgId: string; connectionId: string; sourceType: CostSourceType; payerAccountId?: string | null; ingestionBatchId?: string | null },
  outcome: CostSourceOutcome,
  requestedAccountIds: readonly string[] = [],
  coveredAccountIds: readonly string[] = [],
): Promise<void> {
  const now = new Date().toISOString();
  const usable = outcome.state === 'AVAILABLE' || outcome.state === 'PARTIAL';

  await db
    .insert(
      'cost_source_status?on_conflict=connection_id,source_type',
      {
        org_id: ctx.orgId,
        connection_id: ctx.connectionId,
        source_type: ctx.sourceType,
        state: outcome.state,
        reason_code: outcome.reasonCode ?? null,
        payer_account_id: ctx.payerAccountId ?? null,
        requested_account_ids: requestedAccountIds,
        covered_account_ids: coveredAccountIds,
        covered_period_start: outcome.coveredPeriodStart ?? null,
        covered_period_end: outcome.coveredPeriodEnd ?? null,
        last_attempt_at: now,
        ...(usable ? { last_success_at: now } : {}),
        source_observed_at: outcome.sourceObservedAt ?? null,
        freshness_slo_seconds: COST_FRESHNESS_SLO_SECONDS,
        record_count: outcome.recordCount ?? null,
        currency: outcome.currency ?? null,
        error_code: outcome.errorCode ?? null,
        error_detail_safe: outcome.errorDetailSafe ?? null,
        retryable: outcome.retryable ?? false,
        ingestion_batch_id: ctx.ingestionBatchId ?? null,
        updated_at: now,
      },
      'resolution=merge-duplicates,return=minimal',
    )
    .catch(() => {
      // Recording state must never fail the sync it describes. A missing
      // status row is a visible gap; a sync that died writing one loses the
      // cost data too.
    });
}
