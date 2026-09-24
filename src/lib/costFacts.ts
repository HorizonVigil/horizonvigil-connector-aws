import type { Db } from '@horizonvigil/shared-lib';
import { sha256Hex } from './lineage';

/**
 * Phase 3c — writing cost facts, and detecting restatements while doing it.
 *
 * `cost_facts` existed as a model with nothing writing to it. This is the
 * write path, driven from the Cost Explorer sync because that is the source
 * that actually runs today.
 *
 * THE FINGERPRINT DECIDES EVERYTHING, so it is worth being precise about.
 *
 * `record_fingerprint` identifies the LINE ITEM, not its value. The amount is
 * deliberately NOT part of it. If it were, a restated charge would hash
 * differently and land as a brand-new fact sitting alongside the old one --
 * the total would double and nothing would record that AWS had changed its
 * mind. Excluding the amount is what makes "same line item, different money"
 * detectable as a restatement rather than invisible as a duplicate.
 */

/** Bumped when the mapping from a provider row to a fact changes stored values. */
export const COST_NORMALIZATION_VERSION = '2026-09-10.1';

export interface CostFactInput {
  /** Usage day, `YYYY-MM-DD`, as Cost Explorer reports it. */
  usageDate: string;
  service: string;
  region: string | null;
  linkedAccountId: string | null;
  /** Exact decimal STRING. Never a number -- see money handling in the cost service. */
  amount: string;
  currency: string;
}

export interface CostFactContext {
  orgId: string;
  connectionId: string;
  payerAccountId: string | null;
  sourceType: 'COST_EXPLORER' | 'CUR_DATA_EXPORT';
  ingestionBatchId?: string | null;
}

/**
 * The AWS billing month containing a usage date, as a half-open range.
 *
 * §5: never inferred from a UI date range. AWS bills by calendar month in
 * UTC, so the period is a property of the usage date itself and two callers
 * asking different questions get the same answer for the same day.
 */
export function billingPeriodFor(usageDate: string): { start: string; end: string } {
  const [y, m] = usageDate.split('-').map(Number);
  const startY = y;
  const startM = m;
  const endY = m === 12 ? y + 1 : y;
  const endM = m === 12 ? 1 : m + 1;
  const pad = (n: number) => String(n).padStart(2, '0');
  return { start: `${startY}-${pad(startM)}-01`, end: `${endY}-${pad(endM)}-01` };
}

/**
 * Deterministic identity of a source line item.
 *
 * Separated by U+001F, the same unambiguous delimiter the audit chain and
 * resource lineage use, so no rearrangement of field values can collide.
 */
export async function fingerprintCostFact(ctx: CostFactContext, input: CostFactInput): Promise<string> {
  return sha256Hex(
    [
      ctx.connectionId,
      ctx.sourceType,
      input.usageDate,
      input.service,
      input.region ?? '',
      input.linkedAccountId ?? '',
      input.currency,
    ].join(''),
  );
}

interface ExistingFact {
  id: string;
  record_fingerprint: string;
  billed_cost: string;
  revision: number;
}

export interface CostFactWriteResult {
  /** Line items seen for the first time. */
  inserted: number;
  /** Seen again with an identical amount -- deduplicated, no write. */
  unchanged: number;
  /** Seen again with a DIFFERENT amount -- superseded and re-versioned. */
  restated: number;
  /** Fingerprints whose amount changed, for audit and diagnostics. */
  restatedFingerprints: string[];
}

/**
 * Writes facts for one sync, detecting restatements.
 *
 * Deliberately NOT delete-and-replace, which is what the `cost_snapshots`
 * path does. Replacing would make a restatement indistinguishable from an
 * ordinary re-sync and would destroy the previous amount -- §15 and §17
 * require the superseded revision to remain auditable, and a locked period
 * must not be rewritten in place.
 *
 * Amount comparison is done in Postgres `numeric` space by comparing the
 * canonical strings the database returns, not by parsing to a JS number:
 * `102.50` and `102.5` are the same amount and must not read as a
 * restatement, which is why the comparison normalises trailing zeros rather
 * than comparing raw text.
 */
export async function writeCostFacts(
  db: Db,
  ctx: CostFactContext,
  inputs: readonly CostFactInput[],
): Promise<CostFactWriteResult> {
  const result: CostFactWriteResult = { inserted: 0, unchanged: 0, restated: 0, restatedFingerprints: [] };
  if (inputs.length === 0) return result;

  const fingerprints = await Promise.all(inputs.map((i) => fingerprintCostFact(ctx, i)));

  // Current revisions only. A SUPERSEDED row is history and must not be
  // compared against, or a value would appear to flip back and forth.
  const existing = await db.select<ExistingFact[]>('cost_facts', {
    select: 'id,record_fingerprint,billed_cost,revision',
    filters: {
      connection_id: `eq.${ctx.connectionId}`,
      status: 'neq.SUPERSEDED',
    },
    limit: 10000,
  });
  const byFingerprint = new Map(existing.map((e) => [e.record_fingerprint, e]));

  const toInsert: Record<string, unknown>[] = [];
  const toSupersede: string[] = [];

  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i];
    const fingerprint = fingerprints[i];
    const period = billingPeriodFor(input.usageDate);
    const prior = byFingerprint.get(fingerprint);

    const row = {
      org_id: ctx.orgId,
      connection_id: ctx.connectionId,
      provider: 'aws',
      payer_account_id: ctx.payerAccountId,
      linked_account_id: input.linkedAccountId,
      billing_period_start: period.start,
      billing_period_end: period.end,
      usage_start: `${input.usageDate}T00:00:00Z`,
      service: input.service,
      region: input.region,
      // Only the measure the source actually supplies. Cost Explorer reports
      // UnblendedCost and nothing else, so amortized/net/list stay NULL
      // rather than being fabricated from it.
      billed_cost: input.amount,
      original_currency: input.currency,
      source_type: ctx.sourceType,
      ingestion_batch_id: ctx.ingestionBatchId ?? null,
      normalization_version: COST_NORMALIZATION_VERSION,
      record_fingerprint: fingerprint,
      // PROVISIONAL: AWS may still restate an open billing month. Nothing
      // marks a fact FINALIZED until the period is closed.
      status: 'PROVISIONAL',
      revision: 1,
      observed_at: null,
      ingested_at: new Date().toISOString(),
    };

    if (!prior) {
      toInsert.push(row);
      result.inserted += 1;
      continue;
    }

    if (sameAmount(prior.billed_cost, input.amount)) {
      result.unchanged += 1;
      continue;
    }

    // A restatement. The prior revision is superseded, not overwritten.
    toSupersede.push(prior.id);
    toInsert.push({
      ...row,
      revision: prior.revision + 1,
      supersedes_id: prior.id,
      status: 'RESTATED',
      restatement_reason: `Source reported ${input.amount} where revision ${prior.revision} recorded ${prior.billed_cost}.`,
    });
    result.restated += 1;
    result.restatedFingerprints.push(fingerprint);
  }

  // Supersede first. If the insert then fails, the worst outcome is a period
  // with no current revision -- visibly wrong. Inserting first and failing to
  // supersede would leave TWO current revisions, which double-counts and
  // looks correct.
  for (const id of toSupersede) {
    await db.update('cost_facts', { id: `eq.${id}` }, { status: 'SUPERSEDED', updated_at: new Date().toISOString() }, 'return=minimal');
  }
  if (toInsert.length > 0) {
    await db.insert('cost_facts', toInsert, 'return=minimal');
  }

  return result;
}

/**
 * Whether two decimal strings denote the same amount.
 *
 * `102.50` and `102.5` are equal; raw string comparison would call that a
 * restatement and manufacture a revision on every sync. Compared without
 * floating point: normalise the textual form rather than parsing to a double.
 */
export function sameAmount(a: string | null | undefined, b: string | null | undefined): boolean {
  if (a === null || a === undefined || b === null || b === undefined) return false;
  return normaliseDecimal(a) === normaliseDecimal(b);
}

function normaliseDecimal(value: string): string {
  const text = String(value).trim();
  const negative = text.startsWith('-');
  const body = negative ? text.slice(1) : text;
  const [wholeRaw, fracRaw = ''] = body.split('.');
  const whole = wholeRaw.replace(/^0+(?=\d)/, '') || '0';
  const frac = fracRaw.replace(/0+$/, '');
  const magnitude = frac ? `${whole}.${frac}` : whole;
  // Avoid "-0" comparing unequal to "0".
  return magnitude === '0' ? '0' : `${negative ? '-' : ''}${magnitude}`;
}

/**
 * Ensures the billing period row exists for a usage date.
 *
 * Idempotent: an ordinary re-sync must not create a second period, and the
 * unique constraint on (connection, start, end) is what guarantees it rather
 * than a check-then-insert that races.
 */
export async function ensureBillingPeriod(db: Db, ctx: CostFactContext, usageDate: string): Promise<void> {
  const period = billingPeriodFor(usageDate);
  await db
    .insert(
      'cost_billing_periods?on_conflict=connection_id,billing_period_start,billing_period_end',
      {
        org_id: ctx.orgId,
        connection_id: ctx.connectionId,
        billing_period_start: period.start,
        billing_period_end: period.end,
        timezone: 'UTC',
        status: 'OPEN',
      },
      'resolution=merge-duplicates,return=minimal',
    )
    .catch(() => {
      // Losing the race is the normal outcome under concurrent syncs and
      // means the row already exists, which is what was wanted.
    });
}
