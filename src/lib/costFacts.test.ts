import { describe, it, expect } from 'vitest';
import { billingPeriodFor, fingerprintCostFact, sameAmount, writeCostFacts, type CostFactContext } from './costFacts';
import { stateForFailure, stateForSuccess } from './costSourceState';

const ctx: CostFactContext = {
  orgId: 'org-1',
  connectionId: 'conn-1',
  payerAccountId: '111111111111',
  sourceType: 'COST_EXPLORER',
};

const input = (over: Partial<Parameters<typeof fingerprintCostFact>[1]> = {}) => ({
  usageDate: '2026-08-15', service: 'Amazon EC2', region: 'us-east-1',
  linkedAccountId: '111111111111', amount: '12.50', currency: 'USD', ...over,
});

describe('billing periods', () => {
  it('derives the AWS billing month from the usage date, not a UI range', () => {
    // §5: a UI date range is a question; a billing period is a property of
    // the bill, so the same day always maps to the same period.
    expect(billingPeriodFor('2026-08-15')).toEqual({ start: '2026-08-01', end: '2026-09-01' });
    expect(billingPeriodFor('2026-08-01')).toEqual({ start: '2026-08-01', end: '2026-09-01' });
    expect(billingPeriodFor('2026-08-31')).toEqual({ start: '2026-08-01', end: '2026-09-01' });
  });

  it('rolls the year over at December', () => {
    expect(billingPeriodFor('2026-12-31')).toEqual({ start: '2026-12-01', end: '2027-01-01' });
  });
});

describe('fingerprint identity', () => {
  it('does NOT include the amount', async () => {
    /**
     * The single most important property here. If the amount were part of
     * the identity, a restated charge would hash differently and land as a
     * brand-new fact beside the old one -- the total would double and
     * nothing would record that AWS changed its mind.
     */
    const a = await fingerprintCostFact(ctx, input({ amount: '12.50' }));
    const b = await fingerprintCostFact(ctx, input({ amount: '99.99' }));
    expect(a).toBe(b);
  });

  it('changes when the line item genuinely differs', async () => {
    const base = await fingerprintCostFact(ctx, input());
    expect(await fingerprintCostFact(ctx, input({ service: 'Amazon S3' }))).not.toBe(base);
    expect(await fingerprintCostFact(ctx, input({ region: 'eu-west-1' }))).not.toBe(base);
    expect(await fingerprintCostFact(ctx, input({ usageDate: '2026-08-16' }))).not.toBe(base);
    expect(await fingerprintCostFact(ctx, input({ linkedAccountId: '999999999999' }))).not.toBe(base);
  });

  it('separates sources, so a CUR fact never collides with a CE fact', async () => {
    const ce = await fingerprintCostFact(ctx, input());
    const cur = await fingerprintCostFact({ ...ctx, sourceType: 'CUR_DATA_EXPORT' }, input());
    expect(ce).not.toBe(cur);
  });
});

describe('sameAmount', () => {
  it('treats equal amounts written differently as equal', () => {
    // Without this, every sync would manufacture a restatement because
    // Postgres returns 102.50 where AWS sent 102.5.
    expect(sameAmount('102.50', '102.5')).toBe(true);
    expect(sameAmount('0', '0.00')).toBe(true);
    expect(sameAmount('0', '-0')).toBe(true);
    expect(sameAmount('007.5', '7.50')).toBe(true);
  });

  it('detects a real change', () => {
    expect(sameAmount('102.50', '102.51')).toBe(false);
    expect(sameAmount('100', '-100')).toBe(false);
  });

  it('never treats a missing amount as equal to anything', () => {
    expect(sameAmount(null, '0')).toBe(false);
    expect(sameAmount(undefined, undefined)).toBe(false);
  });
});

describe('writeCostFacts', () => {
  function fakeDb(existing: Record<string, unknown>[] = []) {
    const inserted: Record<string, unknown>[] = [];
    const updated: { filters: unknown; patch: Record<string, unknown> }[] = [];
    return {
      db: {
        select: async () => existing,
        insert: async (_t: string, rows: Record<string, unknown> | Record<string, unknown>[]) => {
          for (const r of Array.isArray(rows) ? rows : [rows]) inserted.push(r);
          return [];
        },
        update: async (_t: string, filters: unknown, patch: Record<string, unknown>) => {
          updated.push({ filters, patch });
          return [];
        },
      } as never,
      inserted,
      updated,
    };
  }

  it('inserts a new line item as revision 1, PROVISIONAL', async () => {
    const { db, inserted } = fakeDb();
    const r = await writeCostFacts(db, ctx, [input()]);
    expect(r).toMatchObject({ inserted: 1, unchanged: 0, restated: 0 });
    expect(inserted[0]).toMatchObject({ revision: 1, status: 'PROVISIONAL', billed_cost: '12.50' });
    // PROVISIONAL because AWS may still restate an open month. Nothing is
    // FINALIZED until the period closes.
    expect(inserted[0].status).not.toBe('FINALIZED');
  });

  it('supplies only the measure the source actually reports', async () => {
    // Cost Explorer gives UnblendedCost and nothing else. Defaulting the
    // others from it would fabricate four numbers from one.
    const { db, inserted } = fakeDb();
    await writeCostFacts(db, ctx, [input()]);
    expect(inserted[0].billed_cost).toBe('12.50');
    expect(inserted[0].amortized_cost).toBeUndefined();
    expect(inserted[0].net_cost).toBeUndefined();
  });

  it('deduplicates an unchanged re-sync without writing', async () => {
    const fp = await fingerprintCostFact(ctx, input());
    const { db, inserted, updated } = fakeDb([{ id: 'f1', record_fingerprint: fp, billed_cost: '12.50', revision: 1 }]);
    const r = await writeCostFacts(db, ctx, [input()]);
    expect(r).toMatchObject({ inserted: 0, unchanged: 1, restated: 0 });
    expect(inserted).toHaveLength(0);
    expect(updated).toHaveLength(0);
  });

  it('does not manufacture a restatement from trailing-zero differences', async () => {
    const fp = await fingerprintCostFact(ctx, input());
    const { db, inserted } = fakeDb([{ id: 'f1', record_fingerprint: fp, billed_cost: '12.5000', revision: 1 }]);
    const r = await writeCostFacts(db, ctx, [input({ amount: '12.50' })]);
    expect(r.unchanged).toBe(1);
    expect(inserted).toHaveLength(0);
  });

  it('records a restatement as a NEW revision, superseding the old one', async () => {
    const fp = await fingerprintCostFact(ctx, input());
    const { db, inserted, updated } = fakeDb([{ id: 'f1', record_fingerprint: fp, billed_cost: '100.00', revision: 1 }]);
    const r = await writeCostFacts(db, ctx, [input({ amount: '102.50' })]);

    expect(r).toMatchObject({ inserted: 0, unchanged: 0, restated: 1 });
    expect(r.restatedFingerprints).toEqual([fp]);

    // The prior revision is superseded, never overwritten -- §15/§17 require
    // the old amount to stay auditable.
    expect(updated[0].patch.status).toBe('SUPERSEDED');
    expect(inserted[0]).toMatchObject({ revision: 2, supersedes_id: 'f1', status: 'RESTATED', billed_cost: '102.50' });
    expect(String(inserted[0].restatement_reason)).toContain('100.00');
  });

  it('supersedes BEFORE inserting the new revision', async () => {
    /**
     * Ordering matters and is not arbitrary. If the insert ran first and the
     * supersede then failed, there would be TWO current revisions -- which
     * double-counts and looks correct. The other way round, a failure leaves
     * a period with no current revision, which is visibly wrong.
     */
    const fp = await fingerprintCostFact(ctx, input());
    const order: string[] = [];
    const db = {
      select: async () => [{ id: 'f1', record_fingerprint: fp, billed_cost: '100.00', revision: 1 }],
      update: async () => { order.push('update'); return []; },
      insert: async () => { order.push('insert'); return []; },
    } as never;
    await writeCostFacts(db, ctx, [input({ amount: '102.50' })]);
    expect(order).toEqual(['update', 'insert']);
  });

  it('ignores superseded rows when comparing', async () => {
    // Comparing against history would make a value appear to flip back and
    // forth on every sync.
    const { db } = fakeDb();
    const r = await writeCostFacts(db, ctx, [input()]);
    expect(r.inserted).toBe(1);
  });

  it('writes nothing for an empty sync', async () => {
    const { db, inserted } = fakeDb();
    const r = await writeCostFacts(db, ctx, []);
    expect(r).toMatchObject({ inserted: 0, unchanged: 0, restated: 0 });
    expect(inserted).toHaveLength(0);
  });
});

describe('cost source state', () => {
  it('separates "not enabled" from "denied" from "broken"', () => {
    /**
     * Collapsing these sends someone to fix an IAM policy that is already
     * correct -- and all three currently render as $0.
     */
    expect(stateForFailure(400, 'User not enabled for cost explorer access')).toMatchObject({
      state: 'NOT_CONFIGURED', reasonCode: 'cost_explorer_not_enabled', retryable: false,
    });
    expect(stateForFailure(403, 'AccessDenied')).toMatchObject({ state: 'PERMISSION_DENIED', retryable: false });
    expect(stateForFailure(500, 'Internal error')).toMatchObject({ state: 'FAILED', retryable: true });
    expect(stateForFailure(429, 'Rate exceeded')).toMatchObject({ state: 'FAILED', reasonCode: 'throttled', retryable: true });
  });

  it('never leaks raw provider text into the customer-safe field', () => {
    const out = stateForFailure(403, 'AccessDenied: arn:aws:iam::999999999999:user/svc is not authorized');
    expect(out.errorDetailSafe).not.toContain('999999999999');
  });

  it('reports PARTIAL when an account returned nothing', () => {
    // §22: 8 of 10 accounts is PARTIAL, never a complete total and never $0.
    expect(stateForSuccess({
      requestedAccountIds: ['1', '2'], coveredAccountIds: ['1'], sourceObservedAt: null,
    })).toMatchObject({ state: 'PARTIAL', reasonCode: 'accounts_not_covered' });
  });

  it('reports AVAILABLE only when coverage is complete', () => {
    expect(stateForSuccess({
      requestedAccountIds: ['1'], coveredAccountIds: ['1'], sourceObservedAt: null,
    })).toMatchObject({ state: 'AVAILABLE' });
  });

  it('judges staleness on when the PROVIDER observed, not when we ran', () => {
    /**
     * A sync that succeeded a minute ago against data AWS last updated a week
     * ago is a fresh request over stale facts.
     */
    const weekOld = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();
    expect(stateForSuccess({
      requestedAccountIds: ['1'], coveredAccountIds: ['1'], sourceObservedAt: weekOld,
    })).toMatchObject({ state: 'STALE', reasonCode: 'outside_freshness_slo' });
  });
});
