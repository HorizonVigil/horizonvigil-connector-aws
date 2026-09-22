import { describe, expect, it } from 'vitest';

import { recordCostSourceState, stateForFailure, stateForSuccess, type CostSourceOutcome } from './costSourceState';
import type { Db } from '@horizonvigil/shared-lib';

/** Captures every insert so both tables written by one call can be asserted. */
function recordingDb() {
  const inserts: { table: string; rows: Record<string, unknown>[] }[] = [];
  const db = {
    insert: async (table: string, rows: unknown) => {
      inserts.push({ table, rows: (Array.isArray(rows) ? rows : [rows]) as Record<string, unknown>[] });
      return [];
    },
  } as unknown as Db;
  const rowsFor = (tablePrefix: string) =>
    inserts.filter((i) => i.table.startsWith(tablePrefix)).flatMap((i) => i.rows);
  return { db, inserts, rowsFor };
}

const ctx = { orgId: 'org-1', connectionId: 'conn-1', sourceType: 'COST_EXPLORER' as const };

/**
 * AWS-M3. `cost_source_status` and `connector_capability_status` describe the
 * same fact from two angles, and a sync wrote only one of them.
 *
 * Production, 2026-09-22: a Cost Explorer sync succeeded at 13:01 and
 * `billing_cost_explorer` still read `last_success 2026-09-15`. A customer
 * looking at capability health was told the source was a week stale while the
 * cost data in front of them was current.
 */
describe('recordCostSourceState writes both tables', () => {
  it('a successful sync refreshes the capability row, not just the cost source', async () => {
    const { db, rowsFor } = recordingDb();

    await recordCostSourceState(db, ctx, { state: 'AVAILABLE', reasonCode: null });

    const [capability] = rowsFor('connector_capability_status');
    expect(capability).toBeTruthy();
    expect(capability.capability).toBe('billing_cost_explorer');
    expect(capability.state).toBe('available');
    expect(capability.last_success_at).toBeTruthy();
    expect(capability.source).toBe('cost_sync');
  });

  it('maps CUR to its own capability', async () => {
    const { db, rowsFor } = recordingDb();

    await recordCostSourceState(db, { ...ctx, sourceType: 'CUR_DATA_EXPORT' }, { state: 'AVAILABLE' });

    expect(rowsFor('connector_capability_status')[0].capability).toBe('billing_cur');
  });

  it('both rows describe the same outcome', async () => {
    // Written from one outcome rather than recomputed, so they cannot
    // disagree about what just happened — which is the whole defect.
    const { db, rowsFor } = recordingDb();

    await recordCostSourceState(db, ctx, { state: 'PERMISSION_DENIED', reasonCode: 'access_denied' });

    const [source] = rowsFor('cost_source_status');
    const [capability] = rowsFor('connector_capability_status');
    expect(source.state).toBe('PERMISSION_DENIED');
    expect(capability.state).toBe('permission_denied');
    expect(capability.reason_code).toBe(source.reason_code);
  });

  /**
   * The rule that stops a stale number being presented as current, applied
   * identically in both tables.
   */
  it('does not advance success on a state that produced no usable data', async () => {
    const { db, rowsFor } = recordingDb();

    await recordCostSourceState(db, ctx, { state: 'FAILED', reasonCode: 'provider_error' });

    const [capability] = rowsFor('connector_capability_status');
    expect(capability.covered_scope).toBe(0);
  });

  /**
   * These rows upsert with merge-duplicates, so an explicit null OVERWRITES a
   * real earlier success and reports a source that worked yesterday as one
   * that has never worked at all.
   */
  it('OMITS last_success_at on failure rather than nulling it', async () => {
    const { db, rowsFor } = recordingDb();

    await recordCostSourceState(db, ctx, { state: 'FAILED' });

    const [capability] = rowsFor('connector_capability_status');
    expect('last_success_at' in capability).toBe(false);
  });

  it('treats PARTIAL as usable — some real data did arrive', async () => {
    const { db, rowsFor } = recordingDb();

    await recordCostSourceState(db, ctx, { state: 'PARTIAL', reasonCode: 'accounts_not_covered' });

    const [capability] = rowsFor('connector_capability_status');
    expect(capability.state).toBe('partial');
    expect(capability.last_success_at).toBeTruthy();
  });

  it('claims no permission snapshot, because a cost sync is not one', async () => {
    const { db, rowsFor } = recordingDb();

    await recordCostSourceState(db, ctx, { state: 'AVAILABLE' });

    expect(rowsFor('connector_capability_status')[0].permission_snapshot_id).toBeNull();
  });

  /**
   * Every cost state must map to a real availability state. A mechanical
   * lowercase() would look right and silently invent three that do not exist
   * in the target vocabulary, and a capability state nothing recognises reads
   * as neither available nor broken.
   */
  it('maps every cost state to a recognised availability state', async () => {
    const ALL: CostSourceOutcome['state'][] = [
      'NOT_CONFIGURED', 'VALIDATING', 'WAITING_FOR_EXPORT', 'INGESTING',
      'AVAILABLE', 'PARTIAL', 'STALE', 'PERMISSION_DENIED', 'FAILED', 'UNSUPPORTED',
    ];
    const KNOWN = new Set([
      'not_configured', 'not_enabled', 'unsupported', 'validating', 'available',
      'partial', 'stale', 'permission_denied', 'throttled', 'failed', 'disconnected',
    ]);

    for (const state of ALL) {
      const { db, rowsFor } = recordingDb();
      await recordCostSourceState(db, ctx, { state });
      const mapped = rowsFor('connector_capability_status')[0].state;
      expect(KNOWN.has(String(mapped)), `${state} -> ${String(mapped)}`).toBe(true);
    }
  });

  it('a write failure on either table never fails the sync it describes', async () => {
    const db = { insert: async () => { throw new Error('postgrest exploded'); } } as unknown as Db;

    // Cost data is the thing that matters; losing it because a status row
    // could not be written would be strictly worse than a missing status row.
    await expect(recordCostSourceState(db, ctx, { state: 'AVAILABLE' })).resolves.toBeUndefined();
  });
});

/** The existing classification rules, which this change depends on and must not alter. */
describe('cost source classification', () => {
  it('separates "never opted in" from "denied"', () => {
    expect(stateForFailure(400, 'User not enabled for cost explorer access').state).toBe('NOT_CONFIGURED');
    expect(stateForFailure(403, 'AccessDenied').state).toBe('PERMISSION_DENIED');
  });

  it('a success covering fewer accounts than requested is PARTIAL, not AVAILABLE', () => {
    const out = stateForSuccess({
      requestedAccountIds: ['1', '2'],
      coveredAccountIds: ['1'],
      sourceObservedAt: null,
    });
    expect(out.state).toBe('PARTIAL');
  });

  it('judges freshness on what the provider observed, not on when we ran', () => {
    const out = stateForSuccess({
      requestedAccountIds: ['1'],
      coveredAccountIds: ['1'],
      sourceObservedAt: '2026-09-01T00:00:00Z',
      now: Date.parse('2026-09-22T00:00:00Z'),
    });
    expect(out.state).toBe('STALE');
  });
});
