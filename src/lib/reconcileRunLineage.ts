import type { Db } from '@horizonvigil/shared-lib';
import { reconcileLineage, toReconciliationRow, type BatchAccounting, type PersistedCount } from './lineageReconciliation';

/**
 * Loads one run's admission accounting and the rows it produced, reconciles
 * them, and stores the verdict.
 *
 * Separated from the pure comparison so the rules stay testable without a
 * database, and separated from the route so the finalize path calls one
 * function rather than assembling queries inline.
 */
export async function reconcileRunLineage(
  db: Db,
  ctx: { orgId: string; connectionId: string; collectionRunId: string; accountId: string | null; evaluatedScopes: readonly string[] },
): Promise<{ status: string; drift: number }> {
  const batchRows = await db.select<{
    collector: string; observed_count: number | null; accepted_count: number | null;
    quarantined_count: number | null; rejected_count: number | null;
  }[]>('ingestion_batches', {
    select: 'collector,observed_count,accepted_count,quarantined_count,rejected_count',
    filters: { collection_run_id: `eq.${ctx.collectionRunId}` },
    limit: 1000,
  });

  /**
   * Collapsed per collector before comparison.
   *
   * A run writes one batch per STEP, so a 1,628-step run produces thousands of
   * batch rows and the ~1000-row page cap would silently truncate them --
   * reconciling a prefix of the run and reporting PASSED over the part it
   * could see. Aggregating in SQL is the better shape long-term; collapsing
   * here keeps the page bounded in the meantime, and the count below proves
   * whether the cap was reached.
   */
  const byCollector = new Map<string, BatchAccounting>();
  for (const r of batchRows) {
    const key = r.collector ?? '(unknown)';
    const acc = byCollector.get(key) ?? { collector: key, observedCount: 0, acceptedCount: 0, quarantinedCount: 0, rejectedCount: 0 };
    acc.observedCount += r.observed_count ?? 0;
    acc.acceptedCount += r.accepted_count ?? 0;
    acc.quarantinedCount += r.quarantined_count ?? 0;
    acc.rejectedCount += r.rejected_count ?? 0;
    byCollector.set(key, acc);
  }

  // Live rows for this connection. Counted exactly rather than paged, because
  // the number is the whole point of the comparison.
  const [, liveRows] = await db.selectWithCount<{ id: string }[]>('cloud_resources', {
    select: 'id',
    filters: { connection_id: `eq.${ctx.connectionId}`, deleted_at: 'is.null', lifecycle_state: 'eq.ACTIVE' },
    limit: 1,
  });

  const persisted: PersistedCount[] = [{ resourceTypeKey: '(all)', liveRows }];
  const result = reconcileLineage([...byCollector.values()], persisted);

  const row = toReconciliationRow(result, ctx);
  // The page cap is recorded on the row rather than silently ignored: a
  // reconciliation that only saw part of a run must say so.
  if (batchRows.length >= 1000) {
    row.reason_code = 'batch_page_cap_reached';
    row.status = 'BLOCKED';
  }

  await db.insert('inventory_reconciliations', row, 'return=minimal');
  return { status: String(row.status), drift: result.drift.length };
}
