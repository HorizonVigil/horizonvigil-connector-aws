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
  /**
   * Paged to exhaustion, not capped.
   *
   * The first version read one page of 1,000 and reported BLOCKED whenever
   * the cap was reached. That was the right refusal -- passing over a partial
   * read is exactly what this control exists to prevent -- but it made the
   * control useless in practice: a 1,628-step run writes one batch per step,
   * so EVERY run exceeded the cap and every reconciliation came back BLOCKED.
   * A control that can only ever say "I could not tell" is not a control.
   *
   * Measured on run b28b0f30: 1,509 batches, of which 1,000 were read and 370
   * records accounted for. Paging sees all of them in two round trips.
   *
   * PAGE_LIMIT stays at the server's own cap rather than something larger,
   * because PostgREST silently truncates above it -- asking for 5,000 and
   * receiving 1,000 looks like a run with 1,000 batches.
   */
  const PAGE_LIMIT = 1000;
  const MAX_PAGES = 50;
  type BatchRow = {
    collector: string; observed_count: number | null; accepted_count: number | null;
    quarantined_count: number | null; rejected_count: number | null;
  };

  const batchRows: BatchRow[] = [];
  let truncated = false;
  for (let page = 0; ; page++) {
    if (page >= MAX_PAGES) { truncated = true; break; }
    const rows = await db.select<BatchRow[]>('ingestion_batches', {
      select: 'collector,observed_count,accepted_count,quarantined_count,rejected_count',
      filters: { collection_run_id: `eq.${ctx.collectionRunId}` },
      // Stable ordering, or paging can repeat one row and miss another.
      order: 'id.asc',
      limit: PAGE_LIMIT,
      offset: page * PAGE_LIMIT,
    });
    batchRows.push(...rows);
    if (rows.length < PAGE_LIMIT) break;
  }

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
  /**
   * Only a run so large it exhausts MAX_PAGES is BLOCKED now -- 50,000
   * batches, which no real run approaches. A reconciliation that saw part of
   * a run must still say so rather than pass on what it could read.
   */
  if (truncated) {
    row.reason_code = 'batch_page_cap_reached';
    row.status = 'BLOCKED';
  }

  await db.insert('inventory_reconciliations', row, 'return=minimal');
  return { status: String(row.status), drift: result.drift.length };
}
