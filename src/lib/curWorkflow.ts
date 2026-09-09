import type { Db } from '@horizonvigil/shared-lib';
import type { Env } from '../env';

/**
 * Server-owned CUR ingestion (§3.4), replacing browser orchestration.
 *
 * What this replaces was worse than the discovery loop: the browser ran a
 * `for` over every report file with an UNBOUNDED `while` over row chunks
 * inside it, calling `cur/ingest-step` once per chunk and carrying the
 * skipRows offset in a local variable. Closing the tab mid-ingest left the
 * billing period partially ingested with nothing recording where it stopped
 * — and cost data that is silently partial is worse than none, because it
 * still renders as a number.
 *
 * Resume is per-FILE, not per-step: one report file can hold hundreds of
 * thousands of rows, so `checkpoint_data` records the row offset reached in
 * each file. Ingestion is an idempotent upsert on
 * (connection_id, resource_id, usage_date), so re-running a partially
 * ingested file corrects rather than duplicates — the checkpoint is an
 * efficiency measure, not a correctness one.
 */

/** Wall-clock budget for one file's ingestion inside a single worker tick. */
export const CUR_FILE_TIME_BUDGET_MS = 90_000;

export interface CurStepOutcome {
  /** True when this file finished; false means resume it on the next tick. */
  done: boolean;
  rowsProcessed: number;
  error?: string;
}

export interface CurCheckpoint {
  [reportKey: string]: number;
}

/**
 * Ingests one report file, resuming from its recorded offset and stopping at
 * the time budget rather than risking the request timeout.
 *
 * `ingestBatch` is injected so the worker's control flow is unit-testable
 * without S3, credentials, or a database.
 */
export async function ingestCurFile(
  reportKey: string,
  checkpoint: CurCheckpoint,
  ingestBatch: (reportKey: string, skipRows: number) => Promise<{ rowsProcessed: number; done: boolean } | { error: string }>,
  opts: { budgetMs?: number; now?: () => number } = {},
): Promise<CurStepOutcome> {
  const budgetMs = opts.budgetMs ?? CUR_FILE_TIME_BUDGET_MS;
  const now = opts.now ?? Date.now;
  const startedAt = now();

  let skipRows = checkpoint[reportKey] ?? 0;

  for (;;) {
    const result = await ingestBatch(reportKey, skipRows);
    if ('error' in result) {
      // Keep the offset reached so far: a failure part-way through a large
      // file must not send the retry back to row 0.
      return { done: false, rowsProcessed: skipRows, error: result.error };
    }

    skipRows = result.rowsProcessed;
    if (result.done) return { done: true, rowsProcessed: skipRows };

    // Out of budget: stop cleanly with the offset recorded. The next tick
    // picks this same file up where it stopped.
    if (now() - startedAt >= budgetMs) return { done: false, rowsProcessed: skipRows };
  }
}

/** Merges one file's progress into the run checkpoint without losing other files' offsets. */
export function advanceCheckpoint(checkpoint: CurCheckpoint, reportKey: string, rowsProcessed: number): CurCheckpoint {
  return { ...checkpoint, [reportKey]: rowsProcessed };
}

/**
 * Records the sync timestamp once every file has completed.
 *
 * Deliberately NOT called when any file is still outstanding: `cur_last_synced_at`
 * is what the UI reads as "your billing data is current as of", and stamping
 * it on a partial ingest would make incomplete cost data look complete —
 * exactly the false-freshness claim the availability contract exists to stop.
 */
export async function finalizeCurRun(db: Db, connectionId: string, now: string = new Date().toISOString()): Promise<void> {
  await db.update('cloud_connections', { id: `eq.${connectionId}` }, { cur_last_synced_at: now }, 'return=minimal');
}

/** True only when every planned file reached `done`. */
export function allFilesComplete(plannedKeys: readonly string[], completedKeys: ReadonlySet<string>): boolean {
  return plannedKeys.length > 0 && plannedKeys.every((k) => completedKeys.has(k));
}
