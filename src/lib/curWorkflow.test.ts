import { describe, it, expect, vi } from 'vitest';
import { ingestCurFile, advanceCheckpoint, allFilesComplete, CUR_FILE_TIME_BUDGET_MS } from './curWorkflow';

/**
 * §3.4. The browser ran a `for` over report files with an UNBOUNDED `while`
 * over row chunks inside it, holding the skipRows offset in a local variable.
 * Closing the tab mid-ingest left the billing period partially ingested with
 * nothing recording where it stopped -- and partial cost data is worse than
 * none, because it still renders as a number.
 */
describe('ingestCurFile', () => {
  it('ingests a file to completion', async () => {
    const batch = vi.fn()
      .mockResolvedValueOnce({ rowsProcessed: 1000, done: false })
      .mockResolvedValueOnce({ rowsProcessed: 1800, done: true });

    const out = await ingestCurFile('f1.csv.gz', {}, batch);

    expect(out.done).toBe(true);
    expect(out.rowsProcessed).toBe(1800);
    expect(batch).toHaveBeenCalledTimes(2);
  });

  it('RESUMES from the recorded offset instead of restarting the file', async () => {
    // The whole point of the checkpoint: a 300k-row file interrupted at
    // 240k must not go back to row 0.
    const batch = vi.fn().mockResolvedValue({ rowsProcessed: 300_000, done: true });

    await ingestCurFile('big.csv.gz', { 'big.csv.gz': 240_000 }, batch);

    expect(batch).toHaveBeenCalledWith('big.csv.gz', 240_000);
  });

  it('starts at row 0 for a file it has never seen', async () => {
    const batch = vi.fn().mockResolvedValue({ rowsProcessed: 10, done: true });
    await ingestCurFile('new.csv.gz', { 'other.csv.gz': 500 }, batch);
    expect(batch).toHaveBeenCalledWith('new.csv.gz', 0);
  });

  it('stops at the time budget rather than risking the request timeout', async () => {
    // Cloud Run kills the request at its ceiling; stopping cleanly with the
    // offset recorded is what makes the next tick able to continue.
    let clock = 0;
    const batch = vi.fn().mockImplementation(async (_k: string, skip: number) => {
      clock += 40_000;
      return { rowsProcessed: skip + 1000, done: false };
    });

    const out = await ingestCurFile('huge.csv.gz', {}, batch, { budgetMs: 90_000, now: () => clock });

    expect(out.done).toBe(false);
    expect(out.rowsProcessed).toBeGreaterThan(0);
    // Stopped rather than looping forever.
    expect(batch.mock.calls.length).toBeLessThan(10);
  });

  it('keeps the offset reached when a batch fails part-way through', async () => {
    // A failure at row 240k must not send the retry back to row 0.
    const batch = vi.fn()
      .mockResolvedValueOnce({ rowsProcessed: 240_000, done: false })
      .mockResolvedValueOnce({ error: 'S3 read failed' });

    const out = await ingestCurFile('f.csv.gz', {}, batch);

    expect(out.done).toBe(false);
    expect(out.rowsProcessed).toBe(240_000);
    expect(out.error).toBe('S3 read failed');
  });

  it('uses a budget well under a Cloud Run request ceiling', () => {
    expect(CUR_FILE_TIME_BUDGET_MS).toBeLessThan(10 * 60 * 1000);
  });
});

describe('advanceCheckpoint', () => {
  it('does not lose other files progress', () => {
    const next = advanceCheckpoint({ a: 100, b: 200 }, 'b', 500);
    expect(next).toEqual({ a: 100, b: 500 });
  });
});

describe('allFilesComplete', () => {
  it('is true only when every planned file finished', () => {
    expect(allFilesComplete(['a', 'b'], new Set(['a', 'b']))).toBe(true);
    expect(allFilesComplete(['a', 'b'], new Set(['a']))).toBe(false);
  });

  it('is false for an empty plan, so nothing is stamped as synced', () => {
    // An empty manifest means no data was published yet. Treating that as
    // "complete" would set cur_last_synced_at and make an empty billing
    // period look current.
    expect(allFilesComplete([], new Set())).toBe(false);
  });
});
