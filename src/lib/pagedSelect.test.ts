import { describe, expect, it, vi } from 'vitest';
import type { Db } from '@horizonvigil/shared-lib';

import { selectAllPages, POSTGREST_MAX_ROWS } from './pagedSelect';

/** A db that behaves like PostgREST: honours offset, caps every page at 1,000. */
const serverWith = (total: number) => {
  const select = vi.fn(async (_t: string, opts: { limit?: number; offset?: number }) => {
    const offset = opts.offset ?? 0;
    const limit = Math.min(opts.limit ?? POSTGREST_MAX_ROWS, POSTGREST_MAX_ROWS);
    return Array.from({ length: Math.max(0, Math.min(limit, total - offset)) }, (_, i) => ({ n: offset + i }));
  });
  return { db: { select } as unknown as Db, select };
};

describe('selectAllPages', () => {
  it('returns every row past the server cap', async () => {
    const { db } = serverWith(1628);
    const { rows, complete } = await selectAllPages<{ n: number }>(db, 't', {});

    expect(rows).toHaveLength(1628);
    expect(complete).toBe(true);
    // Not merely the right count -- the right rows, in order, with none
    // repeated and none skipped.
    expect(rows[0].n).toBe(0);
    expect(rows[1627].n).toBe(1627);
    expect(new Set(rows.map((r) => r.n)).size).toBe(1628);
  });

  it('stops on the first short page', async () => {
    const { db, select } = serverWith(1500);
    await selectAllPages(db, 't', {});
    expect(select).toHaveBeenCalledTimes(2);
  });

  it('spends one extra request to prove an exactly-full page was the last', async () => {
    // 1,000 rows is indistinguishable from "1,000 and more" without asking.
    const { db, select } = serverWith(POSTGREST_MAX_ROWS);
    const { rows, complete } = await selectAllPages(db, 't', {});
    expect(rows).toHaveLength(POSTGREST_MAX_ROWS);
    expect(complete).toBe(true);
    expect(select).toHaveBeenCalledTimes(2);
  });

  it('handles an empty result', async () => {
    const { db, select } = serverWith(0);
    const { rows, complete } = await selectAllPages(db, 't', {});
    expect(rows).toEqual([]);
    expect(complete).toBe(true);
    expect(select).toHaveBeenCalledTimes(1);
  });

  it('never asks for more than the server will give', async () => {
    // Asking for 5,000 and receiving 1,000 is what produced every instance of
    // this bug; the page size is fixed so a caller cannot reintroduce it.
    const { db, select } = serverWith(2500);
    await selectAllPages(db, 't', {});
    for (const call of select.mock.calls) {
      expect((call[1] as { limit: number }).limit).toBe(POSTGREST_MAX_ROWS);
    }
  });

  it('advances the offset by exactly one page each time', async () => {
    const { db, select } = serverWith(2500);
    await selectAllPages(db, 't', {});
    expect(select.mock.calls.map((c) => (c[1] as { offset: number }).offset)).toEqual([0, 1000, 2000]);
  });

  it('passes the caller filters and ordering through unchanged', async () => {
    const { db, select } = serverWith(10);
    await selectAllPages(db, 't', { select: 'a,b', filters: { x: 'eq.1' }, order: 'id.asc' });

    const opts = select.mock.calls[0][1] as Record<string, unknown>;
    expect(opts.select).toBe('a,b');
    expect(opts.filters).toEqual({ x: 'eq.1' });
    expect(opts.order).toBe('id.asc');
  });

  /**
   * The honesty property. A caller publishing a SUM must be able to tell that
   * it did not reach the end of the data -- a partial sum is a wrong number,
   * not a smaller one.
   */
  it('reports incomplete rather than silently truncating at the page limit', async () => {
    const { db } = serverWith(500_000);
    const { rows, complete } = await selectAllPages(db, 't', {});

    expect(complete).toBe(false);
    expect(rows).toHaveLength(100 * POSTGREST_MAX_ROWS);
  });
});
