import type { Db } from '@horizonvigil/shared-lib';

/**
 * Reads every row matching a filter, in pages.
 *
 * WHY THIS EXISTS
 *
 * `limit: 5000` does not return 5,000 rows. PostgREST applies its own
 * server-side row cap — 1,000 in this deployment — before any app-level limit
 * is considered. A read asking for 5,000 and getting 1,000 does not look like
 * an error to the caller; it looks like an estate with 1,000 things in it.
 *
 * This has now bitten the product four separate times:
 *
 *   - 1,805 resources rendered as 1,000
 *   - monitoring health reported ~1,000 of 1,805 live resources
 *   - an account page said "200 of 200 loaded" over 442 rows
 *   - `finalizeRun` recorded "12 of 1000 step(s) failed" for a run with 17
 *     failures across 1,628 steps, and could have committed it as SUCCEEDED
 *
 * Every one under-reported, which is the direction that hides: a number that
 * grows to the cap and then stops looks like a plateau, not a bug.
 *
 * USE THIS WHEN THE ROWS FEED A TOTAL
 *
 * A SUM or a COUNT derived from a truncated page is wrong, and wrong quietly.
 * A bounded DISPLAY list (the 8 most recent activity rows, 5 open alerts) is
 * not: it asks for a page and shows a page. Reach for this where the answer is
 * an aggregate, not where it is a preview.
 *
 * `selectWithCount` remains the better tool when only the COUNT is needed —
 * it reads the exact total off `Content-Range` without fetching the rows at
 * all. This is for the cases that genuinely need every row, such as a sum.
 */

/** PostgREST's server-side cap in this deployment. Pages larger than this are silently truncated. */
export const POSTGREST_MAX_ROWS = 1000;

/** Refuses to page forever if a filter or ordering is pathological. 100 pages = 100,000 rows. */
const MAX_PAGES = 100;

export interface PagedResult<T> {
  rows: T[];
  /**
   * False when the page limit was hit before the data ran out. A caller that
   * publishes a total MUST check this rather than treating the rows as
   * everything — reporting a partial sum as a total is the defect this module
   * exists to prevent.
   */
  complete: boolean;
}

/**
 * @param opts `limit` is ignored if supplied — the page size is fixed at the
 *             server cap, because a larger value is what produced the silent
 *             truncation in the first place. An `order` is strongly advised:
 *             without one, PostgREST's row order is unspecified between
 *             requests, so paging can repeat one row and skip another.
 */
export async function selectAllPages<T>(
  db: Db,
  table: string,
  opts: { select?: string; filters?: Record<string, string>; order?: string },
): Promise<PagedResult<T>> {
  const rows: T[] = [];

  for (let page = 0; page < MAX_PAGES; page += 1) {
    const batch = await db.select<T[]>(table, {
      ...opts,
      limit: POSTGREST_MAX_ROWS,
      offset: page * POSTGREST_MAX_ROWS,
    });

    rows.push(...batch);

    // A short page is the last page. An exactly-full one may not be, so it
    // costs one more request to prove there is nothing after it.
    if (batch.length < POSTGREST_MAX_ROWS) return { rows, complete: true };
  }

  return { rows, complete: false };
}
