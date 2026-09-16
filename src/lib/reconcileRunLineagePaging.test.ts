import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Reconciliation must see the WHOLE run, not one page of it.
 *
 * The first version read a single page of 1,000 batches and reported BLOCKED
 * whenever the cap was reached. The refusal was right -- passing over a
 * partial read is exactly what this control prevents -- but it made the
 * control useless: a 1,628-step run writes one batch per step, so every run
 * exceeded the cap and every reconciliation came back BLOCKED.
 *
 * Measured on run b28b0f30: 1,509 batches, 1,000 read, 370 records accounted
 * for, verdict BLOCKED. A control that can only ever say "I could not tell"
 * is not a control.
 */
const SOURCE = readFileSync(join(__dirname, 'reconcileRunLineage.ts'), 'utf8');

describe('lineage reconciliation paging', () => {
  it('pages to exhaustion rather than reading one capped page', () => {
    expect(SOURCE).toMatch(/for \(let page = 0; ; page\+\+\)/);
    expect(SOURCE).toContain('offset: page * PAGE_LIMIT');
    expect(SOURCE).toContain('if (rows.length < PAGE_LIMIT) break;');
  });

  /**
   * Paging without a stable order can return one row twice and miss another,
   * which would produce a silently wrong accounting rather than an obvious
   * failure.
   */
  it('orders the pages so rows cannot repeat or be skipped', () => {
    expect(SOURCE).toContain("order: 'id.asc'");
  });

  /**
   * PostgREST truncates above its own cap without saying so, so asking for
   * 5,000 and receiving 1,000 looks like a run with 1,000 batches.
   */
  it('requests no more per page than the server will return', () => {
    expect(SOURCE).toMatch(/const PAGE_LIMIT = 1000;/);
  });

  /** The load-bearing negative: the old unconditional cap check is gone. */
  it('no longer blocks merely because a page was full', () => {
    expect(SOURCE).not.toMatch(/if \(batchRows\.length >= 1000\)/);
  });

  /**
   * Still bounded, and still honest when the bound is hit. A run that
   * exhausts MAX_PAGES is BLOCKED rather than passed on partial input.
   */
  it('remains bounded and still refuses to pass on a partial read', () => {
    expect(SOURCE).toContain('MAX_PAGES');
    expect(SOURCE).toMatch(/if \(truncated\) \{/);
    expect(SOURCE).toContain("row.status = 'BLOCKED'");
  });

  /** Live rows stay an exact count -- the number is the point of the compare. */
  it('counts live rows exactly rather than paging them', () => {
    expect(SOURCE).toContain('selectWithCount');
  });
});
