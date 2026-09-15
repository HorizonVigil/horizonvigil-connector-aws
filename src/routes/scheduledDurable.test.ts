import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * AWS-06 — the scheduled collection path must go through the durable job
 * machinery, not around it.
 *
 * Source-level, like the other guards here, because the defect is a property
 * of HOW collection is driven. A behavioural test with a stubbed database
 * would happily execute an inline loop and report success — which is exactly
 * what production did for four days without anyone noticing.
 *
 * What was wrong: `/internal/run-due-scans` and `/internal/run-first-scans`
 * both looped over connections calling `runResourceStep` / `runFindingStep` /
 * `runMetricStep` directly, then called `runFinalize` themselves. Neither
 * created a `collection_runs` row.
 *
 * So the path that actually ran in production — on a schedule, unattended —
 * had no lease, no checkpoint, no run status, and no protection against two
 * overlapping invocations. Measured 2026-09-15: 4 run rows in total, newest
 * 2026-09-10, while `ingestion_batches` grew 7,960 → 15,422 over the
 * following four days. Roughly 7,500 batches that no run row describes.
 */
const SOURCE = readFileSync(join(__dirname, 'internalScan.ts'), 'utf8');

describe('scheduled collection is durable', () => {
  it('both scheduled entry points create a collection run', () => {
    const creates = SOURCE.match(/createOrGetActiveRun\(/g) ?? [];
    expect(creates.length).toBe(2);
    expect(SOURCE).toContain("trigger: 'schedule'");
    expect(SOURCE).toContain("trigger: 'initial_sync'");
  });

  /**
   * The trigger vocabulary is a CHECK constraint on collection_runs:
   *
   *   'user' | 'schedule' | 'initial_sync' | 'retry' | 'backfill'
   *
   * The first cut of this change invented 'scheduled' and 'first_scan'.
   * Both built, both typechecked, both passed the suite -- and production
   * returned 500 on the first real trigger with 23514 check_violation. A
   * string that only the database validates is invisible to tsc, so it is
   * pinned here instead.
   */
  it('uses only trigger values the database constraint permits', () => {
    const ALLOWED = ['user', 'schedule', 'initial_sync', 'retry', 'backfill'];
    const used = [...SOURCE.matchAll(/trigger: '([a-z_]+)'/g)].map((m) => m[1]);
    expect(used.length).toBeGreaterThan(0);
    for (const t of used) expect(ALLOWED, `trigger '${t}' violates collection_runs_trigger_check`).toContain(t);
  });

  /**
   * The load-bearing negatives. Each string below is verbatim from the
   * pre-fix source, so restoring an inline executor fails here rather than
   * silently running unattended collection outside the durable machinery
   * again.
   */
  it('neither entry point executes collection steps inline', () => {
    expect(SOURCE).not.toContain('runOneStep(');
    expect(SOURCE).not.toContain('for (const stepId of steps)');
    expect(SOURCE).not.toMatch(/await\s+runFinalize\(/);
    // Scoped to real call sites. The prose above deliberately names the
    // removed functions, so a bare substring match would fail on this file's
    // own explanation of what it prevents.
    expect(SOURCE).not.toMatch(/await\s+runResourceStep\(/);
    expect(SOURCE).not.toMatch(/await\s+runMetricStep\(/);
    expect(SOURCE).not.toMatch(/await\s+runFindingStep\(/);
  });

  /**
   * Step planning must come from the shared `planSteps`. Two copies of the
   * plan is how the scheduled and interactive paths diverged to begin with —
   * the interactive one gained durability and the scheduled one did not.
   */
  it('reuses the shared step planner rather than rebuilding the plan', () => {
    expect(SOURCE).toContain('planSteps(connection as never)');
    expect(SOURCE).not.toContain('REGIONAL_SCANNERS');
    expect(SOURCE).not.toContain('GLOBAL_SCANNERS');
  });

  /**
   * `next_scheduled_scan_at` must advance even when a run already exists.
   * Leaving it in the past while a connection is mid-collection would
   * re-enqueue it on every tick forever.
   */
  it('advances the next scan time regardless of whether a run was created', () => {
    expect(SOURCE).toContain('next_scheduled_scan_at: nextScan');
    expect(SOURCE).toMatch(/const \{ run, created \} = await createOrGetActiveRun/);
  });
});
