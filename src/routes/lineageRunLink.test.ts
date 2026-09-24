import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Every ingestion batch must name the run that produced it.
 *
 * `ingestion_batches.collection_run_id` was NULL on all 24,476 rows in
 * production. `openBatch` accepted the field and wrote it; the caller in
 * discovery.ts passed a hardcoded `null`, and the durable worker -- which
 * knows `run.id` -- never threaded it down.
 *
 * The consequence is that the lineage chain has a missing link: a stored
 * resource cannot be traced back to the run that collected it, which is the
 * entire premise of AWS-11. It was found by the reconciler on its first ever
 * execution, which reported `no_batches` rather than silently passing.
 */
const DISCOVERY = readFileSync(join(__dirname, 'discovery.ts'), 'utf8');
const WORKER = readFileSync(join(__dirname, 'collectionRuns.ts'), 'utf8');

describe('ingestion batches are linked to their collection run', () => {
  /** The load-bearing negative, verbatim from the pre-fix source. */
  it('does not hardcode a null run id when opening a batch', () => {
    expect(DISCOVERY).not.toMatch(/collectionRunId:\s*null,\s*\n\s*collectionStepId/);
  });

  it('passes the run id through to openBatch', () => {
    expect(DISCOVERY).toMatch(/collectionRunId,\s*\n\s*collectionStepId: stepId,/);
  });

  /**
   * All three step kinds, not just resources. A finding or metric batch that
   * is unlinked leaves the same hole in the chain.
   */
  it('the durable worker supplies run.id to every step kind', () => {
    // Plain substring, not a regex: the call spans lines and the file uses
    // CRLF, which a line-anchored pattern silently fails to match.
    for (const fn of ['runFindingStep', 'runMetricStep', 'runResourceStep']) {
      expect(WORKER.includes(`${fn}(db, run.org_id, null, env, run.connection_id, stepId, run.id)`), fn).toBe(true);
    }
  });

  it('every step function accepts the run id', () => {
    for (const fn of ['runFindingStep', 'runMetricStep', 'runResourceStep']) {
      const at = DISCOVERY.indexOf(`export async function ${fn}(`);
      expect(at, fn).toBeGreaterThan(-1);
      // The parameter appears within the signature that follows.
      expect(DISCOVERY.slice(at, at + 900).includes('collectionRunId: string | null'), fn).toBe(true);
    }
  });
});
