import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Phase 2 wrote `ingestion_batches`, `provider_requests`,
 * `resource_observations` and `quarantine_records` as evidence tables:
 * member-READ only, with INSERT/UPDATE/DELETE/TRUNCATE revoked from
 * `authenticated`.
 *
 * That makes the write path's authentication load-bearing. `runResourceStep`
 * writes lineage using whichever Db its caller hands it, so a caller passing
 * a JWT-scoped Db would get 42501 on every ingestion -- inventory would still
 * be written (cloud_resources is not revoked) while the evidence silently
 * failed, which is precisely the "canonical resource with no traceable
 * source" condition this phase forbids.
 *
 * Both real callers use the service role today. This test pins that, at the
 * source level, because the failure would otherwise appear as a quiet gap in
 * evidence rather than as a broken scan.
 *
 * Read with readFileSync rather than `import.meta.glob`, which is Vite-only
 * and breaks these services' CommonJS `tsc` build.
 */
const read = (p: string) => readFileSync(join(__dirname, p), 'utf8');

describe('lineage write path runs under the service role', () => {
  it('the worker tick builds its Db from SUPABASE_SERVICE_ROLE_KEY', () => {
    const src = read('collectionRuns.ts');
    expect(src).toContain('createDb(c.env, c.env.SUPABASE_SERVICE_ROLE_KEY)');
    // The tick is the caller that drives executeStep -> runResourceStep.
    expect(src).toContain('executeStep(db, c.env, run, steps[i], i)');
  });

  it('the scheduled scan builds its Db from SUPABASE_SERVICE_ROLE_KEY', () => {
    const src = read('internalScan.ts');
    expect(src).toContain('createDb(c.env, c.env.SUPABASE_SERVICE_ROLE_KEY)');
    expect(src).toContain('runResourceStep(db, orgId, null, env, connectionId, stepId)');
  });

  it('no route hands runResourceStep a caller-JWT Db', () => {
    /**
     * A negative assertion that would have caught the mistake: if a route
     * ever calls runResourceStep with the `db` it built from
     * `auth.accessToken`, ingestion evidence stops being written.
     */
    for (const file of ['discovery.ts', 'collectionRuns.ts', 'internalScan.ts', 'accounts.ts']) {
      const src = read(file);
      const jwtDbCalls = src.match(/runResourceStep\(\s*createDb\(c\.env,\s*auth\.accessToken\)/g);
      expect(jwtDbCalls, `${file} passes a caller-JWT Db to runResourceStep`).toBeNull();
    }
  });

  /**
   * Scoped to runResourceStep's own body.
   *
   * `runFindingStep` and `runMetricStep` live in the same file and have their
   * own `scanned.map(...)`, so a file-wide assertion here fails for the wrong
   * reason -- it did, on the first run of this test. They are also genuinely
   * out of scope: findings target `vulnerability_findings` (V2-gated, and the
   * phase brief says not to touch vulnerability functionality) and metrics
   * target `resource_metrics`, a time series rather than canonical resource
   * state. Phase 2's canonical-admission rule is about the canonical RESOURCE
   * table, and that limitation is recorded in the certification rather than
   * glossed over by a broader assertion that happens to pass.
   */
  function runResourceStepBody(): string {
    const src = read('discovery.ts');
    const start = src.indexOf('export async function runResourceStep(');
    expect(start, 'runResourceStep not found').toBeGreaterThan(-1);
    const next = src.indexOf('\nexport ', start + 1);
    return src.slice(start, next === -1 ? undefined : next);
  }

  it('opens the batch before the scanner runs, so a crash leaves evidence', () => {
    /**
     * "No batch" and "a batch that failed" must not look the same. If the
     * batch were opened after a successful scan, a step that died mid-scan
     * would leave no record that ingestion was ever attempted.
     */
    const body = runResourceStepBody();
    const openIdx = body.indexOf('const batch = await openBatch(db, {');
    const scanIdx = body.indexOf('scanned = await scanner(');
    expect(openIdx).toBeGreaterThan(-1);
    expect(scanIdx).toBeGreaterThan(-1);
    expect(openIdx).toBeLessThan(scanIdx);
  });

  it('only ACCEPTED records reach the canonical upsert', () => {
    /**
     * The canonical-admission rule (§7). Before Phase 2 this read
     * `scanned.map(...)`, so every raw provider record became inventory
     * regardless of whether it was valid.
     */
    const body = runResourceStepBody();
    expect(body).toContain('const rows = admission.accepted.map(');
    expect(body).not.toMatch(/const rows = scanned\.map\(/);
    // And the upsert it feeds is the canonical resource table.
    expect(body).toContain("'cloud_resources?on_conflict=connection_id,resource_type_key,resource_id'");
  });
});
