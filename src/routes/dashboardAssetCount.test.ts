import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Phase 4 §24/§32 — the AWS dashboard's headline resource count.
 *
 * Source-level, like the other guards in this repo, because the defect is a
 * property of HOW the number is obtained. A behavioural test with a stubbed
 * database would happily return whatever the stub was told to return and
 * would not notice either failure mode below.
 *
 * `resourcesDiscovered` was `resourceRows.length` over a
 * `db.select('cloud_resources', … limit 5000)`. Two separate wrongs:
 *
 *   1. PostgREST caps the row BODY around 1,000 regardless of the app-level
 *      limit, so the count silently truncated. Same class as the bug that
 *      rendered 1,805 resources as 1,000.
 *   2. It counted every row. Measured against production on 2026-09-11:
 *      922 live AWS rows, of which 376 are aliases (KMS aliases, Route 53
 *      records) and only 418 are assets. An alias is a second name for a
 *      thing already counted, so the headline overstated the estate by 41%
 *      -- hard NO-GO condition 2.
 */
const SOURCE = readFileSync(join(__dirname, 'dashboard.ts'), 'utf8');

describe('AWS dashboard resource count', () => {
  it('counts via the server-side breakdown RPC, not a capped row select', () => {
    expect(SOURCE).toContain("db.rpc<{ entity_class: string | null; count: number }[]>('cloud_resources_breakdown'");
  });

  /**
   * The load-bearing negative. Both strings below are verbatim from the
   * pre-fix source, so a revert -- or someone "simplifying" the RPC back to
   * a select -- fails here rather than silently understating a large estate
   * and overstating a small one at the same time.
   */
  it('never derives the count from the length of a fetched row array', () => {
    expect(SOURCE).not.toContain('resourcesDiscovered: resourceRows.length');
    expect(SOURCE).not.toMatch(/db\.select<\{ region: string \| null \}\[\]>\('cloud_resources'/);
  });

  it('reports assets as the headline, not every record', () => {
    expect(SOURCE).toContain('resourcesDiscovered: assetCount');
    expect(SOURCE).toMatch(/if \(entityClass === 'asset'\) assetCount \+= count;/);
  });

  /**
   * A headline dropping from 922 to 418 with no explanation reads as data
   * loss. The all-classes total and the per-class split travel with it so
   * the drop is legible as "aliases are not assets".
   */
  it('ships the all-records total and the per-class split alongside it', () => {
    expect(SOURCE).toContain('resourceRecordsAllClasses: allRecordCount');
    expect(SOURCE).toContain('resourcesByEntityClass: byEntityClass');
  });

  /**
   * An uncatalogued type must count as an asset. Under-reporting an estate
   * is worse than over-reporting it: a type missing from the catalog is our
   * gap, not the customer's missing resource.
   */
  it('treats an uncatalogued entity_class as an asset', () => {
    expect(SOURCE).toMatch(/row\.entity_class \?\? 'asset'/);
  });
});
