import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  CUR_COLUMNS,
  curManifestCandidates,
  curManifestDataKeys,
  curManifestKey,
  curPartition,
  resolveCurColumns,
} from './curSchema';

/** The ten columns templates/horizonvigil-cur-setup.yaml actually selects. */
const V2_NARROW_HEADER = [
  'bill_billing_period_start_date',
  'line_item_usage_account_id',
  'line_item_line_item_type',
  'line_item_product_code',
  'line_item_resource_id',
  'line_item_unblended_cost',
  'line_item_usage_start_date',
  'product_servicecode',
  'product_region_code',
  'resource_tags',
];

const V1_HEADER = [
  'identity/LineItemId',
  'lineItem/ResourceId',
  'lineItem/UnblendedCost',
  'lineItem/UsageStartDate',
  'lineItem/ProductCode',
  'product/ProductName',
  'product/region',
];

describe('resolveCurColumns picks the generation from the file itself', () => {
  it('recognises a legacy CUR header', () => {
    const resolved = resolveCurColumns(V1_HEADER);
    expect(resolved).not.toHaveProperty('error');
    expect('version' in resolved && resolved.version).toBe('v1');
    expect('columns' in resolved && resolved.columns.resourceId).toBe('lineItem/ResourceId');
  });

  it('recognises a CUR 2.0 header', () => {
    const resolved = resolveCurColumns(V2_NARROW_HEADER);
    expect('version' in resolved && resolved.version).toBe('v2');
    expect('columns' in resolved && resolved.columns.resourceId).toBe('line_item_resource_id');
  });

  /**
   * Detection keys off the three required columns, not the full set. Our own
   * export deliberately selects ten columns rather than the ~100 a full dump
   * gives, so a detector that matched on the complete column list would
   * reject the very report this platform creates.
   */
  it('accepts a narrow export, not just a full column dump', () => {
    expect('version' in resolveCurColumns(V2_NARROW_HEADER)).toBe(true);
    expect('version' in resolveCurColumns(['line_item_resource_id', 'line_item_unblended_cost', 'line_item_usage_start_date'])).toBe(true);
  });

  it('maps every required column to a real position', () => {
    const resolved = resolveCurColumns(V2_NARROW_HEADER);
    if ('error' in resolved) throw new Error(resolved.error);
    for (const key of ['resourceId', 'unblendedCost', 'usageStartDate'] as const) {
      expect(resolved.index[resolved.columns[key]]).toBeGreaterThanOrEqual(0);
    }
    expect(resolved.index['line_item_resource_id']).toBe(V2_NARROW_HEADER.indexOf('line_item_resource_id'));
  });

  it('reports what each generation was missing, rather than a bare failure', () => {
    const resolved = resolveCurColumns(['lineItem/ResourceId']);
    expect(resolved).toHaveProperty('error');
    const { error } = resolved as { error: string };
    // Both generations described: a file matching neither could be either
    // one misconfigured, and the operator needs to know which to look at.
    expect(error).toContain('lineItem/UnblendedCost');
    expect(error).toContain('line_item_resource_id');
    expect(error).toContain('Include resource IDs');
  });

  it('refuses a file that mixes the two spellings', () => {
    expect(resolveCurColumns(['line_item_resource_id', 'lineItem/UnblendedCost', 'lineItem/UsageStartDate']))
      .toHaveProperty('error');
  });

  it('the two column sets share no spelling, so detection cannot be ambiguous', () => {
    const v1 = new Set(Object.values(CUR_COLUMNS.v1));
    for (const name of Object.values(CUR_COLUMNS.v2)) expect(v1.has(name)).toBe(false);
  });
});

describe('billing period partitions differ between generations', () => {
  const sept = new Date(Date.UTC(2026, 8, 14));

  it('v1 names the date range', () => {
    expect(curPartition('v1', sept)).toBe('20260901-20261001');
  });

  it('v2 names the month', () => {
    expect(curPartition('v2', sept)).toBe('BILLING_PERIOD=2026-09');
  });

  it('rolls the year over in December', () => {
    expect(curPartition('v1', new Date(Date.UTC(2026, 11, 31)))).toBe('20261201-20270101');
    expect(curPartition('v2', new Date(Date.UTC(2026, 11, 31)))).toBe('BILLING_PERIOD=2026-12');
  });
});

describe('manifest locations', () => {
  it('v1 puts the manifest beside the period folder', () => {
    expect(curManifestKey('v1', 'hv', 'rpt', '20260901-20261001'))
      .toBe('hv/rpt/20260901-20261001/rpt-Manifest.json');
  });

  it('v2 puts it under metadata/', () => {
    expect(curManifestKey('v2', 'horizonvigil', 'horizonvigil-cur', 'BILLING_PERIOD=2026-09'))
      .toBe('horizonvigil/horizonvigil-cur/metadata/BILLING_PERIOD=2026-09/horizonvigil-cur-Manifest.json');
  });

  it('tolerates a prefix with stray slashes', () => {
    expect(curManifestKey('v1', '/hv/', 'rpt', 'p')).toBe('hv/rpt/p/rpt-Manifest.json');
  });

  /**
   * AWS's delivery documentation contradicts itself on the v2 manifest file
   * name: the Metadata section gives `<export-name>-Manifest.json`, the
   * create-new summary gives a bare `Manifest.json`. Both are tried, because
   * picking one and being wrong means every CUR 2.0 customer sees "no data
   * yet" forever.
   */
  it('tries both documented spellings of the v2 manifest name', () => {
    const keys = curManifestCandidates('horizonvigil', 'horizonvigil-cur', new Date(Date.UTC(2026, 8, 14))).map((c) => c.key);
    expect(keys).toContain('horizonvigil/horizonvigil-cur/metadata/BILLING_PERIOD=2026-09/horizonvigil-cur-Manifest.json');
    expect(keys).toContain('horizonvigil/horizonvigil-cur/metadata/BILLING_PERIOD=2026-09/Manifest.json');
  });

  it('tries v2 before v1, and still reaches v1', () => {
    const candidates = curManifestCandidates('hv', 'rpt', new Date(Date.UTC(2026, 8, 14)));
    expect(candidates[0].version).toBe('v2');
    expect(candidates.map((c) => c.version)).toContain('v1');
    // The partition travels with the candidate, so the caller reports the
    // period it actually found rather than recomputing it for the wrong
    // generation.
    const v1 = candidates.find((c) => c.version === 'v1');
    expect(v1?.partition).toBe('20260901-20261001');
  });
});

describe('reading the file list out of either manifest', () => {
  it('reads v1 reportKeys', () => {
    expect(curManifestDataKeys({ reportKeys: ['a/b.csv.gz', 'a/c.csv.gz'] }))
      .toEqual({ keys: ['a/b.csv.gz', 'a/c.csv.gz'] });
  });

  it('reads v2 dataFiles given as objects', () => {
    expect(curManifestDataKeys({ dataFiles: [{ key: 'x/y-00001.csv.gz' }, { key: 'x/y-00002.csv.gz' }] }))
      .toEqual({ keys: ['x/y-00001.csv.gz', 'x/y-00002.csv.gz'] });
  });

  it('reads dataFiles given as plain strings', () => {
    expect(curManifestDataKeys({ dataFiles: ['x/y-00001.csv.gz'] })).toEqual({ keys: ['x/y-00001.csv.gz'] });
  });

  it('strips an s3:// URL down to the object key', () => {
    expect(curManifestDataKeys({ dataFiles: [{ Key: 's3://some-bucket/x/y-00001.csv.gz' }] }))
      .toEqual({ keys: ['x/y-00001.csv.gz'] });
  });

  /**
   * An empty file list is a real answer -- a billing period can genuinely
   * have no data yet -- and must be distinguishable from a manifest we could
   * not read.
   */
  it('treats an empty list as an answer, not an error', () => {
    expect(curManifestDataKeys({ reportKeys: [] })).toEqual({ keys: [] });
  });

  /**
   * The v2 manifest's field names are not published by AWS. If the real shape
   * turns out to differ from every one accepted here, the failure has to be
   * loud and has to carry the evidence -- reporting zero files would present
   * "we could not read this" as "this month has no cost", and the run would
   * finalize as a clean zero.
   */
  it('names the keys it actually saw when the shape is unrecognised', () => {
    const result = curManifestDataKeys({ assemblyId: 'abc', someNewFieldName: [{ key: 'x' }] });
    expect(result).toHaveProperty('error');
    const { error } = result as { error: string };
    expect(error).toContain('someNewFieldName');
    expect(error).toContain('assemblyId');
    expect(error).toContain('dataFiles');
  });

  it('rejects a list whose entries it cannot read, rather than silently dropping them', () => {
    // Half-readable is the dangerous case: returning only the entries that
    // parsed would ingest a partial month and look complete.
    expect(curManifestDataKeys({ dataFiles: [{ key: 'a.csv.gz' }, { unexpected: 'b.csv.gz' }] }))
      .toHaveProperty('error');
  });

  it('rejects a non-object manifest', () => {
    expect(curManifestDataKeys(null)).toHaveProperty('error');
    expect(curManifestDataKeys('not json')).toHaveProperty('error');
  });
});

/**
 * The durable CUR run is the path that actually matters, and it was calling
 * fetchCurManifest with the WRONG FIELD NAMES behind an `as never` cast:
 *
 *     fetchCurManifest(creds, { bucket, region, prefix, reportName } as never)
 *
 * CurConnectionConfig declares cur_s3_bucket / cur_s3_prefix /
 * cur_report_name / cur_s3_region. `as never` does not loosen a type, it
 * removes the check — never is assignable to everything — so all four fields
 * arrived undefined and the manifest was fetched from
 * s3://undefined/undefined/undefined/. Nothing caught it because nothing
 * tested the wiring, only the pure functions either side of it.
 */
describe('the durable CUR run is wired to the config shape it declares', () => {
  const COLLECTION_RUNS = readFileSync('src/routes/collectionRuns.ts', 'utf8');

  /** Comment lines stripped, so prose describing the old bug cannot satisfy — or trip — these. */
  const code = COLLECTION_RUNS.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');

  const call = (() => {
    const start = code.indexOf('fetchCurManifest(');
    return start === -1 ? '' : code.slice(start, code.indexOf('});', start) + 3);
  })();

  it('finds the call at all', () => {
    expect(call.length).toBeGreaterThan(0);
  });

  it('passes every field CurConnectionConfig declares, as KEYS', () => {
    // Matching on the bare name would be a tautology: the buggy version read
    // `{ bucket: cfg[0].cur_s3_bucket }`, which contains "cur_s3_bucket" as a
    // VALUE while the key is wrong. Requiring the trailing colon is what
    // distinguishes the property name from the property it was read out of —
    // found by tamper-testing this guard rather than by reading it.
    for (const field of ['cur_s3_bucket', 'cur_s3_region', 'cur_s3_prefix', 'cur_report_name']) {
      expect(call, `${field} is not passed as a key in the fetchCurManifest call`)
        .toMatch(new RegExp(`${field}\\s*:`));
    }
  });

  it('does not cast the argument away', () => {
    // An `as never` here would re-disable the check that makes the assertion
    // above meaningful.
    expect(call).not.toContain('as never');
  });

  it('reads the normalized file list, not the raw v1 property', () => {
    // `manifest.manifest.reportKeys ?? []` is undefined on every CUR 2.0
    // manifest, so a readable billing period would report as "no data".
    expect(code).toContain('manifest.reportKeys');
    expect(code).not.toContain('manifest.manifest.reportKeys');
  });
});
