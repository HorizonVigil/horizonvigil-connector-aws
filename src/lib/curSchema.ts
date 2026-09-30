/**
 * Cost & Usage Report schema handling for both report generations.
 *
 * AWS has two CUR products and they agree on almost nothing:
 *
 *                  legacy CUR (v1)                 Data Exports / CUR 2.0 (v2)
 *   created by     cur:PutReportDefinition         bcm-data-exports:CreateExport
 *   discovered by  cur:DescribeReportDefinitions   bcm-data-exports:ListExports
 *   columns        lineItem/ResourceId             line_item_resource_id
 *   partition      20260901-20261001               BILLING_PERIOD=2026-09
 *   manifest at    <report>/<period>/              <report>/metadata/<partition>/
 *
 * templates/horizonvigil-cur-setup.yaml creates a v2 export, because that is
 * where AWS is steering everyone. Customers who already had a report almost
 * certainly have v1. Both have to work, so nothing here asks the caller which
 * one they have.
 *
 * VERSION IS DETECTED, NOT STORED. The column set is read off the CSV header
 * and the layout is found by trying both manifest paths. That deliberately
 * avoids a `cur_version` column on cloud_connections, and it means a customer
 * who migrates their report from v1 to v2 keeps working without anyone
 * re-running discovery or backfilling a row.
 */

export type CurVersion = 'v1' | 'v2';

/** The six columns the ingester reads, in each generation's spelling. */
export interface CurColumnNames {
  resourceId: string;
  unblendedCost: string;
  usageStartDate: string;
  /** Human-readable service name. */
  serviceName: string;
  /** Service code, used when the readable name is absent. */
  productCode: string;
  region: string;
}

export const CUR_COLUMNS: Record<CurVersion, CurColumnNames> = {
  v1: {
    resourceId: 'lineItem/ResourceId',
    unblendedCost: 'lineItem/UnblendedCost',
    usageStartDate: 'lineItem/UsageStartDate',
    serviceName: 'product/ProductName',
    productCode: 'lineItem/ProductCode',
    region: 'product/region',
  },
  v2: {
    resourceId: 'line_item_resource_id',
    unblendedCost: 'line_item_unblended_cost',
    usageStartDate: 'line_item_usage_start_date',
    // v2 has no product/ProductName equivalent: `product` is a struct, and
    // the flat column carrying the service is product_servicecode.
    serviceName: 'product_servicecode',
    productCode: 'line_item_product_code',
    region: 'product_region_code',
  },
};

/** The three without which a row cannot become a cost fact. */
const REQUIRED: (keyof CurColumnNames)[] = ['resourceId', 'unblendedCost', 'usageStartDate'];

export interface ResolvedCurColumns {
  version: CurVersion;
  columns: CurColumnNames;
  /** Column name → position in this file's header. */
  index: Record<string, number>;
}

/**
 * Works out which generation a CSV header belongs to.
 *
 * Detection is by the REQUIRED columns only. An export that selected a narrow
 * column list (ours selects ten, not the ~100 a full dump gives) still
 * resolves, where matching on the full column set would not.
 *
 * Returns an error naming what was actually present rather than a boolean.
 * "This file is not a CUR" and "this CUR is missing resource IDs" need
 * different answers from the operator, and a caller that only knows the
 * lookup failed cannot tell them apart.
 */
export function resolveCurColumns(header: readonly string[]): ResolvedCurColumns | { error: string } {
  const index: Record<string, number> = {};
  for (let i = 0; i < header.length; i++) index[header[i]] = i;

  for (const version of ['v1', 'v2'] as const) {
    const columns = CUR_COLUMNS[version];
    if (REQUIRED.every((k) => index[columns[k]] !== undefined)) {
      return { version, columns, index };
    }
  }

  // Neither matched. Report per generation how close it came, because
  // "resource IDs are turned off" is by far the most common real cause and it
  // is fixed in the Billing console, not in this code.
  const detail = (['v1', 'v2'] as const)
    .map((v) => {
      const missing = REQUIRED.filter((k) => index[CUR_COLUMNS[v][k]] === undefined).map((k) => CUR_COLUMNS[v][k]);
      return `${v} missing ${missing.join(', ')}`;
    })
    .join('; ');

  return {
    error:
      `CUR file header matches neither report generation (${detail}). ` +
      `If the report exists but omits resource IDs, re-create it with "Include resource IDs" enabled — ` +
      `without them cost cannot be attributed to a resource.`,
  };
}

/**
 * The partition a billing period is written under.
 *
 * v1 names the range: 20260901-20261001.
 * v2 names the month: BILLING_PERIOD=2026-09.
 */
export function curPartition(version: CurVersion, now: Date): string {
  const y = now.getUTCFullYear();
  const m = now.getUTCMonth();
  if (version === 'v2') return `BILLING_PERIOD=${y}-${String(m + 1).padStart(2, '0')}`;

  const start = new Date(Date.UTC(y, m, 1));
  const end = new Date(Date.UTC(y, m + 1, 1));
  const fmt = (d: Date) =>
    `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, '0')}${String(d.getUTCDate()).padStart(2, '0')}`;
  return `${fmt(start)}-${fmt(end)}`;
}

/**
 * Where the manifest for a billing period lives.
 *
 * v1: <prefix>/<report>/<period>/<report>-Manifest.json
 * v2: <prefix>/<report>/metadata/<partition>/<report>-Manifest.json
 *
 * AWS's own delivery documentation is internally inconsistent on the v2 file
 * name -- the Metadata section gives `<export-name>-Manifest.json` while the
 * create-new summary gives a bare `Manifest.json`. Both are tried rather than
 * picking one and being wrong half the time; see curManifestCandidates.
 */
export function curManifestKey(
  version: CurVersion,
  prefix: string,
  reportName: string,
  partition: string,
  bareName = false,
): string {
  const base = `${prefix.replace(/^\/+|\/+$/g, '')}/${reportName}`;
  const file = bareName ? 'Manifest.json' : `${reportName}-Manifest.json`;
  return version === 'v2'
    ? `${base}/metadata/${partition}/${file}`
    : `${base}/${partition}/${file}`;
}

export interface CurManifestCandidate {
  version: CurVersion;
  partition: string;
  key: string;
}

/**
 * Every manifest location worth trying, most likely first.
 *
 * v2 leads because that is what this platform's own CloudFormation creates,
 * so a self-service customer hits it on the first request. A pre-existing v1
 * report costs one extra 404 per RUN -- the manifest is fetched once, not
 * once per file -- which is a fair price for not storing a version column
 * that could go stale against the customer's actual report.
 */
export function curManifestCandidates(prefix: string, reportName: string, now: Date): CurManifestCandidate[] {
  const out: CurManifestCandidate[] = [];
  for (const version of ['v2', 'v1'] as const) {
    const partition = curPartition(version, now);
    out.push({ version, partition, key: curManifestKey(version, prefix, reportName, partition) });
    if (version === 'v2') {
      out.push({ version, partition, key: curManifestKey(version, prefix, reportName, partition, true) });
    }
  }
  return out;
}

/**
 * The data file keys listed by a manifest.
 *
 * v1 publishes `reportKeys: string[]` and is documented. v2's manifest is
 * documented only in prose -- "a list of the export files and their file
 * path" -- with no field names given, so the shapes below are accepted and an
 * unrecognised one is reported WITH THE KEYS ACTUALLY SEEN.
 *
 * That last part is the point. Returning an empty list for a manifest we
 * could not read would present "we do not understand this file" as "this
 * billing period has no data", and the run would finalize as a clean zero.
 */
export function curManifestDataKeys(manifest: unknown, bucket?: string): { keys: string[] } | { error: string } {
  if (!manifest || typeof manifest !== 'object') {
    return { error: 'CUR manifest is not a JSON object.' };
  }
  const m = manifest as Record<string, unknown>;

  const candidates = ['reportKeys', 'dataFiles', 'data_files', 'files'];
  for (const field of candidates) {
    const raw = m[field];
    if (!Array.isArray(raw)) continue;
    const keys = raw
      .map((entry) => normalizeKey(entry, bucket))
      .filter((k): k is string => typeof k === 'string' && k.length > 0);
    // An empty array IS a real answer here: a billing period can genuinely
    // have no files yet. Only an unreadable shape is an error.
    if (keys.length === raw.length) return { keys };
  }

  return {
    error:
      `CUR manifest has no readable file list. Top-level keys present: ${Object.keys(m).join(', ') || '(none)'}. ` +
      `Expected one of: ${candidates.join(', ')}.`,
  };
}

/** A manifest entry is either a key string, an s3:// URL, or an object wrapping one. */
function normalizeKey(entry: unknown, bucket?: string): string | null {
  if (typeof entry === 'string') return stripS3Url(entry, bucket);
  if (entry && typeof entry === 'object') {
    for (const field of ['key', 'Key', 'path', 'Path', 's3Key', 'S3Key', 'location', 'Location']) {
      const value = (entry as Record<string, unknown>)[field];
      if (typeof value === 'string' && value) return stripS3Url(value, bucket);
    }
  }
  return null;
}

/** `s3://bucket/a/b.csv.gz` → `a/b.csv.gz`; anything else is already a key. */
function stripS3Url(value: string, bucket?: string): string {
  if (!value.startsWith('s3://')) return value.replace(/^\/+/, '');
  const withoutScheme = value.slice('s3://'.length);
  const slash = withoutScheme.indexOf('/');
  if (slash === -1) return '';
  const host = withoutScheme.slice(0, slash);
  const key = withoutScheme.slice(slash + 1);
  // If it names a different bucket, keep the key anyway -- the caller fetches
  // against the configured bucket and a mismatch is better surfaced as a 404
  // than silently dropped here.
  void bucket;
  void host;
  return key;
}
