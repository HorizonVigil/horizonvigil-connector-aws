import { callJsonApi, createAwsClient, safeFetch, type AwsCreds } from './awsApi';
import {
  CUR_COLUMNS,
  curManifestCandidates,
  curManifestDataKeys,
  resolveCurColumns,
  type CurColumnNames,
  type CurVersion,
} from './curSchema';

/**
 * AWS Cost & Usage Report (CUR) ingestion — the only real AWS mechanism
 * that attributes cost to a specific resource ID (Cost Explorer, used by
 * cost/sync elsewhere in this Worker, only ever gives service+region
 * granularity). The customer creates the report themselves in AWS Billing
 * Console (with "Include resource IDs" checked); we discover it
 * programmatically via cur:DescribeReportDefinitions rather than asking
 * them to type in a bucket name, then read the CSV+GZIP files it drops in
 * their own S3 bucket.
 *
 * CUR files can be large — decompressing and parsing one in a single
 * Worker invocation isn't safe under Cloudflare's CPU budget, so this
 * follows the same stepped pattern as resource discovery: each call
 * re-fetches the (already-open, still-compressed) stream from S3, cheaply
 * fast-skips lines already ingested by a prior step, then does the actual
 * per-field CSV parsing only for the next batch. Re-fetching per step is
 * wasteful for very large reports, but simple and correct — a genuine
 * scaling limit worth documenting rather than a more fragile resumable
 * gzip parser.
 */
const BATCH_SIZE = 2000;
const CUR_HOST = 'cur.us-east-1.amazonaws.com'; // the CUR API is only available in us-east-1, regardless of the report's own S3 region
const DATA_EXPORTS_HOST = 'bcm-data-exports.us-east-1.amazonaws.com'; // likewise us-east-1 only
/**
 * The JSON target prefix for Data Exports. It is NOT the service name, nor
 * the abbreviation the endpoint uses -- it is spelled out in full, per the
 * service model's `targetPrefix`. Guessing `AWSBCMDataExports` from the
 * endpoint would produce an UnknownOperationException.
 */
const DATA_EXPORTS_TARGET = 'AWSBillingAndCostManagementDataExports';

export interface CurReportDefinition {
  ReportName: string;
  Format: string;
  Compression: string;
  AdditionalSchemaElements?: string[];
  S3Bucket: string;
  S3Prefix: string;
  S3Region: string;
  /** Which report generation this definition came from. */
  version: CurVersion;
}

/**
 * Data Exports (CUR 2.0) discovery.
 *
 * Returns null when the account simply has no v2 exports, and an error only
 * when the LOOKUP itself failed. Those are different facts: falling back to
 * legacy discovery is right for the first and wrong for the second, because a
 * denied bcm-data-exports:ListExports reported as "no report found" sends the
 * operator to the Billing console to create a report they already have.
 */
async function discoverCurExportV2(
  creds: AwsCreds,
): Promise<{ report: CurReportDefinition } | { error: string } | null> {
  const listed = await callJsonApi(creds, {
    service: 'bcm-data-exports', region: 'us-east-1', host: DATA_EXPORTS_HOST,
    target: `${DATA_EXPORTS_TARGET}.ListExports`,
    body: { MaxResults: 100 },
  });
  if (!listed.ok) {
    return { error: listed.errorMessage ?? listed.errorCode ?? 'bcm-data-exports:ListExports failed.' };
  }

  const exports = (listed.body as { Exports?: { ExportArn?: string; ExportName?: string }[] }).Exports ?? [];
  if (exports.length === 0) return null;

  // Prefer our own export when it is present, so an account that also has
  // unrelated exports (a FOCUS export, someone's ad-hoc query) still resolves
  // to the one this platform created and knows the shape of.
  const ordered = [...exports].sort((a, b) =>
    Number((b.ExportName ?? '').startsWith('horizonvigil')) - Number((a.ExportName ?? '').startsWith('horizonvigil')));

  const rejected: string[] = [];
  for (const summary of ordered) {
    if (!summary.ExportArn) continue;
    const got = await callJsonApi(creds, {
      service: 'bcm-data-exports', region: 'us-east-1', host: DATA_EXPORTS_HOST,
      target: `${DATA_EXPORTS_TARGET}.GetExport`,
      body: { ExportArn: summary.ExportArn },
    });
    if (!got.ok) continue;

    const exp = (got.body as { Export?: DataExport }).Export;
    const s3 = exp?.DestinationConfigurations?.S3Destination;
    const table = exp?.DataQuery?.TableConfigurations?.COST_AND_USAGE_REPORT;
    const name = exp?.Name ?? summary.ExportName ?? '';
    if (!exp || !s3?.S3Bucket) continue;

    // Parquet is a real export that this connector genuinely cannot read: the
    // ingester streams gzip and parses CSV. Naming that explicitly beats
    // letting it through to fail later as a corrupt-looking CSV.
    const format = s3.S3OutputConfigurations?.Format ?? '';
    if (format && format !== 'TEXT_OR_CSV') {
      rejected.push(`${name} is ${format}, and only TEXT_OR_CSV can be read`);
      continue;
    }
    if (table?.INCLUDE_RESOURCES === 'FALSE') {
      rejected.push(`${name} does not include resource IDs`);
      continue;
    }

    return {
      report: {
        ReportName: name,
        Format: format || 'TEXT_OR_CSV',
        Compression: s3.S3OutputConfigurations?.Compression ?? 'GZIP',
        S3Bucket: s3.S3Bucket,
        S3Prefix: s3.S3Prefix ?? '',
        S3Region: s3.S3Region ?? 'us-east-1',
        version: 'v2',
      },
    };
  }

  if (rejected.length > 0) {
    return {
      error:
        `Found ${rejected.length} Cost & Usage Report export(s), but none can be used: ${rejected.join('; ')}. ` +
        `Re-create the export with CSV output and resource IDs enabled, or deploy horizonvigil-cur-setup.yaml, which does both.`,
    };
  }
  return null;
}

interface DataExport {
  Name?: string;
  DataQuery?: { TableConfigurations?: { COST_AND_USAGE_REPORT?: { INCLUDE_RESOURCES?: string } } };
  DestinationConfigurations?: {
    S3Destination?: {
      S3Bucket?: string;
      S3Prefix?: string;
      S3Region?: string;
      S3OutputConfigurations?: { Format?: string; Compression?: string };
    };
  };
}

/** Legacy CUR discovery. */
async function discoverCurReportV1(creds: AwsCreds): Promise<{ report: CurReportDefinition } | { error: string } | null> {
  const result = await callJsonApi(creds, {
    service: 'cur', region: 'us-east-1', host: CUR_HOST,
    target: 'AWSOrigamiServiceGatewayService.DescribeReportDefinitions',
    body: {},
  });
  if (!result.ok) return { error: result.errorMessage ?? result.errorCode ?? 'DescribeReportDefinitions failed — check the connection has cur:DescribeReportDefinitions permission.' };

  const body = result.body as { ReportDefinitions?: Omit<CurReportDefinition, 'version'>[] };
  const defs = body.ReportDefinitions ?? [];
  const withResourceIds = defs.filter((d) => d.AdditionalSchemaElements?.includes('RESOURCES'));
  const eligible = withResourceIds.find((d) => d.Compression === 'GZIP') ?? withResourceIds[0];

  if (!eligible) {
    return defs.length > 0
      ? { error: 'Found a Cost & Usage Report, but it does not include resource IDs. In AWS Billing Console → Cost & Usage Reports, edit it (or create a new one) with "Include resource IDs" checked.' }
      : null;
  }
  return { report: { ...eligible, version: 'v1' } };
}

/**
 * Finds the account's report, newest generation first.
 *
 * A lookup failure on either path is carried into the final message rather
 * than collapsed into "no report found" — the most damaging outcome here is
 * telling a customer who HAS a report, and merely denied us permission to
 * list it, to go and create another one.
 */
export async function discoverCurReport(creds: AwsCreds): Promise<{ report: CurReportDefinition } | { error: string }> {
  const problems: string[] = [];

  const v2 = await discoverCurExportV2(creds);
  if (v2 && 'report' in v2) return v2;
  if (v2 && 'error' in v2) problems.push(v2.error);

  const v1 = await discoverCurReportV1(creds);
  if (v1 && 'report' in v1) return v1;
  if (v1 && 'error' in v1) problems.push(v1.error);

  if (problems.length > 0) return { error: problems.join(' ') };
  return {
    error:
      'No Cost & Usage Report found for this account. Deploy templates/horizonvigil-cur-setup.yaml in your management account (us-east-1) to create one, ' +
      'or create it manually in AWS Billing Console with resource IDs included.',
  };
}

async function s3Get(creds: AwsCreds, bucket: string, region: string, key: string): Promise<Response> {
  const client = createAwsClient(creds, 's3', region);
  const encodedKey = key.split('/').map(encodeURIComponent).join('/');
  // bufferBody: false -- this streams a potentially large gzip CUR file via
  // res.body (see parseCurBatch below); buffering it entirely into memory
  // first would defeat the point. A mid-stream failure is instead caught at
  // the point parseCurBatch actually reads the stream.
  return safeFetch(client, `https://${bucket}.s3.${region}.amazonaws.com/${encodedKey}`, undefined, { bufferBody: false });
}

/**
 * Every field is optional because the two generations publish different
 * manifests and only v1's is documented field-by-field. Read the file list
 * through curManifestDataKeys rather than off `reportKeys` directly — on a v2
 * manifest that property does not exist, and `undefined` iterated as an empty
 * list is how a readable month becomes a silent zero.
 */
export interface CurManifest {
  assemblyId?: string;
  bucket?: string;
  reportKeys?: string[];
  dataFiles?: unknown[];
  columns?: { category?: string; name?: string }[];
}

export interface CurConnectionConfig {
  cur_s3_bucket: string;
  cur_s3_prefix: string;
  cur_report_name: string;
  cur_s3_region: string;
}

export interface CurManifestResult {
  manifest: CurManifest;
  billingPeriod: string;
  version: CurVersion;
  /** Data file keys, normalized across both manifest shapes. */
  reportKeys: string[];
}

/**
 * Fetches the current billing period's manifest, trying each known layout.
 *
 * A 404 on one candidate is not an error — it is how "this account uses the
 * other generation" looks from here. Only exhausting every candidate is.
 * Any NON-404 (403 especially) stops the walk immediately and is reported:
 * a denied read must never be reported as "no data yet", which is the exact
 * substitution that turns a permissions problem into a silent empty month.
 */
export async function fetchCurManifest(
  creds: AwsCreds,
  config: CurConnectionConfig,
  now: Date = new Date(),
): Promise<CurManifestResult | { error: string }> {
  const candidates = curManifestCandidates(config.cur_s3_prefix, config.cur_report_name, now);
  const tried: string[] = [];

  for (const candidate of candidates) {
    const res = await s3Get(creds, config.cur_s3_bucket, config.cur_s3_region, candidate.key);

    if (res.status === 404) { tried.push(candidate.key); continue; }
    if (!res.ok) {
      return {
        error: res.status === 403
          ? `Access denied reading the CUR manifest (s3://${config.cur_s3_bucket}/${candidate.key}). The scan role needs s3:GetObject on this bucket — redeploy templates/horizonvigil-scan-role-stackset.yaml, setting AdditionalCurBucketName if the report lives outside the bucket HorizonVigil creates.`
          : `Failed to fetch CUR manifest (HTTP ${res.status}).`,
      };
    }

    const manifest = (await res.json()) as CurManifest;
    const keys = curManifestDataKeys(manifest, config.cur_s3_bucket);
    if ('error' in keys) return keys;

    return { manifest, billingPeriod: candidate.partition, version: candidate.version, reportKeys: keys.keys };
  }

  return {
    error:
      `No CUR manifest found yet for the current billing period. AWS publishes the first delivery up to 24 hours after the report is created, ` +
      `then refreshes it at least daily. Looked in: ${tried.map((k) => `s3://${config.cur_s3_bucket}/${k}`).join(', ')}.`,
  };
}

function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; } else inQuotes = false;
      } else cur += ch;
    } else if (ch === '"') inQuotes = true;
    else if (ch === ',') { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

/**
 * Splits complete CSV records while preserving quoted newlines. CUR is CSV,
 * not line-oriented text: a valid quoted field may contain a newline.
 */
function csvRecordSplitter(): TransformStream<string, string> {
  let record = '';
  let inQuotes = false;
  // A quote at a chunk boundary might be a closing quote or the first half
  // of an escaped quote pair. Defer that decision until the next character.
  let pendingQuote = false;
  return new TransformStream<string, string>({
    transform(chunk, controller) {
      for (const ch of chunk) {
        if (pendingQuote) {
          pendingQuote = false;
          if (ch === '"') {
            // Escaped quote inside a quoted field. The first quote was
            // appended in the preceding iteration; retain this one too.
            record += ch;
            continue;
          }
          inQuotes = false;
        }

        record += ch;
        if (ch === '"') {
          if (inQuotes) pendingQuote = true;
          else inQuotes = true;
        } else if (ch === '\n' && !inQuotes) {
          controller.enqueue(record.slice(0, -1).replace(/\r$/, ''));
          record = '';
        }
      }
    },
    flush(controller) {
      // At EOF a pending quote is necessarily a normal closing quote.
      pendingQuote = false;
      inQuotes = false;
      if (record) controller.enqueue(record.replace(/\r$/, ''));
    },
  });
}

/** The bare resource id (matches how the discovery scanners store cloud_resources.resource_id) from a CUR ResourceId, which is usually a full ARN like arn:aws:ec2:region:account:instance/i-0abc. */
function bareResourceId(raw: string): string {
  const parts = raw.split(/[/:]/);
  return parts[parts.length - 1] || raw;
}

export interface CurBatchResult {
  rowsProcessed: number; // cursor to pass as skipRows next call
  rowsIngestedThisBatch: number;
  done: boolean;
  costRows: { resource_id: string; service: string; region: string | null; usage_date: string; unblended_cost: number }[];
}

export async function parseCurBatch(creds: AwsCreds, bucket: string, region: string, reportKey: string, skipRows: number): Promise<CurBatchResult | { error: string }> {
  const res = await s3Get(creds, bucket, region, reportKey);
  if (!res.ok || !res.body) return { error: `Failed to fetch CUR data file (HTTP ${res.status}).` };

  const byteStream = reportKey.endsWith('.gz') ? res.body.pipeThrough(new DecompressionStream('gzip')) : res.body;
  const lineStream = byteStream.pipeThrough(new TextDecoderStream()).pipeThrough(csvRecordSplitter());
  const reader = lineStream.getReader();

  let header: string[] | null = null;
  let colIndex: Record<string, number> = {};
  // Replaced wholesale once the header resolves; the v1 spelling is only a
  // placeholder so the binding is definitely assigned. No data row is read
  // before the header sets it.
  let columns: CurColumnNames = CUR_COLUMNS.v1;
  let dataLineIndex = -1;
  let readThisBatch = 0;
  const costRows: CurBatchResult['costRows'] = [];

  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      await reader.cancel().catch(() => {});
      return { rowsProcessed: skipRows + readThisBatch, rowsIngestedThisBatch: costRows.length, done: true, costRows };
    }
      if (header === null) {
        header = parseCsvLine(value);
        // Which CUR generation this file is comes from its own header, not
        // from anything stored on the connection: a customer who migrates
        // from legacy CUR to Data Exports keeps working with no re-discovery
        // and no row to backfill.
        const resolved = resolveCurColumns(header);
        if ('error' in resolved) {
          await reader.cancel().catch(() => {});
          return { error: resolved.error };
        }
        columns = resolved.columns;
        colIndex = resolved.index;
        continue;
      }
      dataLineIndex++;
      if (dataLineIndex < skipRows) continue; // cheap skip — no field parsing for rows a prior step already ingested
      // Count every CSV record, including blank records, so the persisted
      // cursor always points after exactly the records this step consumed.
      readThisBatch++;
      if (!value.trim()) continue;

    const fields = parseCsvLine(value);
    const at = (name: string) => (colIndex[name] === undefined ? undefined : fields[colIndex[name]]);
    const resourceIdRaw = at(columns.resourceId);
    const cost = Number(at(columns.unblendedCost) ?? 0);
    const usageDate = (at(columns.usageStartDate) ?? '').slice(0, 10);
    const service = at(columns.serviceName) || at(columns.productCode) || 'unknown';
    const rowRegion = at(columns.region) || null;

      if (resourceIdRaw && usageDate && cost) {
      costRows.push({ resource_id: bareResourceId(resourceIdRaw), service, region: rowRegion, usage_date: usageDate, unblended_cost: cost });
    }
    if (readThisBatch >= BATCH_SIZE) {
      await reader.cancel().catch(() => {});
      return { rowsProcessed: skipRows + readThisBatch, rowsIngestedThisBatch: costRows.length, done: false, costRows };
    }
  }
}
