import { callJsonApi, createAwsClient, safeFetch, type AwsCreds } from './awsApi';

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

export interface CurReportDefinition {
  ReportName: string;
  Format: string;
  Compression: string;
  AdditionalSchemaElements?: string[];
  S3Bucket: string;
  S3Prefix: string;
  S3Region: string;
}

export async function discoverCurReport(creds: AwsCreds): Promise<{ report: CurReportDefinition } | { error: string }> {
  const result = await callJsonApi(creds, {
    service: 'cur', region: 'us-east-1', host: CUR_HOST,
    target: 'AWSOrigamiServiceGatewayService.DescribeReportDefinitions',
    body: {},
  });
  if (!result.ok) return { error: result.errorMessage ?? result.errorCode ?? 'DescribeReportDefinitions failed — check the connection has cur:DescribeReportDefinitions permission.' };

  const body = result.body as { ReportDefinitions?: CurReportDefinition[] };
  const defs = body.ReportDefinitions ?? [];
  const withResourceIds = defs.filter((d) => d.AdditionalSchemaElements?.includes('RESOURCES'));
  const eligible = withResourceIds.find((d) => d.Compression === 'GZIP') ?? withResourceIds[0];

  if (!eligible) {
    return {
      error: defs.length > 0
        ? 'Found a Cost & Usage Report, but it does not include resource IDs. In AWS Billing Console → Cost & Usage Reports, edit it (or create a new one) with "Include resource IDs" checked.'
        : 'No Cost & Usage Report found for this account. Create one in AWS Billing Console → Cost & Usage Reports, with "Include resource IDs" checked (CSV, GZIP compression recommended).',
    };
  }
  return { report: eligible };
}

function currentBillingPeriod(): string {
  const now = new Date();
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));
  const fmt = (d: Date) => `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, '0')}${String(d.getUTCDate()).padStart(2, '0')}`;
  return `${fmt(start)}-${fmt(end)}`;
}

async function s3Get(creds: AwsCreds, bucket: string, region: string, key: string): Promise<Response> {
  const client = createAwsClient(creds, 's3', region);
  const encodedKey = key.split('/').map(encodeURIComponent).join('/');
  return safeFetch(client, `https://${bucket}.s3.${region}.amazonaws.com/${encodedKey}`);
}

export interface CurManifest {
  assemblyId: string;
  bucket: string;
  reportKeys: string[];
  columns: { category: string; name: string }[];
}

export interface CurConnectionConfig {
  cur_s3_bucket: string;
  cur_s3_prefix: string;
  cur_report_name: string;
  cur_s3_region: string;
}

export async function fetchCurManifest(creds: AwsCreds, config: CurConnectionConfig): Promise<{ manifest: CurManifest; billingPeriod: string } | { error: string }> {
  const billingPeriod = currentBillingPeriod();
  const prefix = config.cur_s3_prefix.replace(/\/$/, '');
  const key = `${prefix}/${config.cur_report_name}/${billingPeriod}/${config.cur_report_name}-Manifest.json`;
  const res = await s3Get(creds, config.cur_s3_bucket, config.cur_s3_region, key);
  if (!res.ok) {
    return {
      error: res.status === 404
        ? `No manifest found yet for the current billing period (${billingPeriod}) — AWS typically publishes the first CUR data within 24 hours of month start, then refreshes it several times a day.`
        : `Failed to fetch CUR manifest (HTTP ${res.status}).`,
    };
  }
  const manifest = (await res.json()) as CurManifest;
  return { manifest, billingPeriod };
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

function lineSplitter(): TransformStream<string, string> {
  let buffer = '';
  return new TransformStream<string, string>({
    transform(chunk, controller) {
      buffer += chunk;
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';
      for (const line of lines) controller.enqueue(line);
    },
    flush(controller) {
      if (buffer) controller.enqueue(buffer);
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
  const lineStream = byteStream.pipeThrough(new TextDecoderStream()).pipeThrough(lineSplitter());
  const reader = lineStream.getReader();

  let header: string[] | null = null;
  let colIndex: Record<string, number> = {};
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
      colIndex = Object.fromEntries(header.map((h, i) => [h, i]));
      continue;
    }
    dataLineIndex++;
    if (dataLineIndex < skipRows) continue; // cheap skip — no field parsing for rows a prior step already ingested
    if (!value.trim()) continue;

    const fields = parseCsvLine(value);
    const resourceIdRaw = fields[colIndex['lineItem/ResourceId']];
    const cost = Number(fields[colIndex['lineItem/UnblendedCost']] ?? 0);
    const usageDate = (fields[colIndex['lineItem/UsageStartDate']] ?? '').slice(0, 10);
    const service = fields[colIndex['product/ProductName']] || fields[colIndex['lineItem/ProductCode']] || 'unknown';
    const rowRegion = fields[colIndex['product/region']] || null;

    readThisBatch++;
    if (resourceIdRaw && usageDate && cost) {
      costRows.push({ resource_id: bareResourceId(resourceIdRaw), service, region: rowRegion, usage_date: usageDate, unblended_cost: cost });
    }
    if (readThisBatch >= BATCH_SIZE) {
      await reader.cancel().catch(() => {});
      return { rowsProcessed: skipRows + readThisBatch, rowsIngestedThisBatch: costRows.length, done: false, costRows };
    }
  }
}
