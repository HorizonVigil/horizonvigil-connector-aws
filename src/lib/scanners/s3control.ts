import { callQueryApi, createAwsClient } from '../awsApi';
import { extractListItems, extractSection, field } from '../xmlList';
import { fetchText, reportListingFailure, snippet } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const S3CONTROL_RESOURCE_TYPES = ['s3_batch_job', 's3_account_public_access_block'] as const;

/**
 * S3 Control host. Fixed to us-east-1 for consistency with the precedent in
 * s3.ts. NOTE: S3 Batch Operations jobs are REGIONAL -- this endpoint only
 * lists jobs created in us-east-1. See the production notes that shipped
 * with this file before widening it (discovery.ts decides whether this
 * scanner runs once per account or once per region).
 */
const CONTROL_REGION = 'us-east-1';
const CONTROL_BASE = `https://s3-control.${CONTROL_REGION}.amazonaws.com/v20180820`;

const JOBS_PAGE_SIZE = 1000;
/** 20 x 1000 jobs. Beyond this the walk is reported as truncated, never silently cut. */
const MAX_JOB_PAGES = 20;

function xmlBool(xml: string, fieldName: string): boolean | null {
  const value = new RegExp(`<${fieldName}>(true|false)</${fieldName}>`, 'i').exec(xml)?.[1];
  return value ? value.toLowerCase() === 'true' : null;
}

export function accountPublicAccessBlockResource(accountId: string, xml: string, configured = true): ScannedResource {
  return {
    resourceTypeKey: 's3_account_public_access_block',
    resourceId: accountId,
    region: null,
    resourceName: 'S3 account public access block',
    metadata: {
      configured,
      blockPublicAcls: configured ? xmlBool(xml, 'BlockPublicAcls') : false,
      ignorePublicAcls: configured ? xmlBool(xml, 'IgnorePublicAcls') : false,
      blockPublicPolicy: configured ? xmlBool(xml, 'BlockPublicPolicy') : false,
      restrictPublicBuckets: configured ? xmlBool(xml, 'RestrictPublicBuckets') : false,
    },
  };
}

/**
 * ListJobs list items. The REST-XML list member is `<member>` on the wire
 * (the model gives JobListDescriptorList no locationName); older fixtures
 * and this file's earlier version used `<JobListDescriptor>`. Both are
 * accepted so a naming mismatch can never read as "zero jobs".
 */
export function jobItems(xml: string): string[] {
  const section = extractSection(xml, 'Jobs');
  const named = extractListItems(section, 'JobListDescriptor');
  return named.length > 0 ? named : extractListItems(section, 'member');
}

export function batchJobResource(job: string, region: string): ScannedResource | null {
  const jobId = field(job, 'JobId');
  if (!jobId) return null;
  const progress = extractSection(job, 'ProgressSummary') ?? '';
  const num = (xml: string, name: string) => {
    const v = field(xml, name);
    const n = v === null ? NaN : Number(v);
    return Number.isFinite(n) ? n : null;
  };
  return {
    resourceTypeKey: 's3_batch_job',
    resourceId: jobId,
    region,
    state: field(job, 'Status') ?? undefined,
    metadata: {
      operation: field(job, 'Operation'),
      description: field(job, 'Description'),
      creationTime: field(job, 'CreationTime'),
      terminationDate: field(job, 'TerminationDate'),
      priority: num(job, 'Priority'),
      totalNumberOfTasks: num(progress, 'TotalNumberOfTasks'),
      numberOfTasksSucceeded: num(progress, 'NumberOfTasksSucceeded'),
      numberOfTasksFailed: num(progress, 'NumberOfTasksFailed'),
    },
  };
}

/**
 * S3 Batch Operations jobs + the account-level S3 Block Public Access
 * configuration — same account-ID-via-STS + x-amz-account-id pattern s3.ts
 * uses for S3 Control access points. REST-XML, not JSON.
 *
 * Failure contract: every listing that did not complete is REPORTED through
 * onCallFailure before the scanner returns. Returning a shorter list without
 * reporting it would make finalize tombstone the missing jobs and the
 * account guardrail row.
 */
export async function scanS3Control(ctx: ScannerContext): Promise<ScannedResource[]> {
  const stsResult = await callQueryApi(ctx.creds, { service: 'sts', region: 'us-east-1', host: 'sts.amazonaws.com', action: 'GetCallerIdentity', version: '2011-06-15' });
  const accountId = stsResult.ok ? field(stsResult.body as string, 'Account') : null;
  if (!accountId) {
    console.error('S3 Control scan skipped: could not resolve account ID via STS GetCallerIdentity.');
    // Neither listing ran, so neither type may be read as "all deleted".
    reportListingFailure(ctx, { service: 's3control', action: 'ListJobs', region: CONTROL_REGION });
    reportListingFailure(ctx, { service: 's3control', action: 'GetPublicAccessBlock', region: CONTROL_REGION });
    return [];
  }

  const client = createAwsClient(ctx.creds, 's3', CONTROL_REGION);
  const headers = { 'x-amz-account-id': accountId };

  const [jobs, publicAccess] = await Promise.all([
    listAllJobs(ctx, client, headers),
    fetchText(client, `${CONTROL_BASE}/configuration/publicAccessBlock`, { method: 'GET', headers }),
  ]);

  const out: ScannedResource[] = [...jobs];

  if (publicAccess.ok) {
    out.push(accountPublicAccessBlockResource(accountId, publicAccess.text));
  } else if (publicAccess.status === 404 || /NoSuchPublicAccessBlockConfiguration/i.test(publicAccess.text)) {
    // Absence is a real, unsafe configuration state, not missing evidence.
    out.push(accountPublicAccessBlockResource(accountId, '', false));
  } else {
    // Permission or transport failures remain missing evidence. Do not turn
    // them into a clean or failed posture verdict -- and do not let the
    // missing row be read as a deleted one.
    console.error(`S3 Control GetPublicAccessBlock failed (continuing without it): HTTP ${publicAccess.status} ${publicAccess.error ?? snippet(publicAccess.text)}`);
    reportListingFailure(ctx, { service: 's3control', action: 'GetPublicAccessBlock', region: CONTROL_REGION, httpStatus: publicAccess.status });
  }
  return out;
}

async function listAllJobs(
  ctx: ScannerContext,
  client: ReturnType<typeof createAwsClient>,
  headers: Record<string, string>,
): Promise<ScannedResource[]> {
  const out: ScannedResource[] = [];
  const seenTokens = new Set<string>();
  let token: string | null = null;

  for (let page = 0; page < MAX_JOB_PAGES; page++) {
    const params = new URLSearchParams({ maxResults: String(JOBS_PAGE_SIZE) });
    if (token) params.set('nextToken', token);
    const res = await fetchText(client, `${CONTROL_BASE}/jobs?${params.toString()}`, { method: 'GET', headers });

    if (!res.ok) {
      console.error(`S3 Control ListJobs failed on page ${page + 1} (continuing with what was read): HTTP ${res.status} ${res.error ?? snippet(res.text)}`);
      reportListingFailure(ctx, { service: 's3control', action: 'ListJobs', region: CONTROL_REGION, httpStatus: res.status });
      return out;
    }

    for (const job of jobItems(res.text)) {
      const row = batchJobResource(job, CONTROL_REGION);
      if (row) out.push(row);
    }

    token = field(res.text, 'NextToken');
    if (!token) return out;
    if (seenTokens.has(token)) {
      console.error('S3 Control ListJobs returned a repeated NextToken; stopping and reporting truncation.');
      reportListingFailure(ctx, { service: 's3control', action: 'ListJobs', region: CONTROL_REGION, truncated: true });
      return out;
    }
    seenTokens.add(token);
  }

  console.error(`S3 Control ListJobs hit the ${MAX_JOB_PAGES}-page cap; reporting truncation.`);
  reportListingFailure(ctx, { service: 's3control', action: 'ListJobs', region: CONTROL_REGION, truncated: true });
  return out;
}