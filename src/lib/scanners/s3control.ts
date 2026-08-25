import { callQueryApi, createAwsClient, safeFetch } from '../awsApi';
import { extractListItems, extractSection, field } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const S3CONTROL_RESOURCE_TYPES = ['s3_batch_job'] as const;

/**
 * S3 Batch Operations jobs — same account-ID-via-STS + x-amz-account-id
 * pattern s3.ts already uses for S3 Control access points (see that file's
 * comment for the full rationale), same us-east-1-fixed host for
 * consistency with that established precedent. REST-XML, not JSON.
 */
export async function scanS3Control(ctx: ScannerContext): Promise<ScannedResource[]> {
  const stsResult = await callQueryApi(ctx.creds, { service: 'sts', region: 'us-east-1', host: 'sts.amazonaws.com', action: 'GetCallerIdentity', version: '2011-06-15' });
  const accountId = stsResult.ok ? field(stsResult.body as string, 'Account') : null;
  if (!accountId) {
    console.error('S3 Batch Operations scan skipped: could not resolve account ID via STS GetCallerIdentity.');
    return [];
  }

  const client = createAwsClient(ctx.creds, 's3', 'us-east-1');
  const res = await safeFetch(client, 'https://s3-control.us-east-1.amazonaws.com/v20180820/jobs', {
    method: 'GET', headers: { 'x-amz-account-id': accountId },
  });
  const text = await res.text();
  if (!res.ok) {
    console.error(`S3 Control ListJobs failed (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const out: ScannedResource[] = [];
  for (const job of extractListItems(extractSection(text, 'Jobs'), 'JobListDescriptor')) {
    const jobId = field(job, 'JobId');
    if (!jobId) continue;
    out.push({
      resourceTypeKey: 's3_batch_job', resourceId: jobId, region: 'us-east-1',
      state: field(job, 'Status') ?? undefined, metadata: { operation: field(job, 'Operation'), description: field(job, 'Description'), creationTime: field(job, 'CreationTime') },
    });
  }
  return out;
}
