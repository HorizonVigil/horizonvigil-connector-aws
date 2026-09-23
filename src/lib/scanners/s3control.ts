import { callQueryApi, createAwsClient, safeFetch } from '../awsApi';
import { extractListItems, extractSection, field } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const S3CONTROL_RESOURCE_TYPES = ['s3_batch_job', 's3_account_public_access_block'] as const;

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
  const headers = { 'x-amz-account-id': accountId };
  const [jobsRes, publicAccessRes] = await Promise.all([
    safeFetch(client, 'https://s3-control.us-east-1.amazonaws.com/v20180820/jobs', { method: 'GET', headers }),
    safeFetch(client, 'https://s3-control.us-east-1.amazonaws.com/v20180820/configuration/publicAccessBlock', { method: 'GET', headers }),
  ]);
  const jobsText = await jobsRes.text();
  const out: ScannedResource[] = [];
  if (!jobsRes.ok) {
    console.error(`S3 Control ListJobs failed (continuing without it): HTTP ${jobsRes.status} ${jobsText.slice(0, 200)}`);
  } else {
    for (const job of extractListItems(extractSection(jobsText, 'Jobs'), 'JobListDescriptor')) {
      const jobId = field(job, 'JobId');
      if (!jobId) continue;
      out.push({
        resourceTypeKey: 's3_batch_job', resourceId: jobId, region: 'us-east-1',
        state: field(job, 'Status') ?? undefined, metadata: { operation: field(job, 'Operation'), description: field(job, 'Description'), creationTime: field(job, 'CreationTime') },
      });
    }
  }

  const publicAccessText = await publicAccessRes.text();
  if (publicAccessRes.ok) {
    out.push(accountPublicAccessBlockResource(accountId, publicAccessText));
  } else if (publicAccessRes.status === 404 || /NoSuchPublicAccessBlockConfiguration/i.test(publicAccessText)) {
    // Absence is a real, unsafe configuration state, not missing evidence.
    out.push(accountPublicAccessBlockResource(accountId, '', false));
  } else {
    // Permission or transport failures remain missing evidence. Do not turn
    // them into a clean or failed posture verdict.
    console.error(`S3 Control GetPublicAccessBlock failed (continuing without it): HTTP ${publicAccessRes.status} ${publicAccessText.slice(0, 200)}`);
  }
  return out;
}
