import { callQueryApi, createAwsClient, safeFetch } from '../awsApi';
import { extractSection, extractListItems, field } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const S3_RESOURCE_TYPES = ['s3_bucket', 's3_access_point', 's3_multi_region_access_point'] as const;

/**
 * S3's ListBuckets is REST-XML, not Query-protocol (no Action param, and
 * the response's root element IS the result — no "...Response" wrapper
 * around it like EC2/RDS/SNS/SQS have) — createAwsClient's raw signed
 * fetch is what awsApi.ts's docstring calls this out for. It's also a
 * genuinely global call (one endpoint lists every bucket regardless of
 * which region they live in), so this is a GLOBAL_SCANNERS entry, same as
 * IAM — discovery.ts must only ever schedule it once per account, not once
 * per scan region.
 *
 * ListBuckets doesn't say which region each bucket is in, so a follow-up
 * GetBucketLocation call is needed per bucket — capped at 45 buckets for
 * the same Cloudflare free-tier subrequest-budget reason as DynamoDB's
 * DescribeTable follow-ups. A bucket whose location lookup fails (e.g. no
 * s3:GetBucketLocation permission) still gets recorded, just with a
 * best-effort "unknown" region rather than being dropped entirely.
 */
export async function scanS3(ctx: ScannerContext): Promise<ScannedResource[]> {
  // ListBuckets is signed against us-east-1 regardless of ctx.region — same
  // "global service, fixed signing region" convention as IAM.
  const client = createAwsClient(ctx.creds, 's3', 'us-east-1');
  const listRes = await safeFetch(client, 'https://s3.amazonaws.com/', { method: 'GET' });
  const listText = await listRes.text();
  if (!listRes.ok) {
    console.error(`S3 ListBuckets failed (continuing without it): HTTP ${listRes.status} ${listText.slice(0, 200)}`);
    return [];
  }

  const bucketItems = extractListItems(extractSection(listText, 'Buckets'), 'Bucket').slice(0, 45);

  const regions = await Promise.all(bucketItems.map(async (b) => {
    const name = field(b, 'Name');
    if (!name) return null;
    try {
      const locRes = await safeFetch(client, `https://${name}.s3.amazonaws.com/?location`, { method: 'GET' });
      if (!locRes.ok) return 'unknown';
      const locText = await locRes.text();
      const match = /<LocationConstraint[^>]*>([^<]*)<\/LocationConstraint>/.exec(locText);
      // An empty (or self-closing) LocationConstraint means us-east-1 — S3's
      // long-standing quirk for buckets in the original/default region.
      return match && match[1] ? match[1] : 'us-east-1';
    } catch {
      return 'unknown';
    }
  }));

  const out: ScannedResource[] = [];
  for (let i = 0; i < bucketItems.length; i++) {
    const name = field(bucketItems[i], 'Name');
    if (!name) continue;
    out.push({
      resourceTypeKey: 's3_bucket', resourceId: name, region: regions[i], resourceName: name,
      metadata: { creationDate: field(bucketItems[i], 'CreationDate') },
    });
  }

  // S3 Control (access points, multi-region access points) is a distinct
  // account-scoped API needing the account ID as an x-amz-account-id
  // header — fetched here via STS GetCallerIdentity (same call
  // permissionChecks.ts already uses) since ScannerContext carries only
  // region/credentials, not the account ID.
  const stsResult = await callQueryApi(ctx.creds, { service: 'sts', region: 'us-east-1', host: 'sts.amazonaws.com', action: 'GetCallerIdentity', version: '2011-06-15' });
  const accountId = stsResult.ok ? field(stsResult.body as string, 'Account') : null;
  if (!accountId) {
    console.error('S3 Control access-point scan skipped: could not resolve account ID via STS GetCallerIdentity.');
    return out;
  }

  const s3ControlClient = createAwsClient(ctx.creds, 's3', 'us-east-1');
  const apRes = await safeFetch(s3ControlClient, 'https://s3-control.us-east-1.amazonaws.com/v20180820/accesspoint', {
    method: 'GET', headers: { 'x-amz-account-id': accountId },
  });
  const apText = await apRes.text();
  if (!apRes.ok) {
    console.error(`S3 ListAccessPoints failed (continuing without it): HTTP ${apRes.status} ${apText.slice(0, 200)}`);
  } else {
    for (const ap of extractListItems(extractSection(apText, 'AccessPointList'), 'AccessPoint')) {
      const arn = field(ap, 'AccessPointArn');
      if (!arn) continue;
      out.push({
        resourceTypeKey: 's3_access_point', resourceId: arn, region: 'us-east-1', resourceName: field(ap, 'Name') ?? undefined,
        metadata: { bucket: field(ap, 'Bucket'), alias: field(ap, 'Alias'), networkOrigin: field(ap, 'NetworkOrigin') },
      });
    }
  }

  // Multi-Region Access Points are account-wide (not per-region) but the
  // control-plane API is only reachable via the us-west-2 endpoint
  // regardless of where the account's buckets actually live.
  const mrapClient = createAwsClient(ctx.creds, 's3', 'us-west-2');
  const mrapRes = await safeFetch(mrapClient, 'https://s3-control.us-west-2.amazonaws.com/v20180820/mrap/instances', {
    method: 'GET', headers: { 'x-amz-account-id': accountId },
  });
  const mrapText = await mrapRes.text();
  if (!mrapRes.ok) {
    console.error(`S3 ListMultiRegionAccessPoints failed (continuing without it): HTTP ${mrapRes.status} ${mrapText.slice(0, 200)}`);
    return out;
  }
  for (const mrap of extractListItems(extractSection(mrapText, 'AccessPoints'), 'MultiRegionAccessPointReport')) {
    const name = field(mrap, 'Name');
    if (!name) continue;
    out.push({
      resourceTypeKey: 's3_multi_region_access_point', resourceId: name, region: null, resourceName: name,
      metadata: { alias: field(mrap, 'Alias'), status: field(mrap, 'Status'), createdAt: field(mrap, 'CreatedAt') },
    });
  }
  return out;
}
