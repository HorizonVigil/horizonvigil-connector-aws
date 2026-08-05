import { createAwsClient } from '../awsApi';
import { extractSection, extractListItems, field } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const S3_RESOURCE_TYPES = ['s3_bucket'] as const;

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
  const listRes = await client.fetch('https://s3.amazonaws.com/', { method: 'GET' });
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
      const locRes = await client.fetch(`https://${name}.s3.amazonaws.com/?location`, { method: 'GET' });
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
  return out;
}
