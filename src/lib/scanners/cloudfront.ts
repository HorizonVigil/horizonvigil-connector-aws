import { createAwsClient } from '../awsApi';
import { extractSection, extractListItems, field, boolField } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CLOUDFRONT_RESOURCE_TYPES = ['cloudfront_distribution'] as const;

/**
 * CloudFront is REST-XML, global — a GLOBAL_SCANNERS entry like
 * IAM/S3/Route53, signed against us-east-1 (CloudFront's control-plane API
 * only exists in that region regardless of which edge locations actually
 * serve traffic).
 */
export async function scanCloudFront(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'cloudfront', 'us-east-1');
  const res = await client.fetch('https://cloudfront.amazonaws.com/2020-05-31/distribution', { method: 'GET' });
  const text = await res.text();
  if (!res.ok) {
    console.error(`CloudFront ListDistributions failed (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const out: ScannedResource[] = [];
  for (const dist of extractListItems(extractSection(text, 'Items'), 'DistributionSummary')) {
    const id = field(dist, 'Id');
    if (!id) continue;
    out.push({
      resourceTypeKey: 'cloudfront_distribution', resourceId: id, region: null,
      resourceName: field(dist, 'DomainName') ?? undefined, state: field(dist, 'Status') ?? undefined,
      metadata: {
        arn: field(dist, 'ARN'), enabled: boolField(dist, 'Enabled'), comment: field(dist, 'Comment'),
        priceClass: field(dist, 'PriceClass'), lastModifiedTime: field(dist, 'LastModifiedTime'),
      },
    });
  }
  return out;
}
