import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CLOUDTRAIL_RESOURCE_TYPES = ['cloudtrail_trail'] as const;

interface Trail {
  Name: string; S3BucketName?: string; TrailARN?: string; IsMultiRegionTrail?: boolean;
  IsOrganizationTrail?: boolean; LogFileValidationEnabled?: boolean; HomeRegion?: string;
}

/**
 * DescribeTrails — JSON-RPC, same pattern as DynamoDB/ECS/KMS. A
 * multi-region trail's HomeRegion is where it was created, but
 * DescribeTrails returns every trail visible from any region by default —
 * only recording ones whose HomeRegion matches ctx.region avoids the same
 * multi-region trail being duplicated once per scan region.
 */
export async function scanCloudTrail(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `cloudtrail.${ctx.region}.amazonaws.com`;
  const result = await callJsonApi(ctx.creds, { service: 'cloudtrail', region: ctx.region, host: endpoint, target: 'CloudTrail_20131101.DescribeTrails', body: { includeShadowTrails: false } });
  if (!result.ok) {
    console.error(`CloudTrail DescribeTrails failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const trails = (result.body as { trailList?: Trail[] }).trailList ?? [];
  return trails
    .filter((t) => !t.HomeRegion || t.HomeRegion === ctx.region)
    .map((t) => ({
      resourceTypeKey: 'cloudtrail_trail', resourceId: t.TrailARN ?? t.Name, region: ctx.region, resourceName: t.Name,
      metadata: {
        s3BucketName: t.S3BucketName, isMultiRegionTrail: t.IsMultiRegionTrail,
        isOrganizationTrail: t.IsOrganizationTrail, logFileValidationEnabled: t.LogFileValidationEnabled,
      },
    }));
}
