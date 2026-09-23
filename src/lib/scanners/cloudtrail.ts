import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CLOUDTRAIL_RESOURCE_TYPES = ['cloudtrail_trail'] as const;

interface Trail {
  Name: string; S3BucketName?: string; TrailARN?: string; IsMultiRegionTrail?: boolean;
  IsOrganizationTrail?: boolean; LogFileValidationEnabled?: boolean; HomeRegion?: string;
}

interface TrailStatus { IsLogging?: boolean; LatestDeliveryTime?: string; LatestNotificationTime?: string }

export function trailMetadata(trail: Trail, status: TrailStatus | null) {
  return {
    s3BucketName: trail.S3BucketName,
    isMultiRegionTrail: trail.IsMultiRegionTrail,
    isOrganizationTrail: trail.IsOrganizationTrail,
    logFileValidationEnabled: trail.LogFileValidationEnabled,
    statusCollected: status !== null,
    isLogging: status?.IsLogging ?? null,
    latestDeliveryTime: status?.LatestDeliveryTime ?? null,
    latestNotificationTime: status?.LatestNotificationTime ?? null,
  };
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
  const localTrails = trails.filter((t) => !t.HomeRegion || t.HomeRegion === ctx.region);
  return Promise.all(localTrails.map(async (t) => {
    const statusResult = await callJsonApi(ctx.creds, {
      service: 'cloudtrail', region: ctx.region, host: endpoint,
      target: 'CloudTrail_20131101.GetTrailStatus', body: { Name: t.TrailARN ?? t.Name },
    });
    const status = statusResult.ok ? statusResult.body as TrailStatus : null;
    if (!statusResult.ok) console.error(`CloudTrail GetTrailStatus failed for ${t.Name} in ${ctx.region}; recording configuration with status unavailable.`);
    return {
      resourceTypeKey: 'cloudtrail_trail', resourceId: t.TrailARN ?? t.Name, region: ctx.region, resourceName: t.Name,
      state: status?.IsLogging === true ? 'logging' : status?.IsLogging === false ? 'stopped' : undefined,
      metadata: trailMetadata(t, status),
    };
  }));
}
