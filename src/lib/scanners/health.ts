import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const HEALTH_RESOURCE_TYPES = ['health_event'] as const;

interface HealthEvent {
  arn: string; service?: string; eventTypeCode?: string; eventTypeCategory?: string; region?: string;
  availabilityZone?: string; startTime?: number; endTime?: number; statusCode?: string;
}
interface DescribeEventsResponse { events?: HealthEvent[] }

/**
 * AWS Health — global service (single endpoint in us-east-1 regardless of
 * ctx.region, same convention as IAM/Organizations). Target prefix/version
 * confirmed against AWS's API reference (element IDs on the DescribeEvents
 * page are prefixed "AWSHealth-", matching the health-2016-08-04 API
 * version in the doc URL). Requires a Business, Enterprise On-Ramp, or
 * Enterprise Support plan — a Basic/Developer-support account gets a
 * SubscriptionRequiredException on every call, an expected, common state.
 */
export async function scanHealth(ctx: ScannerContext): Promise<ScannedResource[]> {
  const result = await callJsonApi(ctx.creds, {
    service: 'health', region: 'us-east-1', host: 'health.us-east-1.amazonaws.com',
    target: 'AWSHealth_20160804.DescribeEvents', body: { filter: { eventStatusCodes: ['open', 'upcoming'] }, maxResults: 50 },
  });
  if (!result.ok) {
    console.error(`AWS Health DescribeEvents failed (continuing without it — likely requires Business/Enterprise support): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const events = (result.body as DescribeEventsResponse).events ?? [];
  return events.map((e) => ({
    resourceTypeKey: 'health_event', resourceId: e.arn, region: e.region ?? null, resourceName: e.eventTypeCode,
    state: e.statusCode, metadata: { service: e.service, eventTypeCategory: e.eventTypeCategory, availabilityZone: e.availabilityZone, startTime: e.startTime, endTime: e.endTime },
  }));
}
