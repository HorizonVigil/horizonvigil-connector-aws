import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'Kinesis_20131202';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const KINESIS_RESOURCE_TYPES = ['kinesis_stream'] as const;

interface StreamDescriptionSummary {
  StreamName: string; StreamARN?: string; StreamStatus?: string; RetentionPeriodHours?: number;
  StreamModeDetails?: { StreamMode?: string }; OpenShardCount?: number; StreamCreationTimestamp?: number;
}

/**
 * ListStreams only returns bare names — same shape as DynamoDB's
 * ListTables, so this follows dynamodb.ts's pattern exactly: one list call,
 * then a capped fan-out of per-stream detail calls (30, matching this
 * codebase's ~50-subrequest-per-invocation budget with room for the list
 * call itself and headroom).
 */
export async function scanKinesis(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `kinesis.${ctx.region}.amazonaws.com`;
  const listResult = await callJsonApi(ctx.creds, { service: 'kinesis', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListStreams`, body: {} });
  if (!listResult.ok) {
    console.error(`Kinesis ListStreams failed in ${ctx.region} (continuing without it): ${listResult.errorMessage ?? listResult.errorCode ?? listResult.status}`);
    return [];
  }

  const streamNames = ((listResult.body as { StreamNames?: string[] }).StreamNames ?? []).slice(0, 30);
  const out: ScannedResource[] = [];

  const descriptions = await Promise.all(streamNames.map((name) =>
    callJsonApi(ctx.creds, { service: 'kinesis', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.DescribeStreamSummary`, body: { StreamName: name } }),
  ));

  for (let i = 0; i < streamNames.length; i++) {
    const desc = descriptions[i];
    const name = streamNames[i];
    if (!desc.ok) {
      console.error(`Kinesis DescribeStreamSummary(${name}) failed in ${ctx.region} (continuing without it): ${desc.errorMessage ?? desc.errorCode ?? desc.status}`);
      out.push({ resourceTypeKey: 'kinesis_stream', resourceId: name, region: ctx.region, resourceName: name });
      continue;
    }
    const summary = (desc.body as { StreamDescriptionSummary?: StreamDescriptionSummary }).StreamDescriptionSummary;
    out.push({
      resourceTypeKey: 'kinesis_stream', resourceId: summary?.StreamARN ?? name, region: ctx.region, resourceName: name,
      state: summary?.StreamStatus,
      metadata: {
        retentionPeriodHours: summary?.RetentionPeriodHours, streamMode: summary?.StreamModeDetails?.StreamMode,
        openShardCount: summary?.OpenShardCount, createdAt: summary?.StreamCreationTimestamp,
      },
    });
  }

  return out;
}
