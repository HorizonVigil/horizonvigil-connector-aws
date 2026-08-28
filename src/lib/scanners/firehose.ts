import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'Firehose_20150804';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const FIREHOSE_RESOURCE_TYPES = ['kinesis_firehose'] as const;

interface ListDeliveryStreamsResponse {
  DeliveryStreamNames?: string[];
  HasMoreDeliveryStreams?: boolean;
}

interface DestinationDescription {
  DestinationId?: string;
}

interface DeliveryStreamDescription {
  DeliveryStreamName?: string;
  DeliveryStreamARN?: string;
  DeliveryStreamStatus?: string;
  DeliveryStreamType?: string;
  VersionId?: string;
  CreateTimestamp?: number;
  LastUpdateTimestamp?: number;
  Destinations?: DestinationDescription[];
}

interface DescribeDeliveryStreamResponse {
  DeliveryStreamDescription?: DeliveryStreamDescription;
}

/**
 * Kinesis Data Firehose (now "Amazon Data Firehose") is regional like
 * ec2/rds, not a single global endpoint like iam/ce — called once per scan
 * region, registered as a REGIONAL_SCANNERS entry in discovery.ts, not
 * GLOBAL_SCANNERS. ListDeliveryStreams only returns bare stream names (plus
 * a HasMoreDeliveryStreams/ExclusiveStartDeliveryStreamName pagination
 * cursor, handled below via a do-while loop, same pattern as
 * budgets.ts's DescribeBudgets/NextToken loop), so a DescribeDeliveryStream
 * call per name fills in ARN/status/type/timestamps — same
 * list-then-describe-fan-out shape as dynamodb.ts's ListTables ->
 * DescribeTable. Capped at 45 DescribeDeliveryStream calls per region-step
 * for the same reason dynamodb.ts caps at 45 DescribeTable calls: staying
 * under Cloudflare's free-tier ~50 subrequest budget for one invocation. An
 * account with more delivery streams than that in a single region needs a
 * chunked/paginated version of this scanner, not built yet.
 *
 * UNVERIFIED against a real account's actual Firehose response shape until
 * this runs against a live connection and gets checked -- same
 * disclosed-uncertainty convention as inspector2.ts.
 */
export async function scanFirehose(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `firehose.${ctx.region}.amazonaws.com`;
  const out: ScannedResource[] = [];

  const names: string[] = [];
  let exclusiveStartName: string | undefined;

  do {
    const listResult = await callJsonApi(ctx.creds, {
      service: 'firehose', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListDeliveryStreams`,
      body: { Limit: 100, ...(exclusiveStartName ? { ExclusiveStartDeliveryStreamName: exclusiveStartName } : {}) },
    });
    if (!listResult.ok) {
      console.error(`Firehose ListDeliveryStreams failed in ${ctx.region} (continuing without it): ${listResult.errorMessage ?? listResult.errorCode ?? listResult.status}`);
      break;
    }
    const body = listResult.body as ListDeliveryStreamsResponse;
    const pageNames = body.DeliveryStreamNames ?? [];
    names.push(...pageNames);
    exclusiveStartName = body.HasMoreDeliveryStreams && pageNames.length > 0 ? pageNames[pageNames.length - 1] : undefined;
  } while (exclusiveStartName && names.length < 45);

  const capped = names.slice(0, 45);

  const descriptions = await Promise.all(capped.map((name) =>
    callJsonApi(ctx.creds, { service: 'firehose', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.DescribeDeliveryStream`, body: { DeliveryStreamName: name } }),
  ));

  for (let i = 0; i < capped.length; i++) {
    const name = capped[i];
    const desc = descriptions[i];
    if (!desc.ok) {
      console.error(`Firehose DescribeDeliveryStream(${name}) failed in ${ctx.region} (continuing without it): ${desc.errorMessage ?? desc.errorCode ?? desc.status}`);
      out.push({ resourceTypeKey: 'kinesis_firehose', resourceId: name, region: ctx.region, resourceName: name });
      continue;
    }
    const stream = (desc.body as DescribeDeliveryStreamResponse).DeliveryStreamDescription;
    out.push({
      resourceTypeKey: 'kinesis_firehose', resourceId: stream?.DeliveryStreamARN ?? name, region: ctx.region, resourceName: name,
      state: stream?.DeliveryStreamStatus,
      metadata: {
        deliveryStreamType: stream?.DeliveryStreamType,
        versionId: stream?.VersionId,
        createdAt: stream?.CreateTimestamp,
        lastUpdateTimestamp: stream?.LastUpdateTimestamp,
        destinationIds: (stream?.Destinations ?? []).map((d) => d.DestinationId).filter((id): id is string => !!id),
      },
    });
  }

  return out;
}
