import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2012-11-05';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SQS_RESOURCE_TYPES = ['sqs_queue'] as const;

/**
 * ListQueues returns a flat list of `<QueueUrl>` elements directly (no
 * per-queue name/attributes) — a fuller pass would need GetQueueAttributes
 * per queue, an N+1 call this first pass skips. The URL itself (unique,
 * always present) is used as resourceId rather than deriving an ARN, since
 * the account ID needed for a real ARN isn't available in this call.
 */
export async function scanSqs(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `sqs.${ctx.region}.amazonaws.com`;
  const result = await callQueryApi(ctx.creds, { service: 'sqs', region: ctx.region, host: endpoint, action: 'ListQueues', version: VERSION });
  if (!result.ok) {
    console.error(`SQS ListQueues failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const out: ScannedResource[] = [];
  for (const url of extractListItems(extractSection(result.body as string, 'ListQueuesResult'), 'QueueUrl')) {
    const trimmed = url.trim();
    if (!trimmed) continue;
    out.push({ resourceTypeKey: 'sqs_queue', resourceId: trimmed, region: ctx.region, resourceName: trimmed.split('/').pop(), metadata: { queueUrl: trimmed } });
  }
  return out;
}
