import { paginateQueryList, incompleteSink } from '../pagination';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2012-11-05';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SQS_RESOURCE_TYPES = ['sqs_queue'] as const;

/**
 * ListQueues, every page.
 *
 * ListQueues is paginated on `NextToken` (default cap 1,000 per page). Reading
 * only page one meant an account with more queues than a page silently reported
 * a subset, and finalize — which reads "a covering scanner did not return it" as
 * deletion — soft-deleted the rest.
 *
 * ListQueues returns a flat list of `<QueueUrl>` elements directly (no
 * per-queue name/attributes) — a fuller pass would need GetQueueAttributes per
 * queue, an N+1 call this pass still skips. The URL itself (unique, always
 * present) is used as resourceId rather than deriving an ARN, since the account
 * ID needed for a real ARN is not available in this call.
 */
export async function scanSqs(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `sqs.${ctx.region}.amazonaws.com`;

  const walk = await paginateQueryList(
    ctx.creds,
    { service: 'sqs', region: ctx.region, host: endpoint, action: 'ListQueues', version: VERSION },
    'ListQueuesResult',
    'QueueUrl',
    // An unfinished walk degrades this scanner's coverage, so an account whose
    // queue list was cut short is not read as having fewer queues than it has.
    { onIncomplete: incompleteSink(ctx.creds) },
  );

  return walk.items
    .map((url) => url.trim())
    .filter((url) => url !== '')
    .map((url) => ({
      resourceTypeKey: 'sqs_queue',
      resourceId: url,
      region: ctx.region,
      resourceName: url.split('/').pop(),
      metadata: { queueUrl: url, pages: walk.pages, walkComplete: walk.termination === 'complete' },
    }));
}
