import { callQueryApi } from '../awsApi';
import { paginateQueryList, incompleteSink } from '../pagination';
import { accountIdFromArn, attr, parseAttributeEntries, summarizePolicy } from './policyEvidence';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2012-11-05';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SQS_RESOURCE_TYPES = ['sqs_queue'] as const;

/**
 * ListQueues page size. MUST be sent: without MaxResults, ListQueues returns
 * up to 1,000 queue URLs and NO NextToken, so an account with 1,001 queues
 * lost the rest with no truncation signal at all.
 */
const LIST_PAGE_SIZE = '1000';

/** GetQueueAttributes follow-ups per region (Workers subrequest budget). */
const MAX_QUEUE_ATTRIBUTE_LOOKUPS = 40;
const ATTRIBUTE_CONCURRENCY = 5;

/**
 * Attributes that change on their own (message counts). Never stored: they
 * would make every queue look modified on every scan.
 */
const VOLATILE_ATTRIBUTE_PREFIX = 'Approximate';

function intOrNull(v: string | null): number | null {
  if (v === null) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/** Security + configuration evidence for one queue, from GetQueueAttributes. */
export function queueAttributeEvidence(attributes: Record<string, string> | null) {
  if (attributes === null) {
    return {
      metadata: {
        attributesCollected: false,
        queueArn: null, fifoQueue: null, kmsMasterKeyId: null, sqsManagedSseEnabled: null, encrypted: null,
        visibilityTimeout: null, messageRetentionPeriod: null, delaySeconds: null, receiveMessageWaitTimeSeconds: null,
        maxReceiveCount: null, policy: summarizePolicy(null, null),
      },
      relationships: { deadLetterTargetArn: null as string | null },
    };
  }

  const queueArn = attr(attributes, 'QueueArn');
  const kmsMasterKeyId = attr(attributes, 'KmsMasterKeyId');
  const sqsManagedSseEnabled = attr(attributes, 'SqsManagedSseEnabled') === 'true';

  let deadLetterTargetArn: string | null = null;
  let maxReceiveCount: number | null = null;
  const redrive = attr(attributes, 'RedrivePolicy');
  if (redrive) {
    try {
      const parsed = JSON.parse(redrive) as { deadLetterTargetArn?: string; maxReceiveCount?: number | string };
      deadLetterTargetArn = parsed.deadLetterTargetArn ?? null;
      maxReceiveCount = intOrNull(parsed.maxReceiveCount === undefined ? null : String(parsed.maxReceiveCount));
    } catch {
      // Unreadable redrive policy: leave both null rather than guess.
    }
  }

  return {
    metadata: {
      attributesCollected: true,
      queueArn,
      fifoQueue: attr(attributes, 'FifoQueue') === 'true',
      // Encryption at rest (FSBP SQS.1): either a KMS key or SQS-managed SSE.
      kmsMasterKeyId,
      sqsManagedSseEnabled,
      encrypted: kmsMasterKeyId !== null || sqsManagedSseEnabled,
      visibilityTimeout: intOrNull(attr(attributes, 'VisibilityTimeout')),
      messageRetentionPeriod: intOrNull(attr(attributes, 'MessageRetentionPeriod')),
      delaySeconds: intOrNull(attr(attributes, 'DelaySeconds')),
      receiveMessageWaitTimeSeconds: intOrNull(attr(attributes, 'ReceiveMessageWaitTimeSeconds')),
      maxReceiveCount,
      // Anonymous or cross-account send/receive.
      policy: summarizePolicy(attributes.Policy, accountIdFromArn(queueArn)),
    },
    relationships: { deadLetterTargetArn },
  };
}

/**
 * ListQueues, every page, plus per-queue security evidence.
 *
 * The URL is resourceId (unique, always present, and what existing rows are
 * keyed on); the queue ARN is carried in metadata once attributes are read.
 * An unfinished walk degrades this scanner's coverage via the creds sink, so a
 * cut-short queue list is not read as fewer queues.
 */
export async function scanSqs(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `sqs.${ctx.region}.amazonaws.com`;

  const walk = await paginateQueryList(
    ctx.creds,
    { service: 'sqs', region: ctx.region, host: endpoint, action: 'ListQueues', version: VERSION, params: { MaxResults: LIST_PAGE_SIZE } },
    'ListQueuesResult',
    'QueueUrl',
    { onIncomplete: incompleteSink(ctx.creds) },
  );

  const urls = [...new Set(walk.items.map((url) => url.trim()).filter((url) => url !== ''))];

  const lookups = urls.slice(0, MAX_QUEUE_ATTRIBUTE_LOOKUPS);
  if (urls.length > lookups.length) {
    console.error(`SQS ${ctx.region}: ${urls.length} queues; attributes read for the first ${lookups.length}, the rest are recorded as not collected.`);
  }
  const attributesByUrl = new Map<string, Record<string, string> | null>();
  await mapWithConcurrency(lookups, ATTRIBUTE_CONCURRENCY, async (url) => {
    const res = await callQueryApi(ctx.creds, {
      service: 'sqs', region: ctx.region, host: endpoint, action: 'GetQueueAttributes', version: VERSION,
      params: { QueueUrl: url, 'AttributeName.1': 'All' },
    });
    if (!res.ok) {
      attributesByUrl.set(url, null);
      return;
    }
    const all = parseAttributeEntries(res.body as string, 'sqs');
    for (const key of Object.keys(all)) if (key.startsWith(VOLATILE_ATTRIBUTE_PREFIX)) delete all[key];
    attributesByUrl.set(url, all);
  });

  return urls.map((url) => {
    const evidence = queueAttributeEvidence(attributesByUrl.get(url) ?? null);
    return {
      resourceTypeKey: 'sqs_queue',
      resourceId: url,
      region: ctx.region,
      resourceName: url.split('/').pop(),
      metadata: { queueUrl: url, pages: walk.pages, walkComplete: walk.termination === 'complete', ...evidence.metadata },
      relationships: evidence.relationships,
    };
  });
}