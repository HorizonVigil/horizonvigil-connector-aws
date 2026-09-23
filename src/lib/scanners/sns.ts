import { callQueryApi } from '../awsApi';
import { paginateQueryApi, detectQueryTruncation, incompleteSink } from '../pagination';
import { extractSection, extractListItems, field } from '../xmlList';
import { accountIdFromArn, attr, parseAttributeEntries, summarizePolicy } from './policyEvidence';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2010-03-31';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SNS_RESOURCE_TYPES = ['sns_topic', 'sns_subscription'] as const;

/**
 * GetTopicAttributes follow-ups per region. Bounded for the Workers
 * subrequest budget; topics past the cap are recorded with
 * `attributesCollected: false` so posture reports them NOT_ASSESSED rather
 * than passing them.
 */
const MAX_TOPIC_ATTRIBUTE_LOOKUPS = 40;
const ATTRIBUTE_CONCURRENCY = 5;

/** Security evidence for one topic, from GetTopicAttributes. */
export function topicAttributeEvidence(attributes: Record<string, string> | null, topicArn: string) {
  if (attributes === null) {
    return {
      attributesCollected: false,
      kmsMasterKeyId: null,
      encrypted: null,
      displayName: null,
      fifoTopic: null,
      policy: summarizePolicy(null, null),
    };
  }
  const kmsMasterKeyId = attr(attributes, 'KmsMasterKeyId');
  return {
    attributesCollected: true,
    // Encryption at rest (FSBP SNS.1).
    kmsMasterKeyId,
    encrypted: kmsMasterKeyId !== null,
    displayName: attr(attributes, 'DisplayName'),
    fifoTopic: attr(attributes, 'FifoTopic') === 'true',
    // Who can publish/subscribe: anonymous or cross-account access.
    policy: summarizePolicy(attributes.Policy, accountIdFromArn(topicArn)),
  };
}

/**
 * SNS topics and subscriptions, every page, plus per-topic security evidence.
 *
 * Both ListTopics and ListSubscriptions are paginated on `NextToken`; an
 * unfinished walk is reported through the creds sink so finalize does not read
 * the unread remainder as deleted.
 *
 * PENDING SUBSCRIPTIONS. An HTTP/S or email subscription awaiting
 * confirmation reports the LITERAL string `PendingConfirmation` as its
 * SubscriptionArn. There is no provider-native id until it is confirmed, so it
 * is not persisted as a subscription (that would give every pending
 * subscription the same resource_id). The previous version recorded the
 * count on a SYNTHETIC `sns_topic` row -- a topic that does not exist, which
 * every topic posture check (encryption, public policy) then evaluated as if
 * it were real. The count now lives on the real topic each pending
 * subscription belongs to: `pendingConfirmationSubscriptionCount`.
 */
export async function scanSns(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `sns.${ctx.region}.amazonaws.com`;
  const opts = { service: 'sns', region: ctx.region, host: endpoint, version: VERSION };
  const onIncomplete = incompleteSink(ctx.creds);

  const [topics, subscriptions] = await Promise.all([
    paginateQueryApi<string, string>(
      ctx.creds, { ...opts, action: 'ListTopics' },
      (page) => extractListItems(extractSection(page, 'Topics'), 'member'),
      (page) => detectQueryTruncation(page),
      { onIncomplete },
    ),
    paginateQueryApi<string, string>(
      ctx.creds, { ...opts, action: 'ListSubscriptions' },
      (page) => extractListItems(extractSection(page, 'Subscriptions'), 'member'),
      (page) => detectQueryTruncation(page),
      { onIncomplete },
    ),
  ]);

  const topicArns = [...new Set(topics.items.map((t) => field(t, 'TopicArn')).filter((a): a is string => !!a))];

  // Pending confirmations, attributed to the topic they belong to.
  const pendingByTopic = new Map<string, number>();
  const confirmedSubscriptions: string[] = [];
  let unattributedPending = 0;
  for (const s of subscriptions.items) {
    const arn = field(s, 'SubscriptionArn');
    if (arn === 'PendingConfirmation') {
      const topicArn = field(s, 'TopicArn');
      if (topicArn) pendingByTopic.set(topicArn, (pendingByTopic.get(topicArn) ?? 0) + 1);
      else unattributedPending += 1;
      continue;
    }
    if (arn) confirmedSubscriptions.push(s);
  }
  if (unattributedPending > 0) {
    console.error(`SNS ${ctx.region}: ${unattributedPending} pending subscription(s) carried no TopicArn and could not be attributed.`);
  }

  // Per-topic security evidence, bounded.
  const lookups = topicArns.slice(0, MAX_TOPIC_ATTRIBUTE_LOOKUPS);
  if (topicArns.length > lookups.length) {
    console.error(`SNS ${ctx.region}: ${topicArns.length} topics; attributes read for the first ${lookups.length}, the rest are recorded as not collected.`);
  }
  const attributesByArn = new Map<string, Record<string, string> | null>();
  await mapWithConcurrency(lookups, ATTRIBUTE_CONCURRENCY, async (arn) => {
    const res = await callQueryApi(ctx.creds, { ...opts, action: 'GetTopicAttributes', params: { TopicArn: arn } });
    attributesByArn.set(arn, res.ok ? parseAttributeEntries(res.body as string, 'sns') : null);
  });

  const out: ScannedResource[] = [];
  for (const arn of topicArns) {
    out.push({
      resourceTypeKey: 'sns_topic', resourceId: arn, region: ctx.region,
      resourceName: arn.split(':').pop(),
      metadata: {
        arn,
        pages: topics.pages,
        walkComplete: topics.termination === 'complete',
        pendingConfirmationSubscriptionCount: pendingByTopic.get(arn) ?? 0,
        ...topicAttributeEvidence(attributesByArn.get(arn) ?? null, arn),
      },
    });
  }

  for (const s of confirmedSubscriptions) {
    const arn = field(s, 'SubscriptionArn') as string;
    out.push({
      resourceTypeKey: 'sns_subscription', resourceId: arn, region: ctx.region, resourceName: arn.split(':').pop(),
      metadata: {
        protocol: field(s, 'Protocol'),
        endpoint: field(s, 'Endpoint'),
        owner: field(s, 'Owner'),
        // A subscription owned by another account is a cross-account data flow.
        crossAccount: (() => {
          const owner = field(s, 'Owner');
          const topicAccount = accountIdFromArn(field(s, 'TopicArn'));
          return owner && topicAccount ? owner !== topicAccount : null;
        })(),
        pages: subscriptions.pages,
      },
      relationships: { topicArn: field(s, 'TopicArn') },
    });
  }

  return out;
}