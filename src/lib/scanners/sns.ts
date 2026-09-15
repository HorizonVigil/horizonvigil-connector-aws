import { paginateQueryApi, detectQueryTruncation, incompleteSink } from '../pagination';
import { extractSection, extractListItems, field } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2010-03-31';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SNS_RESOURCE_TYPES = ['sns_topic', 'sns_subscription'] as const;

/**
 * SNS topics and subscriptions, every page.
 *
 * Both ListTopics and ListSubscriptions are paginated on `NextToken`. Reading
 * only page one meant a topic-heavy account silently reported a subset, and
 * finalize — which reads "a covering scanner did not return it" as deletion —
 * soft-deleted the rest.
 *
 * ListTopics returns only a bare TopicArn per topic (no name, no attributes, no
 * tags), so the resource name here is the ARN's trailing segment. A fuller pass
 * (subscription counts, delivery policy) would need GetTopicAttributes per
 * topic, an N+1 call this pass still skips. ListSubscriptions, unlike
 * ListTopics, is account-wide across every topic in one call.
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

  const out: ScannedResource[] = [];

  for (const t of topics.items) {
    const arn = field(t, 'TopicArn');
    if (!arn) continue;
    out.push({
      resourceTypeKey: 'sns_topic', resourceId: arn, region: ctx.region,
      resourceName: arn.split(':').pop(), metadata: { arn, pages: topics.pages, walkComplete: topics.termination === 'complete' },
    });
  }

  let unconfirmedSubscriptionCount = 0;
  for (const s of subscriptions.items) {
    const arn = field(s, 'SubscriptionArn');
    /**
     * An HTTP/S or email subscription awaiting confirmation reports the LITERAL
     * string `PendingConfirmation` as its SubscriptionArn rather than an ARN.
     * Persisting that would give every pending subscription on the account the
     * SAME resource_id — one identity shared by several resources, which is
     * exactly the condition inventory reconciliation reports as DUPLICATE_LOCAL
     * and which would make the graph attribute them to each other. There is no
     * provider-native id to fall back on (the real ARN does not exist until it
     * is confirmed), so they are skipped and counted instead of invented.
     */
    if (!arn || arn === 'PendingConfirmation') {
      if (arn === 'PendingConfirmation') unconfirmedSubscriptionCount += 1;
      continue;
    }
    out.push({
      resourceTypeKey: 'sns_subscription', resourceId: arn, region: ctx.region, resourceName: arn.split(':').pop(),
      metadata: { protocol: field(s, 'Protocol'), endpoint: field(s, 'Endpoint'), pages: subscriptions.pages },
      relationships: { topicArn: field(s, 'TopicArn') },
    });
  }

  if (unconfirmedSubscriptionCount > 0) {
    // Recorded rather than silently dropped: a subscription that never confirms
    // is absent from the inventory by design, and that has to be visible.
    out.push({
      resourceTypeKey: 'sns_topic', resourceId: `pending-confirmation-count:${ctx.region}`,
      region: ctx.region, resourceName: 'Pending SNS subscription confirmations',
      metadata: { unconfirmedSubscriptionCount, note: 'sentinel row: counts subscriptions AWS reports as PendingConfirmation' },
    });
  }

  return out;
}
