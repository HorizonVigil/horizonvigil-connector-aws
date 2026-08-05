import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems, field } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2010-03-31';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SNS_RESOURCE_TYPES = ['sns_topic', 'sns_subscription'] as const;

/**
 * SNS's ListTopics only ever returns a bare TopicArn per topic — no name,
 * no attributes, no tags — so the resource name here is just the ARN's
 * trailing segment. A fuller pass (subscription counts, delivery policy)
 * would need GetTopicAttributes per topic, an N+1 call this first pass
 * skips. ListSubscriptions, unlike ListTopics, is account-wide across every
 * topic in one call — no per-topic fan-out needed.
 */
export async function scanSns(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `sns.${ctx.region}.amazonaws.com`;
  const call = async (action: string): Promise<string> => {
    const result = await callQueryApi(ctx.creds, { service: 'sns', region: ctx.region, host: endpoint, action, version: VERSION });
    if (!result.ok) {
      console.error(`SNS ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return '';
    }
    return result.body as string;
  };

  const [topics, subscriptions] = await Promise.all([call('ListTopics'), call('ListSubscriptions')]);

  const out: ScannedResource[] = [];
  for (const t of extractListItems(extractSection(topics, 'Topics'), 'member')) {
    const arn = field(t, 'TopicArn');
    if (!arn) continue;
    out.push({ resourceTypeKey: 'sns_topic', resourceId: arn, region: ctx.region, resourceName: arn.split(':').pop(), metadata: { arn } });
  }
  for (const s of extractListItems(extractSection(subscriptions, 'Subscriptions'), 'member')) {
    const arn = field(s, 'SubscriptionArn');
    if (!arn) continue;
    out.push({
      resourceTypeKey: 'sns_subscription', resourceId: arn, region: ctx.region, resourceName: arn.split(':').pop(),
      metadata: { protocol: field(s, 'Protocol'), endpoint: field(s, 'Endpoint') },
      relationships: { topicArn: field(s, 'TopicArn') },
    });
  }
  return out;
}
