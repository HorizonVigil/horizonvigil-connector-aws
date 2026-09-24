import { beforeEach, describe, expect, it, vi } from 'vitest';

const callQueryApiMock = vi.fn();
vi.mock('../awsApi', async (importOriginal: () => Promise<Record<string, unknown>>) => ({
  ...(await importOriginal()),
  callQueryApi: (...args: unknown[]) => callQueryApiMock(...args),
}));

import { scanSns } from './sns';
import { scanSqs } from './sqs';
import type { ScannedResource } from './types';

type Req = { action: string; params?: Record<string, string> };

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ctx = { creds, region: 'eu-west-1' };
const ok = (body: string) => Promise.resolve({ ok: true, status: 200, body });
const denied = () => Promise.resolve({ ok: false, status: 403, body: '', errorCode: 'AccessDenied' });

const TOPIC = 'arn:aws:sns:eu-west-1:111122223333:alerts';
const publicPolicy = JSON.stringify({ Statement: [{ Effect: 'Allow', Principal: '*', Action: 'sns:Publish' }] }).replace(/"/g, '&quot;');

function serve(handlers: Record<string, (req: Req) => Promise<unknown>>) {
  callQueryApiMock.mockImplementation((_c: unknown, req: Req) => {
    const h = handlers[req.action];
    return h ? h(req) : ok(`<${req.action}Response/>`);
  });
}

const ofType = (out: ScannedResource[], t: string) => out.filter((r) => r.resourceTypeKey === t);

beforeEach(() => { callQueryApiMock.mockReset(); });

describe('scanSns', () => {
  const topics = () => ok(`<ListTopicsResponse><ListTopicsResult><Topics><member><TopicArn>${TOPIC}</TopicArn></member></Topics></ListTopicsResult></ListTopicsResponse>`);
  const subs = () => ok(
    '<ListSubscriptionsResponse><ListSubscriptionsResult><Subscriptions>' +
    `<member><SubscriptionArn>PendingConfirmation</SubscriptionArn><TopicArn>${TOPIC}</TopicArn><Protocol>email</Protocol></member>` +
    `<member><SubscriptionArn>${TOPIC}:abc</SubscriptionArn><TopicArn>${TOPIC}</TopicArn><Protocol>sqs</Protocol><Owner>444455556666</Owner></member>` +
    '</Subscriptions></ListSubscriptionsResult></ListSubscriptionsResponse>');

  it('no longer creates a fake sns_topic row for pending confirmations', async () => {
    serve({ ListTopics: topics, ListSubscriptions: subs });
    const out = await scanSns(ctx);
    const topicRows = ofType(out, 'sns_topic');
    expect(topicRows.map((r) => r.resourceId)).toEqual([TOPIC]);
    expect(topicRows[0].metadata?.pendingConfirmationSubscriptionCount).toBe(1);
  });

  it('records topic encryption and a public topic policy', async () => {
    serve({
      ListTopics: topics, ListSubscriptions: subs,
      GetTopicAttributes: () => ok(`<GetTopicAttributesResponse><GetTopicAttributesResult><Attributes>` +
        `<entry><key>Policy</key><value>${publicPolicy}</value></entry>` +
        `</Attributes></GetTopicAttributesResult></GetTopicAttributesResponse>`),
    });
    const [topic] = ofType(await scanSns(ctx), 'sns_topic');
    expect(topic.metadata).toMatchObject({ attributesCollected: true, encrypted: false, policy: { allowsAnonymous: true } });
  });

  it('marks attributes NOT collected (never "unencrypted") when the lookup fails', async () => {
    serve({ ListTopics: topics, ListSubscriptions: subs, GetTopicAttributes: denied });
    const [topic] = ofType(await scanSns(ctx), 'sns_topic');
    expect(topic.metadata).toMatchObject({ attributesCollected: false, encrypted: null });
  });

  it('flags a cross-account subscription', async () => {
    serve({ ListTopics: topics, ListSubscriptions: subs });
    const [sub] = ofType(await scanSns(ctx), 'sns_subscription');
    expect(sub.metadata?.crossAccount).toBe(true);
  });
});

describe('scanSqs', () => {
  const URL = 'https://sqs.eu-west-1.amazonaws.com/111122223333/orders';
  const list = () => ok(`<ListQueuesResponse><ListQueuesResult><QueueUrl>${URL}</QueueUrl></ListQueuesResult></ListQueuesResponse>`);

  it('sends MaxResults, without which ListQueues silently stops at 1,000', async () => {
    serve({ ListQueues: list });
    await scanSqs(ctx);
    const req = callQueryApiMock.mock.calls.find((c: unknown[]) => (c[1] as Req).action === 'ListQueues')?.[1] as Req;
    expect(req.params?.MaxResults).toBe('1000');
  });

  it('records encryption, DLQ and policy evidence, and never the volatile message counts', async () => {
    serve({
      ListQueues: list,
      GetQueueAttributes: () => ok('<GetQueueAttributesResponse><GetQueueAttributesResult>' +
        '<Attribute><Name>QueueArn</Name><Value>arn:aws:sqs:eu-west-1:111122223333:orders</Value></Attribute>' +
        '<Attribute><Name>SqsManagedSseEnabled</Name><Value>true</Value></Attribute>' +
        '<Attribute><Name>ApproximateNumberOfMessages</Name><Value>42</Value></Attribute>' +
        '<Attribute><Name>RedrivePolicy</Name><Value>{&quot;deadLetterTargetArn&quot;:&quot;arn:aws:sqs:eu-west-1:111122223333:dlq&quot;,&quot;maxReceiveCount&quot;:5}</Value></Attribute>' +
        '</GetQueueAttributesResult></GetQueueAttributesResponse>'),
    });

    const [q] = await scanSqs(ctx);

    expect(q.resourceId).toBe(URL);
    expect(q.metadata).toMatchObject({ attributesCollected: true, encrypted: true, sqsManagedSseEnabled: true, maxReceiveCount: 5, policy: { present: false } });
    expect(q.relationships?.deadLetterTargetArn).toBe('arn:aws:sqs:eu-west-1:111122223333:dlq');
    expect(JSON.stringify(q.metadata).includes('42')).toBe(false);
  });

  it('keeps the queue, marked not collected, when attributes are denied', async () => {
    serve({ ListQueues: list, GetQueueAttributes: denied });
    const [q] = await scanSqs(ctx);
    expect(q.metadata).toMatchObject({ attributesCollected: false, encrypted: null });
  });
});