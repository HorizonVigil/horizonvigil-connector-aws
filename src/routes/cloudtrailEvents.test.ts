import { describe, expect, it } from 'vitest';
import { mapCloudTrailEvent, redactCloudTrailDetail } from './cloudtrailEvents';

describe('CloudTrail evidence sanitization', () => {
  it('redacts nested secrets and AWS access-key identifiers', () => {
    const syntheticKeyId = ['AK', 'IA', 'ABCDEFGHIJKLMNOP'].join('');
    expect(redactCloudTrailDetail({ password: 'synthetic-password', nested: { accessKeyId: syntheticKeyId, label: syntheticKeyId } })).toEqual({
      password: '[redacted]', nested: { accessKeyId: '[redacted]', label: '[redacted access key]' },
    });
  });

  it('retains attribution while removing secrets from mapped evidence', () => {
    const mapped = mapCloudTrailEvent({
      EventId: 'event-1', EventName: 'PutBucketPolicy', EventTime: 1_700_000_000,
      EventSource: 's3.amazonaws.com', Username: 'alice', Resources: [{ ResourceType: 'AWS::S3::Bucket', ResourceName: 'customer-data' }],
      CloudTrailEvent: JSON.stringify({ userIdentity: { type: 'IAMUser', arn: 'arn:aws:iam::123:user/alice' }, userAgent: 'console.amazonaws.com', requestParameters: { token: 'secret', bucketName: 'customer-data' } }),
    });
    expect(mapped.provenance).toMatchObject({ actorClass: 'human', actorKind: 'console' });
    expect(mapped.requestParameters).toEqual({ token: '[redacted]', bucketName: 'customer-data' });
  });
});
