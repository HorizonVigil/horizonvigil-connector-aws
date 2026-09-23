import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * CloudTrail scanner contract tests.
 *
 * callJsonApi is mocked at the awsApi boundary (same lazy-closure pattern the
 * EC2 tests use for aws4fetch), so these assert the scanner's decisions --
 * which trails it keeps, what it calls, how it records missing evidence --
 * independently of the JSON-RPC wire encoding.
 */
const callJsonApiMock = vi.fn();
vi.mock('../awsApi', () => ({
  callJsonApi: (...args: unknown[]) => callJsonApiMock(...args),
}));

import { scanCloudTrail, summarizeEventSelectors, toIsoTimestamp, trailMetadata } from './cloudtrail';

type JsonReq = { target: string; body: Record<string, unknown> };

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ok = (body: unknown) => Promise.resolve({ ok: true, status: 200, body });
const denied = () => Promise.resolve({ ok: false, status: 400, body: null, errorCode: 'AccessDeniedException' });

const orgTrail = {
  Name: 'org-trail',
  TrailARN: 'arn:aws:cloudtrail:us-east-1:111122223333:trail/org-trail',
  HomeRegion: 'us-east-1',
  IsMultiRegionTrail: true,
  IsOrganizationTrail: true,
  LogFileValidationEnabled: true,
};

beforeEach(() => { callJsonApiMock.mockReset(); });

describe('CloudTrail status evidence', () => {
  const trail = { Name: 'org-trail', TrailARN: 'arn:aws:cloudtrail:us-east-1:111122223333:trail/org-trail', IsMultiRegionTrail: true, IsOrganizationTrail: true, LogFileValidationEnabled: true };

  it('keeps runtime logging status separate from configuration', () => {
    expect(trailMetadata(trail, { IsLogging: true, LatestDeliveryTime: '2026-09-23T00:00:00Z' }))
      .toMatchObject({ isMultiRegionTrail: true, logFileValidationEnabled: true, statusCollected: true, isLogging: true });
  });

  it('does not call a trail stopped when GetTrailStatus was unavailable', () => {
    expect(trailMetadata(trail, null)).toMatchObject({ statusCollected: false, isLogging: null });
  });

  it('normalizes the JSON protocol epoch-seconds timestamps to ISO strings', () => {
    expect(toIsoTimestamp(1790121600)).toBe('2026-09-23T00:00:00.000Z');
    expect(toIsoTimestamp('2026-09-23T00:00:00Z')).toBe('2026-09-23T00:00:00Z');
    expect(toIsoTimestamp(undefined)).toBeNull();
    expect(trailMetadata(trail, { IsLogging: true, LatestDeliveryTime: 1790121600 }).latestDeliveryTime)
      .toBe('2026-09-23T00:00:00.000Z');
  });

  it('records encryption and CloudWatch integration evidence', () => {
    const md = trailMetadata({ ...trail, KmsKeyId: 'arn:aws:kms:us-east-1:111122223333:key/abc', CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:111122223333:log-group:ct:*' }, null);
    expect(md).toMatchObject({ encryptedWithKms: true, trailAccountId: '111122223333' });
    expect(md.cloudWatchLogsLogGroupArn).toBe('arn:aws:logs:us-east-1:111122223333:log-group:ct:*');
    expect(trailMetadata(trail, null).encryptedWithKms).toBe(false);
  });
});

describe('CloudTrail event selector evidence', () => {
  it('treats missing selectors as NOT collected, never as "records nothing"', () => {
    expect(summarizeEventSelectors(null)).toMatchObject({ collected: false, managementEvents: null, managementReadWriteType: null });
  });

  it('reads basic selectors, defaulting IncludeManagementEvents to true', () => {
    expect(summarizeEventSelectors({ EventSelectors: [{ ReadWriteType: 'All' }] }))
      .toMatchObject({ collected: true, mode: 'basic', managementEvents: true, managementReadWriteType: 'All' });
  });

  it('flags a WriteOnly trail, which fails CIS 3.1', () => {
    expect(summarizeEventSelectors({ EventSelectors: [{ ReadWriteType: 'WriteOnly', IncludeManagementEvents: true }] }).managementReadWriteType)
      .toBe('WriteOnly');
  });

  it('flags a data-events-only trail as capturing no management events', () => {
    expect(summarizeEventSelectors({ EventSelectors: [{ IncludeManagementEvents: false, DataResources: [{ Type: 'AWS::S3::Object', Values: ['arn:aws:s3'] }] }] }))
      .toMatchObject({ managementEvents: false, dataEventsConfigured: true, managementReadWriteType: null });
  });

  it('combines a ReadOnly and a WriteOnly selector into All', () => {
    expect(summarizeEventSelectors({ EventSelectors: [{ ReadWriteType: 'ReadOnly' }, { ReadWriteType: 'WriteOnly' }] }).managementReadWriteType)
      .toBe('All');
  });

  it('reads advanced selectors, including excluded event sources', () => {
    const summary = summarizeEventSelectors({
      AdvancedEventSelectors: [{
        Name: 'mgmt',
        FieldSelectors: [
          { Field: 'eventCategory', Equals: ['Management'] },
          { Field: 'eventSource', NotEquals: ['kms.amazonaws.com'] },
        ],
      }],
    });
    expect(summary).toMatchObject({ mode: 'advanced', managementEvents: true, managementReadWriteType: 'All', excludedManagementEventSources: ['kms.amazonaws.com'] });
  });

  it('reads the advanced readOnly field selector', () => {
    const summary = summarizeEventSelectors({
      AdvancedEventSelectors: [{ FieldSelectors: [{ Field: 'eventCategory', Equals: ['Management'] }, { Field: 'readOnly', Equals: ['false'] }] }],
    });
    expect(summary.managementReadWriteType).toBe('WriteOnly');
  });
});

describe('scanCloudTrail', () => {
  const serve = (trails: unknown[], opts: { statusFails?: boolean; selectorsFail?: boolean } = {}) => {
    callJsonApiMock.mockImplementation((_creds: unknown, req: JsonReq) => {
      if (req.target.endsWith('.DescribeTrails')) return ok({ trailList: trails });
      if (req.target.endsWith('.GetTrailStatus')) return opts.statusFails ? denied() : ok({ IsLogging: true });
      if (req.target.endsWith('.GetEventSelectors')) return opts.selectorsFail ? denied() : ok({ EventSelectors: [{ ReadWriteType: 'All' }] });
      return denied();
    });
  };

  it('asks for shadow trails, so member accounts can see the organization trail', async () => {
    serve([orgTrail]);
    await scanCloudTrail({ creds, region: 'us-east-1' });
    const describeCall = callJsonApiMock.mock.calls.find((c: unknown[]) => (c[1] as JsonReq).target.endsWith('.DescribeTrails'));
    expect((describeCall?.[1] as JsonReq).body).toEqual({ includeShadowTrails: true });
  });

  it('records a multi-region trail once, in its home region only', async () => {
    serve([orgTrail]);
    expect(await scanCloudTrail({ creds, region: 'us-east-1' })).toHaveLength(1);

    serve([orgTrail]);
    expect(await scanCloudTrail({ creds, region: 'eu-west-1' })).toHaveLength(0);
  });

  it('records an organization trail seen from a member account, with its owning account', async () => {
    serve([orgTrail]);
    const [row] = await scanCloudTrail({ creds, region: 'us-east-1' });
    expect(row.metadata).toMatchObject({ isOrganizationTrail: true, trailAccountId: '111122223333' });
  });

  it('does not duplicate a trail DescribeTrails returned twice', async () => {
    serve([orgTrail, { ...orgTrail }]);
    expect(await scanCloudTrail({ creds, region: 'us-east-1' })).toHaveLength(1);
  });

  it('keeps the trail, with state unknown, when status and selectors are unavailable', async () => {
    serve([orgTrail], { statusFails: true, selectorsFail: true });
    const [row] = await scanCloudTrail({ creds, region: 'us-east-1' });
    expect(row.resourceId).toBe(orgTrail.TrailARN);
    expect(row.state).toBeUndefined();
    expect(row.metadata).toMatchObject({ statusCollected: false, isLogging: null, eventSelectors: { collected: false } });
  });

  it('records logging state and selectors when both calls succeed', async () => {
    serve([orgTrail]);
    const [row] = await scanCloudTrail({ creds, region: 'us-east-1' });
    expect(row.state).toBe('logging');
    expect(row.metadata).toMatchObject({ eventSelectors: { collected: true, managementReadWriteType: 'All' } });
  });

  it('returns nothing (and does not throw) when DescribeTrails fails', async () => {
    callJsonApiMock.mockImplementation(() => denied());
    expect(await scanCloudTrail({ creds, region: 'us-east-1' })).toEqual([]);
  });
});