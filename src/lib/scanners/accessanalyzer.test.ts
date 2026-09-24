import { beforeEach, describe, expect, it, vi } from 'vitest';

const fetchMock = vi.fn();
vi.mock('aws4fetch', () => ({
  AwsClient: class {
    fetch(url: string, init?: RequestInit) {
      return fetchMock(url, init);
    }
  },
}));

import { analyzerTypeFacts, scanAccessAnalyzer } from './accessanalyzer';
import { describeUnusedByType, scanAccessAnalyzerFindings } from './accessAnalyzerFindings';

type Failure = { action?: string };

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ctx = { creds, region: 'us-east-1' };
const json = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status }));

const ANALYZERS = [
  { arn: 'arn:aa:account', name: 'acct', type: 'ACCOUNT', status: 'ACTIVE' },
  { arn: 'arn:aa:org', name: 'org', type: 'ORGANIZATION', status: 'ACTIVE' },
  { arn: 'arn:aa:unused', name: 'unused', type: 'ACCOUNT_UNUSED_ACCESS', status: 'ACTIVE' },
  { arn: 'arn:aa:off', name: 'off', type: 'ACCOUNT', status: 'DISABLED' },
];

function serve(overrides: { detail?: boolean } = {}) {
  fetchMock.mockImplementation((url: string, init?: RequestInit) => {
    const body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : {};
    if (url.includes('/analyzer')) return json({ analyzers: ANALYZERS });
    if (url.endsWith('/finding')) {
      if (body.analyzerArn === 'arn:aa:account') {
        return json({ findings: [
          { id: 'f-public', resourceType: 'AWS::S3::Bucket', resource: 'arn:aws:s3:::open', status: 'ACTIVE', isPublic: true, principal: { AWS: '*' }, action: ['s3:GetObject'] },
          { id: 'f-cross', resourceType: 'AWS::IAM::Role', resource: 'arn:aws:iam::1:role/r', status: 'ACTIVE', isPublic: false, principal: { AWS: '444455556666' } },
        ] });
      }
      return json({ findings: [{ id: 'f-org', resourceType: 'AWS::KMS::Key', resource: 'arn:k', status: 'ACTIVE', isPublic: false }] });
    }
    if (url.endsWith('/findingv2')) {
      return json({ findings: [
        { id: 'u-role', resourceType: 'AWS::IAM::Role', resource: 'arn:aws:iam::1:role/stale', status: 'ACTIVE', findingType: 'UnusedIAMRole' },
        { id: 'u-key', resourceType: 'AWS::IAM::User', resource: 'arn:aws:iam::1:user/bob', status: 'ACTIVE', findingType: 'UnusedIAMUserAccessKey' },
      ] });
    }
    if (url.includes('/findingv2/')) {
      return overrides.detail
        ? json({ findingDetails: [{ unusedIamUserAccessKeyDetails: { accessKeyId: 'AKIA123', lastAccessed: '2026-01-01T00:00:00Z' } }] })
        : json({}, 403);
    }
    return json({}, 404);
  });
}

beforeEach(() => { fetchMock.mockReset(); });

describe('Access Analyzer analyzers', () => {
  it('classifies all six analyzer types', () => {
    expect(analyzerTypeFacts('ORGANIZATION_UNUSED_ACCESS')).toEqual({ scope: 'organization', kind: 'unused_access' });
    expect(analyzerTypeFacts('ACCOUNT')).toEqual({ scope: 'account', kind: 'external_access' });
    expect(analyzerTypeFacts('ACCOUNT_INTERNAL_ACCESS')).toEqual({ scope: 'account', kind: 'internal_access' });
  });

  it('follows nextToken and reports a failed list', async () => {
    fetchMock.mockImplementation((url: string) => (url.includes('nextToken=t2')
      ? json({ analyzers: [ANALYZERS[1]] })
      : json({ analyzers: [ANALYZERS[0]], nextToken: 't2' })));
    expect((await scanAccessAnalyzer(ctx)).map((r) => r.resourceId)).toEqual(['arn:aa:account', 'arn:aa:org']);

    const failures: Failure[] = [];
    fetchMock.mockImplementation(() => json({}, 403));
    await scanAccessAnalyzer({ creds: { ...creds, onCallFailure: (f: Failure) => failures.push(f) }, region: 'us-east-1' });
    expect(failures.some((f) => f.action === 'ListAnalyzers')).toBe(true);
  });
});

describe('Access Analyzer findings', () => {
  it('rates public exposure CRITICAL again (details come from v1 ListFindings)', async () => {
    serve();
    const out = await scanAccessAnalyzerFindings(ctx);
    expect(out.find((f) => f.awsFindingId === 'f-public')?.severity).toBe('critical');
    expect(out.find((f) => f.awsFindingId === 'f-cross')?.severity).toBe('high');
  });

  it('includes ORGANIZATION analyzers this account owns', async () => {
    serve();
    const out = await scanAccessAnalyzerFindings(ctx);
    expect(out.some((f) => f.awsFindingId === 'f-org')).toBe(true);
  });

  it('never asks for the non-existent type=UNUSED_ACCESS', async () => {
    serve();
    await scanAccessAnalyzerFindings(ctx);
    expect(fetchMock.mock.calls.some((c: unknown[]) => String(c[0]).includes('type=UNUSED_ACCESS'))).toBe(false);
  });

  it('collects unused-access findings even when details are unavailable', async () => {
    serve({ detail: false });
    const unused = (await scanAccessAnalyzerFindings(ctx)).filter((f) => f.findingSource === 'iam_access_analyzer_unused');
    expect(unused.map((f) => f.awsFindingId).sort()).toEqual(['u-key', 'u-role']);
    expect(unused.find((f) => f.awsFindingId === 'u-role')?.title).toBe('Unused IAM role: Role');
  });

  it('enriches unused-access findings from GetFindingV2 when available', async () => {
    serve({ detail: true });
    const key = (await scanAccessAnalyzerFindings(ctx)).find((f) => f.awsFindingId === 'u-key');
    expect(key?.description).toContain('AKIA123');
  });

  it('asks AWS for ACTIVE findings only', async () => {
    serve();
    await scanAccessAnalyzerFindings(ctx);
    const post = fetchMock.mock.calls.find((c: unknown[]) => String(c[0]).endsWith('/finding'));
    expect(JSON.parse(String((post?.[1] as RequestInit).body)).filter).toEqual({ status: { eq: ['ACTIVE'] } });
  });

  it('titles every unused-access finding type', () => {
    for (const t of ['UnusedIAMRole', 'UnusedIAMUserAccessKey', 'UnusedIAMUserPassword', 'UnusedPermission']) {
      expect(describeUnusedByType(t, 'X')).not.toBeNull();
    }
    expect(describeUnusedByType('SomethingNew', 'X')).toBeNull();
  });
});