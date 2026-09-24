import { describe, it, expect, vi, beforeEach } from 'vitest';

/**
 * End-to-end retry behaviour of the AWS call helpers.
 *
 * The policy maths is unit-tested in awsErrors.test.ts; what these assert is
 * that callQueryApi/callJsonApi actually APPLY it — that a throttled call is
 * genuinely re-issued rather than returned to the scanner as an empty body,
 * which is the exact step that used to end in finalize deleting live
 * inventory.
 *
 * aws4fetch is mocked so no network or credentials are involved; `sleep` is
 * injected so the retries are instant and deterministic.
 */
const fetchMock = vi.fn();
vi.mock('aws4fetch', () => ({
  AwsClient: class {
    fetch(url: string, init?: RequestInit) {
      return fetchMock(url, init);
    }
  },
}));

// Static import: vitest hoists vi.mock above it, so aws4fetch is already
// mocked by the time this binds. A top-level `await import` would work at
// runtime but tsc rejects it under this project's module target.
import { callQueryApi, callJsonApi } from './awsApi';

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const queryOpts = { service: 'ec2', region: 'us-east-1', host: 'ec2.us-east-1.amazonaws.com', action: 'DescribeInstances', version: '2016-11-15' };
const noSleep = { sleep: async () => {}, random: () => 0 };

function xmlError(code: string, message = 'slow down') {
  return new Response(`<Response><Errors><Error><Code>${code}</Code><Message>${message}</Message></Error></Errors></Response>`, { status: 400 });
}

beforeEach(() => {
  fetchMock.mockReset();
});

describe('callQueryApi retry', () => {
  it('retries a throttled call and returns the eventual success', async () => {
    fetchMock
      .mockResolvedValueOnce(xmlError('RequestLimitExceeded'))
      .mockResolvedValueOnce(xmlError('RequestLimitExceeded'))
      .mockResolvedValueOnce(new Response('<ok/>', { status: 200 }));

    const res = await callQueryApi(creds, queryOpts, noSleep);

    expect(res.ok).toBe(true);
    expect(res.attempts).toBe(3);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('gives up after maxAttempts and reports THROTTLED rather than an empty success', async () => {
    // The critical property: a persistently throttled call must surface as a
    // FAILURE with a normalized code. Returning ok with an empty body is what
    // made a throttle indistinguishable from "this account has no instances".
    fetchMock.mockImplementation(() => Promise.resolve(xmlError('RequestLimitExceeded')));

    const res = await callQueryApi(creds, queryOpts, { ...noSleep, retry: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 2 } });

    expect(res.ok).toBe(false);
    expect(res.normalizedCode).toBe('THROTTLED');
    expect(res.attempts).toBe(3);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('does NOT retry a permission error', async () => {
    // Retrying cannot succeed and only adds load to an account that may
    // already be throttling.
    fetchMock.mockImplementation(() => Promise.resolve(xmlError('UnauthorizedOperation', 'not authorized')));

    const res = await callQueryApi(creds, queryOpts, noSleep);

    expect(res.ok).toBe(false);
    expect(res.normalizedCode).toBe('PERMISSION_DENIED');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('does not retry a successful call', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(new Response('<ok/>', { status: 200 })));
    const res = await callQueryApi(creds, queryOpts, noSleep);
    expect(res.attempts).toBe(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('retries a transport failure and normalizes it', async () => {
    fetchMock
      .mockRejectedValueOnce(new Error('fetch failed'))
      .mockResolvedValueOnce(new Response('<ok/>', { status: 200 }));

    const res = await callQueryApi(creds, queryOpts, noSleep);
    expect(res.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('honours Retry-After instead of its own backoff', async () => {
    const slept: number[] = [];
    fetchMock
      .mockResolvedValueOnce(new Response('{}', { status: 429, headers: { 'retry-after': '2' } }))
      .mockResolvedValueOnce(new Response('<ok/>', { status: 200 }));

    await callQueryApi(creds, queryOpts, { sleep: async (ms) => { slept.push(ms); }, random: () => 0 });

    expect(slept).toEqual([2000]);
  });

  it('passes an abort signal so a hung request cannot block a scan step forever', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(new Response('<ok/>', { status: 200 })));
    await callQueryApi(creds, queryOpts, noSleep);
    expect(fetchMock.mock.calls[0][1].signal).toBeDefined();
  });
});

describe('callJsonApi retry', () => {
  it('retries ThrottlingException, the JSON-protocol spelling', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({ __type: 'com.amazon#ThrottlingException', message: 'Rate exceeded' }), { status: 400 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ Clusters: [] }), { status: 200 }));

    const res = await callJsonApi(creds, { service: 'eks', region: 'us-east-1', host: 'eks.us-east-1.amazonaws.com', target: 'X.ListClusters', body: {} }, noSleep);

    expect(res.ok).toBe(true);
    expect(res.attempts).toBe(2);
  });

  it('surfaces a normalized code for an unsupported capability without retrying it', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ __type: 'x#AWSOrganizationsNotInUseException', message: 'not in use' }), { status: 400 })));

    const res = await callJsonApi(creds, { service: 'organizations', region: 'us-east-1', host: 'organizations.us-east-1.amazonaws.com', target: 'X.ListAccounts', body: {} }, noSleep);

    expect(res.normalizedCode).toBe('UNSUPPORTED_CAPABILITY');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

/**
 * The creds sink is what makes degraded-coverage reporting universal.
 *
 * It hangs off the credentials rather than ScannerContext because creds are
 * the one object all 111 scanner files already thread into every AWS call,
 * whichever helper they use (18 use callQueryApi, 57 callJsonApi, 38
 * safeFetch). These assert each helper reports, which is the basis for
 * claiming coverage without having edited any scanner.
 */
describe('creds.onCallFailure — universal degraded-coverage reporting', () => {
  it('reports a terminal failure from callQueryApi', async () => {
    const seen: unknown[] = [];
    fetchMock.mockImplementation(() => Promise.resolve(xmlError('UnauthorizedOperation', 'nope')));

    await callQueryApi({ ...creds, onCallFailure: (f) => seen.push(f) }, queryOpts, noSleep);

    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ service: 'ec2', action: 'DescribeInstances', region: 'us-east-1', normalizedCode: 'PERMISSION_DENIED' });
  });

  it('reports only after retries are exhausted, not once per attempt', async () => {
    // One failed call must degrade the scanner once, not three times.
    const seen: unknown[] = [];
    fetchMock.mockImplementation(() => Promise.resolve(xmlError('RequestLimitExceeded')));

    await callQueryApi({ ...creds, onCallFailure: () => seen.push(1) }, queryOpts, { ...noSleep, retry: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 2 } });

    expect(seen).toHaveLength(1);
  });

  it('does NOT report a call that eventually succeeded', async () => {
    const seen: unknown[] = [];
    fetchMock
      .mockResolvedValueOnce(xmlError('RequestLimitExceeded'))
      .mockResolvedValueOnce(new Response('<ok/>', { status: 200 }));

    await callQueryApi({ ...creds, onCallFailure: () => seen.push(1) }, queryOpts, noSleep);

    expect(seen).toHaveLength(0);
  });

  it('does NOT report UNSUPPORTED_CAPABILITY as degraded coverage', async () => {
    // "This account has not enabled Macie" is a settled answer, not incomplete
    // coverage. Treating it as degraded would permanently freeze vanished-
    // resource cleanup for every service the customer does not use.
    const seen: unknown[] = [];
    fetchMock.mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ __type: 'x#OptInRequired', message: 'not subscribed' }), { status: 400 })));

    await callJsonApi({ ...creds, onCallFailure: () => seen.push(1) }, { service: 'macie2', region: 'us-east-1', host: 'macie2.us-east-1.amazonaws.com', target: 'X.ListFindings', body: {} }, noSleep);

    expect(seen).toHaveLength(0);
  });

  it('reports from callJsonApi with the action derived from the X-Amz-Target', async () => {
    const seen: { action?: string }[] = [];
    fetchMock.mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ __type: 'x#AccessDeniedException', message: 'no' }), { status: 403 })));

    await callJsonApi({ ...creds, onCallFailure: (f) => seen.push(f) }, { service: 'eks', region: 'eu-west-1', host: 'eks.eu-west-1.amazonaws.com', target: 'EKS.ListClusters', body: {} }, noSleep);

    expect(seen[0].action).toBe('ListClusters');
  });

  it('works for a scanner that never opts in — no sink means no crash', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(xmlError('UnauthorizedOperation')));
    const res = await callQueryApi(creds, queryOpts, noSleep);
    expect(res.normalizedCode).toBe('PERMISSION_DENIED');
  });
});
