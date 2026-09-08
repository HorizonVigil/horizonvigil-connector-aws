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
