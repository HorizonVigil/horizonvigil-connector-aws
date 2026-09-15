import { describe, it, expect, vi, beforeEach } from 'vitest';

/**
 * The central truncation guard: a SUCCESSFUL but incomplete AWS response must
 * be reported as degraded coverage.
 *
 * This is the property that protects the scanners not yet migrated onto
 * lib/pagination.ts. Without it, a scanner reading only page 1 returns fewer
 * resources than exist with a 200 and no error, `onCallFailure` has nothing to
 * fire on, and finalize soft-deletes everything on the unread pages. The
 * assertions below pin both directions: it must fire when AWS says there is
 * more, and it must NOT fire when the answer is complete — a false positive
 * would degrade a scanner permanently and freeze its cleanup.
 */
const fetchMock = vi.fn();
vi.mock('aws4fetch', () => ({
  AwsClient: class {
    fetch(url: string, init?: RequestInit) {
      return fetchMock(url, init);
    }
  },
}));

import { callQueryApi, callJsonApi, safeFetch, createAwsClient } from './awsApi';

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const noSleep = { sleep: async () => {}, random: () => 0 };
const queryOpts = { service: 'ec2', region: 'us-east-1', host: 'ec2.us-east-1.amazonaws.com', action: 'DescribeVolumes', version: '2016-11-15' };
const jsonOpts = { service: 'lambda', region: 'us-east-1', host: 'lambda.us-east-1.amazonaws.com', target: 'Lambda.ListFunctions', body: {} };

function sink() {
  const seen: { normalizedCode?: string }[] = [];
  return { seen, creds: { ...creds, onCallFailure: (f: { normalizedCode?: string }) => seen.push(f) } };
}

beforeEach(() => {
  fetchMock.mockReset();
});

describe('truncation guard on callQueryApi', () => {
  it('reports PAGINATION_TRUNCATED when a 200 carries a continuation token', async () => {
    fetchMock.mockResolvedValue(new Response('<X><volumeSet><item/></volumeSet><NextToken>t2</NextToken></X>', { status: 200 }));
    const s = sink();

    const res = await callQueryApi(s.creds, queryOpts, noSleep);

    // The call itself is still a SUCCESS — the body is valid and usable.
    expect(res.ok).toBe(true);
    expect(s.seen).toHaveLength(1);
    expect(s.seen[0].normalizedCode).toBe('PAGINATION_TRUNCATED');
  });

  it('reports it for IsTruncated with no token as well', async () => {
    fetchMock.mockResolvedValue(new Response('<X><IsTruncated>true</IsTruncated></X>', { status: 200 }));
    const s = sink();

    await callQueryApi(s.creds, queryOpts, noSleep);

    expect(s.seen).toHaveLength(1);
  });

  it('does NOT report a complete response', async () => {
    fetchMock.mockResolvedValue(new Response('<X><volumeSet><item/></volumeSet></X>', { status: 200 }));
    const s = sink();

    await callQueryApi(s.creds, queryOpts, noSleep);

    expect(s.seen).toHaveLength(0);
  });

  it('does NOT report IsTruncated=false', async () => {
    fetchMock.mockResolvedValue(new Response('<X><IsTruncated>false</IsTruncated></X>', { status: 200 }));
    const s = sink();

    await callQueryApi(s.creds, queryOpts, noSleep);

    expect(s.seen).toHaveLength(0);
  });

  it('is suppressed under pagination: "follow" — the walker reports for itself', async () => {
    // Without this, every correctly-paginating scanner would be marked degraded
    // on each page-1 response.
    fetchMock.mockResolvedValue(new Response('<X><NextToken>t2</NextToken></X>', { status: 200 }));
    const s = sink();

    await callQueryApi(s.creds, queryOpts, { ...noSleep, pagination: 'follow' });

    expect(s.seen).toHaveLength(0);
  });

  it('does not fire on a FAILED call, which is already reported as its own error', async () => {
    fetchMock.mockResolvedValue(new Response('<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>no</Message></Error></Errors></Response>', { status: 403 }));
    const s = sink();

    await callQueryApi(s.creds, queryOpts, noSleep);

    expect(s.seen).toHaveLength(1);
    expect(s.seen[0].normalizedCode).toBe('PERMISSION_DENIED');
  });
});

describe('truncation guard on callJsonApi', () => {
  it('reports a root NextToken', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ Functions: [], NextToken: 'n2' }), { status: 200 }));
    const s = sink();

    const res = await callJsonApi(s.creds, jsonOpts, noSleep);

    expect(res.ok).toBe(true);
    expect(s.seen).toHaveLength(1);
    expect(s.seen[0].normalizedCode).toBe('PAGINATION_TRUNCATED');
  });

  it('reports a root nextToken', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ functions: [], nextToken: 'n2' }), { status: 200 }));
    const s = sink();

    await callJsonApi(s.creds, jsonOpts, noSleep);

    expect(s.seen).toHaveLength(1);
  });

  it('ignores a nested marker — a resource field is not pagination', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ Buckets: [{ Marker: 'x' }] }), { status: 200 }));
    const s = sink();

    await callJsonApi(s.creds, jsonOpts, noSleep);

    expect(s.seen).toHaveLength(0);
  });

  it('does not report a complete JSON response', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ Functions: [] }), { status: 200 }));
    const s = sink();

    await callJsonApi(s.creds, jsonOpts, noSleep);

    expect(s.seen).toHaveLength(0);
  });
});

describe('truncation guard on safeFetch (the raw-client path)', () => {
  const url = 'https://s3.us-east-1.amazonaws.com/?list-type=2';

  it('reports a truncated response for a scanner that never opts in', async () => {
    fetchMock.mockResolvedValue(new Response('<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>', { status: 200 }));
    const s = sink();

    const res = await safeFetch(createAwsClient(s.creds, 's3', 'us-east-1'), url, {}, noSleep);

    expect(res.ok).toBe(true);
    expect(s.seen).toHaveLength(1);
    expect(s.seen[0].normalizedCode).toBe('PAGINATION_TRUNCATED');
  });

  it('does not report a complete response', async () => {
    fetchMock.mockResolvedValue(new Response('<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>', { status: 200 }));
    const s = sink();

    await safeFetch(createAwsClient(s.creds, 's3', 'us-east-1'), url, {}, noSleep);

    expect(s.seen).toHaveLength(0);
  });

  it('puts no credential or bucket name in the reported record', async () => {
    fetchMock.mockResolvedValue(new Response('<X><NextToken>t</NextToken></X>', { status: 200 }));
    const s = sink();

    await safeFetch(createAwsClient(s.creds, 's3', 'us-east-1'), 'https://s3.amazonaws.com/secret-bucket-name/?list-type=2', {}, noSleep);

    expect(JSON.stringify(s.seen)).not.toMatch(/AKIA|secret-bucket-name/);
  });

  it('does not fire when the caller streams the body itself', async () => {
    // curIngest.ts's CUR download opts out of buffering; there is no in-memory
    // body to probe, and re-reading a stream the caller owns would corrupt it.
    fetchMock.mockResolvedValue(new Response('<X><NextToken>t</NextToken></X>', { status: 200 }));
    const s = sink();

    await safeFetch(createAwsClient(s.creds, 's3', 'us-east-1'), url, {}, { ...noSleep, bufferBody: false });

    expect(s.seen).toHaveLength(0);
  });
});