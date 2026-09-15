import { describe, it, expect, vi, beforeEach } from 'vitest';

/**
 * The pagination contract, asserted against a mocked transport.
 *
 * Every case the connector spec requires is here: 1 page, 2 pages, many pages,
 * an empty page, a repeated token, a missing token, malformed pagination and
 * partial failure — plus the one that matters most, that items from EVERY page
 * survive. A previous implementation concatenated the page bodies and then
 * sliced the list out with `extractSection` (first match only), so it made the
 * calls for pages 2..N and threw all of them away. The two-page test below is
 * what would have caught that.
 */
const fetchMock = vi.fn();
vi.mock('aws4fetch', () => ({
  AwsClient: class {
    fetch(url: string, init?: RequestInit) {
      return fetchMock(url, init);
    }
  },
}));

import {
  detectQueryTruncation,
  detectJsonTruncation,
  paginateQueryList,
  paginateJsonApi,
  queryPageItems,
  jsonPageItems,
  isComplete,
  incompleteSink,
  DEFAULT_MAX_PAGES,
} from './pagination';

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const queryOpts = { service: 'ec2', region: 'us-east-1', host: 'ec2.us-east-1.amazonaws.com', action: 'DescribeVolumes', version: '2016-11-15' };
const noSleep = { sleep: async () => {}, random: () => 0 };

/** A Query-protocol list page: a section of `<item>`s plus an optional token. */
function volumePage(ids: string[], nextToken?: string | null): string {
  const items = ids.map((id) => `<item><volumeId>${id}</volumeId></item>`).join('');
  const token = nextToken ? `<NextToken>${nextToken}</NextToken>` : '';
  return `<DescribeVolumesResponse><volumeSet>${items}</volumeSet>${token}</DescribeVolumesResponse>`;
}

function xmlOk(body: string) {
  return new Response(body, { status: 200 });
}

/** Reads the NextToken the walker sent back, so the mock can serve the right page. */
function sentToken(init?: RequestInit): string | null {
  const body = String(init?.body ?? '');
  const match = /NextToken=([^&]*)/.exec(body);
  return match ? decodeURIComponent(match[1]) : null;
}

beforeEach(() => {
  fetchMock.mockReset();
});

describe('truncation detection', () => {
  it('reads IsTruncated as authoritative on marker-style APIs', () => {
    expect(detectQueryTruncation('<X><IsTruncated>true</IsTruncated></X>').truncated).toBe(true);
    expect(detectQueryTruncation('<X><IsTruncated>false</IsTruncated></X>').truncated).toBe(false);
  });

  it('prefers a populated token field over an empty one', () => {
    // A stray empty NextToken must not mask a real NextMarker.
    const signal = detectQueryTruncation('<X><NextToken></NextToken><NextMarker>abc</NextMarker></X>');
    expect(signal).toMatchObject({ truncated: true, nextToken: 'abc', tokenParam: 'NextMarker' });
  });

  it('surfaces truncation with no token rather than calling it complete', () => {
    expect(detectQueryTruncation('<X><IsTruncated>true</IsTruncated></X>')).toMatchObject({ truncated: true, nextToken: null });
  });

  it('reads JSON tokens, including the lower-camel forms', () => {
    expect(detectJsonTruncation({ NextToken: 't' })).toMatchObject({ truncated: true, nextToken: 't', tokenParam: 'NextToken' });
    expect(detectJsonTruncation({ nextToken: 't' })).toMatchObject({ truncated: true, tokenParam: 'nextToken' });
    expect(detectJsonTruncation({ IsTruncated: true })).toMatchObject({ truncated: true, nextToken: null });
    expect(detectJsonTruncation({ Clusters: [] }).truncated).toBe(false);
  });

  it('ignores a nested marker, which is a resource field and not pagination', () => {
    // A false positive here would degrade a scanner's coverage and freeze its
    // cleanup, so root-only inspection is load-bearing.
    expect(detectJsonTruncation({ Buckets: [{ Marker: 'not-a-token' }] }).truncated).toBe(false);
  });

  it('treats a non-object and an absent body as untruncated', () => {
    expect(detectJsonTruncation(null).truncated).toBe(false);
    expect(detectJsonTruncation([1, 2]).truncated).toBe(false);
    expect(detectQueryTruncation('').truncated).toBe(false);
  });
});

/** `<item><volumeId>vol-1</volumeId></item>` -> `vol-1`, parsed out of a page item. */
function xmlIdOf(item: string): string {
  return /<volumeId>([^<]*)<\/volumeId>/.exec(item)?.[1] ?? '';
}

describe('paginateQueryList — the required pagination matrix', () => {
  /** Serves each page exactly once per token, the way AWS does. */
  function servePages(pages: Record<string, string>) {
    fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
      const token = sentToken(init);
      const body = token === null ? pages['first'] : pages[token];
      if (!body) throw new Error(`unexpected token ${token}`);
      return Promise.resolve(xmlOk(body));
    });
  }

  it('one page: returns its items and reports complete', async () => {
    servePages({ first: volumePage(['vol-1', 'vol-2']) });

    const walk = await paginateQueryList(creds, queryOpts, 'volumeSet');

    expect(walk.items.map((i) => xmlIdOf(i))).toEqual(['vol-1', 'vol-2']);
    expect(walk.pages).toBe(1);
    expect(walk.termination).toBe('complete');
    expect(isComplete(walk)).toBe(true);
  });

  it('two pages: items from BOTH survive, and the token is sent back', async () => {
    // The regression this whole module exists for: a page-1-only reader returns
    // one item here, and finalize then tombstones the other as vanished.
    servePages({ first: volumePage(['vol-1'], 't2'), t2: volumePage(['vol-2']) });

    const walk = await paginateQueryList(creds, queryOpts, 'volumeSet');

    expect(walk.items.map((i) => xmlIdOf(i))).toEqual(['vol-1', 'vol-2']);
    expect(walk.pages).toBe(2);
    expect(walk.termination).toBe('complete');
  });

  it('many pages: every page is accumulated, in order', async () => {
    const pages: Record<string, string> = {};
    for (let i = 1; i <= 20; i++) {
      pages[i === 1 ? 'first' : `t${i}`] = volumePage([`vol-${i}`], i < 20 ? `t${i + 1}` : null);
    }
    servePages(pages);

    const walk = await paginateQueryList(creds, queryOpts, 'volumeSet');

    expect(walk.pages).toBe(20);
    expect(walk.items).toHaveLength(20);
    expect(xmlIdOf(walk.items[19])).toBe('vol-20');
    expect(walk.termination).toBe('complete');
  });

  it('empty page: no items, no token, still complete', async () => {
    servePages({ first: volumePage([]) });

    const walk = await paginateQueryList(creds, queryOpts, 'volumeSet');

    expect(walk.items).toEqual([]);
    expect(walk.termination).toBe('complete');
  });

  it('empty FIRST page with a token keeps walking', async () => {
    // An empty page is not proof of completion when AWS is still handing out
    // tokens; treating it as the end would silently drop the real page.
    servePages({ first: volumePage([], 't2'), t2: volumePage(['vol-9']) });

    const walk = await paginateQueryList(creds, queryOpts, 'volumeSet');

    expect(walk.items.map((i) => xmlIdOf(i))).toEqual(['vol-9']);
    expect(walk.pages).toBe(2);
  });

  it('repeated token: stops rather than looping, and SAYS so', async () => {
    const incomplete = vi.fn();
    // AWS handing back a token already followed would otherwise spin forever.
    servePages({ first: volumePage(['vol-1'], 'same'), same: volumePage(['vol-2'], 'same') });

    const walk = await paginateQueryList(creds, queryOpts, 'volumeSet', 'item', { onIncomplete: incomplete });

    expect(walk.termination).toBe('repeated_token');
    expect(walk.items).toHaveLength(2);
    expect(incomplete).toHaveBeenCalledWith('PAGINATION_TRUNCATED', expect.stringContaining('already followed'));
  });

  it('missing token: truncation with nothing to follow is malformed, not complete', async () => {
    const incomplete = vi.fn();
    servePages({ first: '<DescribeVolumesResponse><volumeSet></volumeSet><IsTruncated>true</IsTruncated></DescribeVolumesResponse>' });

    const walk = await paginateQueryList(creds, queryOpts, 'volumeSet', 'item', { onIncomplete: incomplete });

    expect(walk.termination).toBe('malformed');
    expect(incomplete).toHaveBeenCalledWith('PAGINATION_TRUNCATED', expect.stringContaining('no continuation token'));
  });

  it('malformed pagination (empty token) is treated as no token, not as a loop', async () => {
    servePages({ first: volumePage(['vol-1'], null).replace('</DescribeVolumesResponse>', '<NextToken></NextToken></DescribeVolumesResponse>') });

    const walk = await paginateQueryList(creds, queryOpts, 'volumeSet');

    expect(walk.termination).toBe('complete');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('page cap: stops and reports rather than truncating silently', async () => {
    const incomplete = vi.fn();
    fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
      const token = sentToken(init);
      const n = token === null ? 1 : Number(token);
      return Promise.resolve(xmlOk(volumePage([`vol-${n}`], String(n + 1))));
    });

    const walk = await paginateQueryList(creds, queryOpts, 'volumeSet', 'item', { maxPages: 3, onIncomplete: incomplete });

    expect(walk.pages).toBe(3);
    expect(walk.termination).toBe('page_cap');
    expect(incomplete).toHaveBeenCalledWith('PAGINATION_TRUNCATED', expect.stringContaining('3-page cap'));
  });
it('partial failure: keeps the pages already read and reports the walk as partial', async () => {
    // The failed call is reported by awsApi's own sink (that is what degrades
    // the scanner's resource types); this asserts the walk does not pretend to
    // have finished.
    fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
      const token = sentToken(init);
      if (token === null) return Promise.resolve(xmlOk(volumePage(['vol-1'], 't2')));
      return Promise.resolve(new Response('<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>no</Message></Error></Errors></Response>', { status: 403 }));
    });

    const walk = await paginateQueryList(creds, queryOpts, 'volumeSet');

    expect(walk.items.map((i) => xmlIdOf(i))).toEqual(['vol-1']);
    expect(walk.termination).toBe('failed');
    expect(isComplete(walk)).toBe(false);
  });

  it('reports a failed page through the shared degraded-coverage sink', async () => {
    const failures: unknown[] = [];
    fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
      const token = sentToken(init);
      if (token === null) return Promise.resolve(xmlOk(volumePage(['vol-1'], 't2')));
      return Promise.resolve(new Response('<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>no</Message></Error></Errors></Response>', { status: 403 }));
    });

    await paginateQueryList({ ...creds, onCallFailure: (f) => failures.push(f) }, queryOpts, 'volumeSet');

    expect(failures).toHaveLength(1);
    expect(failures[0]).toMatchObject({ service: 'ec2', action: 'DescribeVolumes', normalizedCode: 'PERMISSION_DENIED' });
  });

  it('does not double-count a FAILED page as incompleteness', async () => {
    // awsApi reports the failure; reporting it again here would degrade twice
    // for one event.
    const incomplete = vi.fn();
    fetchMock.mockResolvedValue(new Response('<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>no</Message></Error></Errors></Response>', { status: 403 }));

    await paginateQueryList(creds, queryOpts, 'volumeSet', 'item', { onIncomplete: incomplete });

    expect(incomplete).not.toHaveBeenCalled();
  });

  it('defaults to the documented page cap', () => {
    expect(DEFAULT_MAX_PAGES).toBe(200);
  });
});

describe('paginateJsonApi', () => {
  it('follows nextToken across pages', async () => {
    fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { nextToken?: string };
      if (body.nextToken === undefined) return Promise.resolve(new Response(JSON.stringify({ functions: ['a'], nextToken: 'n2' }), { status: 200 }));
      return Promise.resolve(new Response(JSON.stringify({ functions: ['b'] }), { status: 200 }));
    });

    const walk = await paginateJsonApi<{ functions?: string[] }, string>(
      creds,
      { service: 'lambda', region: 'us-east-1', host: 'lambda.us-east-1.amazonaws.com', target: 'Lambda.ListFunctions', body: {} },
      (page) => jsonPageItems(page, 'functions'),
      (page) => detectJsonTruncation(page),
    );

    expect(walk.items).toEqual(['a', 'b']);
    expect(walk.pages).toBe(2);
    expect(walk.termination).toBe('complete');
  });
});

describe('incompleteSink', () => {
  it('turns an incomplete walk into degraded coverage on the creds sink', () => {
    const seen: { normalizedCode?: string }[] = [];
    incompleteSink({ ...creds, onCallFailure: (f) => seen.push(f) })('PAGINATION_TRUNCATED', 'stopped at the cap');

    expect(seen).toHaveLength(1);
    expect(seen[0].normalizedCode).toBe('PAGINATION_TRUNCATED');
  });

  it('carries no credential, ARN or account id in its record', () => {
    const seen: Record<string, unknown>[] = [];
    incompleteSink({ ...creds, onCallFailure: (f) => seen.push(f as unknown as Record<string, unknown>) })('PAGINATION_TRUNCATED', 'stopped at the cap');

    expect(JSON.stringify(seen)).not.toMatch(/AKIA|arn:|\d{12}/);
  });
});

describe('queryPageItems / jsonPageItems', () => {
  it('reads one page at a time, never merging pages itself', () => {
    // Per-page extraction is the whole point: a merged reader would return only
    // the first page's items here.
    expect(queryPageItems(volumePage(['vol-1']), 'volumeSet')).toHaveLength(1);
    expect(queryPageItems(volumePage(['vol-2']), 'volumeSet')).toHaveLength(1);
  });

  it('supports a non-default member tag (IAM uses <member>)', () => {
    const xml = '<ListUsersResult><Users><member><Arn>arn:aws:iam::1:user/a</Arn></member></Users></ListUsersResult>';
    expect(queryPageItems(xml, 'Users', 'member')).toHaveLength(1);
  });

  it('treats an absent JSON list key as an empty page, not an error', () => {
    expect(jsonPageItems({}, 'functions')).toEqual([]);
    expect(jsonPageItems(null, 'functions')).toEqual([]);
    expect(jsonPageItems({ functions: 'not-an-array' }, 'functions')).toEqual([]);
  });
});