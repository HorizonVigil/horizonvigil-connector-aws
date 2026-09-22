import { describe, it, expect, vi, beforeEach } from 'vitest';

/**
 * S3 scanner contract tests.
 *
 * The load-bearing ones are the region tests. The previous implementation
 * returned the STRING `'unknown'` when GetBucketLocation failed. That is not a
 * valid AWS region name, so admission quarantined the bucket -- defeating this
 * scanner's own stated intent that such a bucket is "recorded, just with a
 * best-effort region rather than being dropped entirely".
 *
 * Measured in production 2026-09-22: 48 quarantine_records, reason
 * INVALID_REGION, 100% s3_bucket, accruing on every run since 2026-09-10.
 * ZERO S3 buckets in inventory while 48 existed.
 *
 * admission.ts already documents NULL as legitimate for exactly this case. The
 * two components were designed to agree; one word broke it -- which is why the
 * decisive test here runs the scanner's output through the real admission rule
 * rather than asserting on the scanner alone.
 */
const fetchMock = vi.fn();
vi.mock('aws4fetch', () => ({
  AwsClient: class {
    fetch(url: string, init?: RequestInit) {
      return fetchMock(url, init);
    }
  },
}));

import { scanS3 } from './s3';
import { classifyRecord, type AdmissionContext } from '../admission';
import type { ScannedResource } from './types';

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };

const ADMISSION: AdmissionContext = {
  orgId: 'org-1',
  connectionId: 'conn-1',
  accountNativeId: '111122223333',
  knownResourceTypes: new Set(['s3_bucket']),
};

const listResponse = (names: string[]) =>
  `<ListAllMyBucketsResult><Buckets>${names
    .map((n) => `<Bucket><Name>${n}</Name><CreationDate>2026-01-01T00:00:00Z</CreationDate></Bucket>`)
    .join('')}</Buckets></ListAllMyBucketsResult>`;

const ok = (body: string, headers: Record<string, string> = {}) =>
  Promise.resolve(new Response(body, { status: 200, headers }));

const fail = (status: number, headers: Record<string, string> = {}) =>
  Promise.resolve(new Response('<Error><Code>AccessDenied</Code></Error>', { status, headers }));

const isLocationCall = (url: string) => url.includes('?location');

/**
 * Serves ListBuckets, and whatever the test says for the per-bucket
 * GetBucketLocation follow-up.
 *
 * Everything else (the STS GetCallerIdentity that gates the S3 Control calls)
 * gets the same harmless body, which carries no <Account>, so the scanner
 * stops after the buckets -- access points are a different code path and not
 * what these tests are about.
 */
function serve(buckets: string[], location: (url: string) => Promise<Response>): void {
  fetchMock.mockImplementation((url: string) =>
    isLocationCall(url) ? location(url) : ok(listResponse(buckets)));
}

const bucketsOf = (out: ScannedResource[]) => out.filter((r) => r.resourceTypeKey === 's3_bucket');

beforeEach(() => { fetchMock.mockReset(); });

describe('S3 bucket region resolution', () => {
  it('records a bucket with NULL region when the location lookup is denied', async () => {
    serve(['my-bucket'], () => fail(403));

    const [bucket] = bucketsOf(await scanS3({ creds, region: 'us-east-1' }));

    expect(bucket.resourceId).toBe('my-bucket');
    expect(bucket.region).toBeNull();
    // The string that caused the outage must never be emitted again.
    expect(bucket.region).not.toBe('unknown');
  });

  /**
   * The end-to-end property, and the only one that would have caught this.
   *
   * A scanner-only assertion passed BEFORE the fix too -- the bucket WAS
   * returned; admission is what discarded it. This asserts the pair.
   */
  it('a bucket whose location lookup failed now SURVIVES admission', async () => {
    serve(['my-bucket'], () => fail(403));

    const [bucket] = bucketsOf(await scanS3({ creds, region: 'us-east-1' }));
    const verdict = await classifyRecord(bucket, ADMISSION);

    expect(verdict.kind, verdict.kind === 'quarantined' ? verdict.reasonDetail : '').toBe('accepted');
  });

  /**
   * The other half of the pair: proof that the rule which quarantined 48
   * buckets is still enforced, and that the old value is what tripped it. If
   * this ever passes, the fix above has stopped being load-bearing and the
   * region column has started accepting junk.
   */
  it('the OLD value would still be quarantined — the rule was never the bug', async () => {
    const withOldValue = { resourceTypeKey: 's3_bucket', resourceId: 'my-bucket', region: 'unknown' };

    const verdict = await classifyRecord(withOldValue, ADMISSION);

    expect(verdict.kind).toBe('quarantined');
    if (verdict.kind === 'quarantined') expect(verdict.reasonCode).toBe('INVALID_REGION');
  });

  /**
   * S3 returns the bucket's home region in `x-amz-bucket-region` on SUCCESS
   * **and** on failure -- a 301 for a bucket outside the signing region and a
   * 403 when the call is not permitted both carry it. Reading the header first
   * resolves the region without the follow-up call succeeding at all, which is
   * what makes the fix robust to either root cause.
   */
  it('reads the region from x-amz-bucket-region even when the call is denied', async () => {
    serve(['my-bucket'], () => fail(403, { 'x-amz-bucket-region': 'eu-west-2' }));

    const [bucket] = bucketsOf(await scanS3({ creds, region: 'us-east-1' }));
    expect(bucket.region).toBe('eu-west-2');
  });

  it('reads it from a 301 redirect too', async () => {
    serve(['my-bucket'], () => fail(301, { 'x-amz-bucket-region': 'ap-south-1' }));

    const [bucket] = bucketsOf(await scanS3({ creds, region: 'us-east-1' }));
    expect(bucket.region).toBe('ap-south-1');
  });

  it('still parses LocationConstraint on a normal success', async () => {
    serve(['my-bucket'], () => ok('<LocationConstraint>eu-central-1</LocationConstraint>'));

    const [bucket] = bucketsOf(await scanS3({ creds, region: 'us-east-1' }));
    expect(bucket.region).toBe('eu-central-1');
  });

  it('maps S3s legacy EU constraint to eu-west-1 rather than dropping it', async () => {
    // "EU" fails the region-format check, so without the explicit mapping a
    // long-lived European bucket would silently land with no region at all.
    serve(['my-bucket'], () => ok('<LocationConstraint>EU</LocationConstraint>'));

    const [bucket] = bucketsOf(await scanS3({ creds, region: 'us-east-1' }));
    expect(bucket.region).toBe('eu-west-1');
    expect((await classifyRecord(bucket, ADMISSION)).kind).toBe('accepted');
  });

  it('treats an empty LocationConstraint as us-east-1, S3s long-standing quirk', async () => {
    serve(['my-bucket'], () => ok('<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>'));

    const [bucket] = bucketsOf(await scanS3({ creds, region: 'us-east-1' }));
    expect(bucket.region).toBe('us-east-1');
  });

  /**
   * Deliberately NOT defaulted to us-east-1 when the lookup fails: claiming a
   * region we did not read is a false answer, and a wrong region misfiles the
   * bucket in every regional view the product has.
   */
  it('does not guess us-east-1 when the region is genuinely unknown', async () => {
    serve(['my-bucket'], () => fail(500));

    const [bucket] = bucketsOf(await scanS3({ creds, region: 'us-east-1' }));
    expect(bucket.region).toBeNull();
  });

  /**
   * The root cause, measured in production 2026-09-22 rather than guessed at:
   * this call returns HTTP 400, not 403 and not 301. A bucket outside
   * us-east-1 reached through the legacy global endpoint and signed for
   * us-east-1 is refused with AuthorizationHeaderMalformed -- and that refusal
   * names the region we were trying to discover.
   *
   * This is the real production response for `elasticbeanstalk-ap-south-1-…`.
   */
  it('reads the region out of the 400 that refuses the request', async () => {
    serve(['elasticbeanstalk-ap-south-1-354307071074'], () =>
      Promise.resolve(new Response(
        '<?xml version="1.0" encoding="UTF-8"?><Error><Code>AuthorizationHeaderMalformed</Code>'
        + "<Message>The authorization header is malformed; the region 'us-east-1' is wrong; expecting 'ap-south-1'</Message>"
        + '<Region>ap-south-1</Region></Error>',
        { status: 400 },
      )));

    const [bucket] = bucketsOf(await scanS3({ creds, region: 'us-east-1' }));
    expect(bucket.region).toBe('ap-south-1');
  });

  it('the region from a 400 still has to pass admission', async () => {
    // A <Region> element containing junk must not become a region, or this is
    // the same outage with a different source for the bad value.
    serve(['my-bucket'], () =>
      Promise.resolve(new Response('<Error><Region>not a region</Region></Error>', { status: 400 })));

    const [bucket] = bucketsOf(await scanS3({ creds, region: 'us-east-1' }));
    expect(bucket.region).toBeNull();
    expect((await classifyRecord(bucket, ADMISSION)).kind).toBe('accepted');
  });

  it('prefers the header over the error body when both are present', async () => {
    serve(['my-bucket'], () =>
      Promise.resolve(new Response('<Error><Region>eu-west-3</Region></Error>', {
        status: 400, headers: { 'x-amz-bucket-region': 'ap-south-1' },
      })));

    const [bucket] = bucketsOf(await scanS3({ creds, region: 'us-east-1' }));
    expect(bucket.region).toBe('ap-south-1');
  });

  /**
   * The structural guarantee, not just the fixed case. Whatever S3 returns and
   * from whichever of its three locations, the scanner validates with the same
   * predicate admission uses, so it cannot emit a region admission refuses.
   */
  it('no S3 response shape can produce a region that admission would quarantine', async () => {
    const hostile = [
      () => ok('<LocationConstraint>unknown</LocationConstraint>'),
      () => fail(403, { 'x-amz-bucket-region': 'not a region' }),
      () => fail(400, { 'x-amz-bucket-region': '  ' }),
      () => Promise.resolve(new Response('<Error><Region>../../etc</Region></Error>', { status: 400 })),
      () => ok('<LocationConstraint>   </LocationConstraint>'),
    ];

    for (const [i, location] of hostile.entries()) {
      fetchMock.mockReset();
      serve(['my-bucket'], location);

      const [bucket] = bucketsOf(await scanS3({ creds, region: 'us-east-1' }));
      const verdict = await classifyRecord(bucket, ADMISSION);

      expect(verdict.kind, `case ${i}: region=${JSON.stringify(bucket.region)}`).toBe('accepted');
    }
  });

  it('records the bucket when the location request fails at the transport level', async () => {
    serve(['my-bucket'], () => Promise.reject(new Error('socket hang up')));

    const [bucket] = bucketsOf(await scanS3({ creds, region: 'us-east-1' }));
    expect(bucket.resourceId).toBe('my-bucket');
    expect(bucket.region).toBeNull();
  });

  it('keeps every bucket, whatever mix of answers the lookups give', async () => {
    serve(['a', 'b', 'c'], (url) => {
      if (url.includes('//a.')) return ok('<LocationConstraint>eu-west-1</LocationConstraint>');
      if (url.includes('//b.')) return fail(403, { 'x-amz-bucket-region': 'us-west-2' });
      return fail(403);
    });

    const out = bucketsOf(await scanS3({ creds, region: 'us-east-1' }));

    expect(out.map((r) => r.resourceId)).toEqual(['a', 'b', 'c']);
    expect(out.map((r) => r.region)).toEqual(['eu-west-1', 'us-west-2', null]);
  });
});

/**
 * M4. The per-bucket cap was applied silently, so an account with more buckets
 * than the cap reported the first 45 as though that were the whole estate --
 * the same shape as every other truncation defect in this product, and the one
 * that hides because it under-reports rather than erroring.
 */
describe('S3 bucket cap', () => {
  const many = (n: number) => Array.from({ length: n }, (_, i) => `bucket-${i}`);
  const located = () => ok('<LocationConstraint>eu-west-1</LocationConstraint>');

  it('reports truncation when the cap is hit', async () => {
    const failures: { normalizedCode: string; action: string }[] = [];
    serve(many(60), located);

    await scanS3({ creds: { ...creds, onCallFailure: (f) => failures.push(f) }, region: 'us-east-1' });

    const truncation = failures.filter((f) => f.normalizedCode === 'PAGINATION_TRUNCATED');
    expect(truncation).toHaveLength(1);
    expect(truncation[0].action).toBe('ListBuckets');
  });

  it('does NOT report truncation when every bucket was read', async () => {
    // A false truncation signal would degrade s3_bucket on every clean run,
    // which is how a real signal stops being believed.
    const failures: { normalizedCode: string }[] = [];
    serve(many(10), located);

    await scanS3({ creds: { ...creds, onCallFailure: (f) => failures.push(f) }, region: 'us-east-1' });

    expect(failures.filter((f) => f.normalizedCode === 'PAGINATION_TRUNCATED')).toEqual([]);
  });

  it('still returns the buckets it did read', async () => {
    serve(many(60), located);
    expect(bucketsOf(await scanS3({ creds, region: 'us-east-1' }))).toHaveLength(45);
  });
});
