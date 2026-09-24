import { callQueryApi, createAwsClient } from '../awsApi';
import { extractSection, extractListItems, field } from '../xmlList';
import { isValidRegionFormat } from '../lineage';
import { errorMessage, fetchText, mapWithConcurrency, reportListingFailure, snippet } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const S3_RESOURCE_TYPES = ['s3_bucket', 's3_access_point', 's3_multi_region_access_point'] as const;

/**
 * ListBuckets page size. Passing ANY ListBuckets parameter also makes S3
 * include each bucket's <BucketRegion> in the response, which resolves the
 * region with zero follow-up calls for the vast majority of buckets.
 */
const LIST_PAGE_SIZE = 1000;
/** 20 x 1000 = 20,000 buckets, double the default 10,000-bucket quota. */
const MAX_LIST_PAGES = 20;

/**
 * Per-bucket GetBucketLocation follow-ups, needed only for buckets whose
 * region ListBuckets did not return. Fits inside the Cloudflare free-tier
 * subrequest budget. Exceeding it is reported as truncation, never dropped
 * silently.
 */
const MAX_LOCATION_LOOKUPS = 45;
const LOOKUP_CONCURRENCY = 6;

/** S3 Control listing pages (access points / MRAPs) per region. */
const CONTROL_PAGE_SIZE = 1000;
const MAX_CONTROL_PAGES = 10;
const CONTROL_REGION_CONCURRENCY = 4;

/**
 * Returns a region only if admission would also accept it.
 *
 * This is the whole lesson of the outage in one function. The scanner emitted
 * the string "unknown" as a region; admission rejected anything that is not a
 * valid AWS region name; the two contracts contradicted each other and every
 * S3 bucket was quarantined for twelve days. Validating here with the SAME
 * predicate admission uses means the scanner cannot emit a region admission
 * would refuse -- the contradiction is now impossible rather than merely
 * fixed. Anything unacceptable becomes null, which admission documents as
 * legitimate for a bucket whose region could not be read.
 */
function acceptRegion(value: string | null | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  if (trimmed === 'EU') return 'eu-west-1';
  return isValidRegionFormat(trimmed) ? trimmed : null;
}

/**
 * GetBucketLocation URL.
 *
 * Virtual-hosted style for ordinary names. A bucket name containing dots
 * breaks TLS on virtual-hosted style (`a.b.s3.amazonaws.com` does not match
 * the `*.s3.amazonaws.com` certificate), so those use path style -- otherwise
 * every dotted bucket failed at the transport layer and landed with no region.
 */
export function locationUrl(bucket: string): string {
  return bucket.includes('.')
    ? `https://s3.amazonaws.com/${encodeURIComponent(bucket)}?location`
    : `https://${bucket}.s3.amazonaws.com/?location`;
}

interface ListedBucket { name: string; creationDate: string | null; listedRegion: string | null }

/**
 * S3's ListBuckets is REST-XML, not Query-protocol (no Action param, and the
 * response's root element IS the result). It's a genuinely global call (one
 * endpoint lists every bucket regardless of region), so this is a
 * GLOBAL_SCANNERS entry, same as IAM — discovery.ts must only ever schedule it
 * once per account, not once per scan region.
 *
 * Region resolution, in order of cost:
 *   1. <BucketRegion> from ListBuckets itself (free, every bucket).
 *   2. GetBucketLocation for any bucket still unresolved (capped, reported).
 *      Region is read from the header, the error body, or the body, in that
 *      order; see resolveBucketRegion.
 *
 * A bucket whose region cannot be read is recorded with a NULL region —
 * which admission documents as legitimate for exactly this case.
 */
export async function scanS3(ctx: ScannerContext): Promise<ScannedResource[]> {
  // Signed against us-east-1 regardless of ctx.region — same "global service,
  // fixed signing region" convention as IAM.
  const client = createAwsClient(ctx.creds, 's3', 'us-east-1');
  const out: ScannedResource[] = [];

  const listing = await listAllBuckets(ctx, client);
  const listed = listing.buckets;

  // Only the buckets ListBuckets did not locate cost a follow-up call.
  const needLookup = listed.filter((b) => !b.listedRegion);
  const dropped = new Set<string>();
  if (needLookup.length > MAX_LOCATION_LOOKUPS) {
    /*
     * AWS-P3 (M4). The cap used to be applied silently, so an account with
     * more buckets than the cap reported the first N as though that were the
     * whole estate. PAGINATION_TRUNCATED is the vocabulary's word for "the call
     * succeeded and did not read everything", which degrades the type rather
     * than failing the scan.
     */
    for (const b of needLookup.slice(MAX_LOCATION_LOOKUPS)) dropped.add(b.name);
    reportListingFailure(ctx, { service: 's3', action: 'ListBuckets', region: 'us-east-1', truncated: true });
    console.error(`S3: ${needLookup.length} buckets need a location lookup; only the first ${MAX_LOCATION_LOOKUPS} were read this run.`);
  }

  const lookups = needLookup.filter((b) => !dropped.has(b.name));
  const lookedUp = new Map<string, string | null>();
  await mapWithConcurrency(lookups, LOOKUP_CONCURRENCY, async (b) => {
    lookedUp.set(b.name, await resolveBucketRegion(client, b.name));
  });

  for (const b of listed) {
    if (dropped.has(b.name)) continue;
    out.push({
      resourceTypeKey: 's3_bucket',
      resourceId: b.name,
      region: b.listedRegion ?? lookedUp.get(b.name) ?? null,
      resourceName: b.name,
      metadata: { creationDate: b.creationDate },
    });
  }

  // S3 Control (access points, multi-region access points) is a distinct
  // account-scoped API needing the account ID as an x-amz-account-id header —
  // fetched here via STS GetCallerIdentity (same call permissionChecks.ts
  // already uses) since ScannerContext carries only region/credentials.
  const stsResult = await callQueryApi(ctx.creds, { service: 'sts', region: 'us-east-1', host: 'sts.amazonaws.com', action: 'GetCallerIdentity', version: '2011-06-15' });
  const accountId = stsResult.ok ? field(stsResult.body as string, 'Account') : null;
  if (!accountId) {
    console.error('S3 Control access-point scan skipped: could not resolve account ID via STS GetCallerIdentity.');
    reportListingFailure(ctx, { service: 's3', action: 'ListAccessPoints', region: 'us-east-1' });
    reportListingFailure(ctx, { service: 's3', action: 'ListMultiRegionAccessPoints', region: 'us-west-2' });
    return out;
  }

  /*
   * Access points are REGIONAL and always live in their bucket's region, so
   * the set of regions to ask is exactly the set of bucket regions (plus
   * us-east-1, which the previous version always queried). The previous
   * version only ever asked us-east-1 and so missed every access point
   * elsewhere.
   */
  const apRegions = [...new Set(['us-east-1', ...out.map((r) => r.region).filter((r): r is string => !!r)])].sort();
  const regionSetComplete = listing.complete && dropped.size === 0 && out.every((r) => r.region !== null);
  if (!regionSetComplete) {
    // Some bucket regions are unknown, so some access-point regions may not
    // have been asked. Degrade rather than let those access points look deleted.
    reportListingFailure(ctx, { service: 's3', action: 'ListAccessPoints', region: 'us-east-1', truncated: true });
  }

  const apResults = await mapWithConcurrency(apRegions, CONTROL_REGION_CONCURRENCY, (region) =>
    listAccessPoints(ctx, accountId, region));
  for (const rows of apResults) out.push(...rows);

  out.push(...await listMultiRegionAccessPoints(ctx, accountId));
  return out;
}

async function listAllBuckets(
  ctx: ScannerContext,
  client: ReturnType<typeof createAwsClient>,
): Promise<{ buckets: ListedBucket[]; complete: boolean }> {
  const buckets: ListedBucket[] = [];
  const seenTokens = new Set<string>();
  let token: string | null = null;

  for (let page = 0; page < MAX_LIST_PAGES; page++) {
    const params = new URLSearchParams({ 'max-buckets': String(LIST_PAGE_SIZE) });
    if (token) params.set('continuation-token', token);
    const res = await fetchText(client, `https://s3.amazonaws.com/?${params.toString()}`, { method: 'GET' });

    if (!res.ok) {
      console.error(`S3 ListBuckets failed on page ${page + 1} (continuing with what was read): HTTP ${res.status} ${res.error ?? snippet(res.text)}`);
      reportListingFailure(ctx, { service: 's3', action: 'ListBuckets', region: 'us-east-1', httpStatus: res.status });
      return { buckets, complete: false };
    }

    for (const b of extractListItems(extractSection(res.text, 'Buckets'), 'Bucket')) {
      const name = field(b, 'Name');
      if (!name) continue;
      buckets.push({ name, creationDate: field(b, 'CreationDate'), listedRegion: acceptRegion(field(b, 'BucketRegion')) });
    }

    // <ContinuationToken> sits at the result root, after </Buckets>; it is not
    // a field inside any bucket, so a whole-document lookup is unambiguous.
    token = field(res.text, 'ContinuationToken');
    if (!token) return { buckets, complete: true };
    if (seenTokens.has(token)) break;
    seenTokens.add(token);
  }

  console.error(`S3 ListBuckets did not finish within ${MAX_LIST_PAGES} pages; reporting truncation.`);
  reportListingFailure(ctx, { service: 's3', action: 'ListBuckets', region: 'us-east-1', truncated: true });
  return { buckets, complete: false };
}

/**
 * One bucket's region via GetBucketLocation. Never throws; null when unknown.
 *
 * Deliberately NOT defaulted to us-east-1 on failure: claiming a region we did
 * not read is a false answer, and a wrong region misfiles the bucket in every
 * regional view the product has.
 */
async function resolveBucketRegion(client: ReturnType<typeof createAwsClient>, name: string): Promise<string | null> {
  const res = await fetchText(client, locationUrl(name), { method: 'GET' });
  if (res.status === 0) {
    console.error(`S3 GetBucketLocation threw for a bucket (recording it with no region): ${res.error ?? 'unknown error'}`);
    return null;
  }

  try {
    /*
     * S3 returns the bucket's home region in `x-amz-bucket-region` on SUCCESS
     * **and** on failure -- a 301 PermanentRedirect for a bucket outside the
     * signing region, and a 403 when GetBucketLocation is not permitted, both
     * carry it.
     */
    const headerRegion = acceptRegion(res.headers.get('x-amz-bucket-region'));
    if (headerRegion) return headerRegion;

    if (!res.ok) {
      /*
       * Measured in production 2026-09-22: a bucket outside us-east-1 reached
       * through the legacy global endpoint and signed for us-east-1 gets HTTP
       * 400 AuthorizationHeaderMalformed, whose body carries
       * <Region>ap-south-1</Region>. The answer is inside the rejection.
       */
      const fromError = acceptRegion(/<Region>([^<]*)<\/Region>/.exec(res.text)?.[1]);
      if (fromError) return fromError;
      console.error(`S3 GetBucketLocation failed for a bucket (recording it with no region): HTTP ${res.status}`);
      return null;
    }

    const match = /<LocationConstraint[^>]*>([^<]*)<\/LocationConstraint>/.exec(res.text);
    // An empty (or self-closing) LocationConstraint means us-east-1 — S3's
    // long-standing quirk. A present value still goes through acceptRegion
    // rather than being trusted because it arrived on a 200: that trust is
    // what put the string "unknown" in this column. "EU" (legacy alias for
    // eu-west-1) is mapped inside acceptRegion.
    if (!match || !match[1]) return 'us-east-1';
    return acceptRegion(match[1]);
  } catch (err) {
    console.error(`S3 GetBucketLocation parse failed for a bucket (recording it with no region): ${errorMessage(err)}`);
    return null;
  }
}

async function listAccessPoints(ctx: ScannerContext, accountId: string, region: string): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 's3', region);
  const headers = { 'x-amz-account-id': accountId };
  const out: ScannedResource[] = [];
  const seenTokens = new Set<string>();
  let token: string | null = null;

  for (let page = 0; page < MAX_CONTROL_PAGES; page++) {
    const params = new URLSearchParams({ maxResults: String(CONTROL_PAGE_SIZE) });
    if (token) params.set('nextToken', token);
    const res = await fetchText(client, `https://s3-control.${region}.amazonaws.com/v20180820/accesspoint?${params.toString()}`, { method: 'GET', headers });

    if (!res.ok) {
      console.error(`S3 ListAccessPoints failed in ${region} (continuing without it): HTTP ${res.status} ${res.error ?? snippet(res.text)}`);
      reportListingFailure(ctx, { service: 's3', action: 'ListAccessPoints', region, httpStatus: res.status });
      return out;
    }

    for (const ap of extractListItems(extractSection(res.text, 'AccessPointList'), 'AccessPoint')) {
      const arn = field(ap, 'AccessPointArn');
      if (!arn) continue;
      out.push({
        resourceTypeKey: 's3_access_point', resourceId: arn, region, resourceName: field(ap, 'Name') ?? undefined,
        metadata: {
          bucket: field(ap, 'Bucket'),
          bucketAccountId: field(ap, 'BucketAccountId'),
          alias: field(ap, 'Alias'),
          networkOrigin: field(ap, 'NetworkOrigin'),
          vpcId: field(extractSection(ap, 'VpcConfiguration') ?? '', 'VpcId'),
        },
      });
    }

    token = field(res.text, 'NextToken');
    if (!token) return out;
    if (seenTokens.has(token)) break;
    seenTokens.add(token);
  }

  reportListingFailure(ctx, { service: 's3', action: 'ListAccessPoints', region, truncated: true });
  return out;
}

/**
 * Multi-Region Access Points are account-wide, but the control-plane API is
 * only reachable via the us-west-2 endpoint.
 *
 * The list member is `<AccessPoint>` on the wire (the model's locationName);
 * `<MultiRegionAccessPointReport>` (the shape name, used by this file's
 * earlier version) is also accepted so neither spelling can read as zero.
 */
async function listMultiRegionAccessPoints(ctx: ScannerContext, accountId: string): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 's3', 'us-west-2');
  const headers = { 'x-amz-account-id': accountId };
  const out: ScannedResource[] = [];
  const seenTokens = new Set<string>();
  let token: string | null = null;

  for (let page = 0; page < MAX_CONTROL_PAGES; page++) {
    const params = new URLSearchParams({ maxResults: '100' });
    if (token) params.set('nextToken', token);
    const res = await fetchText(client, `https://s3-control.us-west-2.amazonaws.com/v20180820/mrap/instances?${params.toString()}`, { method: 'GET', headers });

    if (!res.ok) {
      console.error(`S3 ListMultiRegionAccessPoints failed (continuing without it): HTTP ${res.status} ${res.error ?? snippet(res.text)}`);
      reportListingFailure(ctx, { service: 's3', action: 'ListMultiRegionAccessPoints', region: 'us-west-2', httpStatus: res.status });
      return out;
    }

    const section = extractSection(res.text, 'AccessPoints');
    const named = extractListItems(section, 'MultiRegionAccessPointReport');
    for (const mrap of named.length > 0 ? named : extractListItems(section, 'AccessPoint')) {
      const name = field(mrap, 'Name');
      if (!name) continue;
      out.push({
        resourceTypeKey: 's3_multi_region_access_point', resourceId: name, region: null, resourceName: name,
        metadata: { alias: field(mrap, 'Alias'), status: field(mrap, 'Status'), createdAt: field(mrap, 'CreatedAt') },
      });
    }

    token = field(res.text, 'NextToken');
    if (!token) return out;
    if (seenTokens.has(token)) break;
    seenTokens.add(token);
  }

  reportListingFailure(ctx, { service: 's3', action: 'ListMultiRegionAccessPoints', region: 'us-west-2', truncated: true });
  return out;
}