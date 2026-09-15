/**
 * AWS-05 — the backend owns supported-region truth.
 *
 * Region truth was split between a regex in lineage.ts and a list in React,
 * and the connector's own comment recorded that it hardcodes 17 commercial
 * regions (AWS-P1-01). A hardcoded roster fails in two opposite directions:
 * a region AWS launched afterwards looks invalid, and a region the account
 * cannot actually use looks available.
 *
 * `ec2:DescribeRegions` is the provider's own answer. With
 * `AllRegions=true` it returns every region AWS publishes plus an
 * `optInStatus` per region, which is the only honest source for whether
 * THIS account may use one.
 */
import { callQueryApi } from './awsApi';
import type { AwsCreds } from './awsApi';
import { partitionForRegion } from './lineage';

/** EC2 query API version used across this connector's EC2 calls. */
const EC2_API_VERSION = '2016-11-15';

/**
 * AWS returns one of these in `optInStatus`.
 *
 * `opt-in-not-required` is the ordinary case for long-standing commercial
 * regions. The other two are what make this call worth making at all: they
 * distinguish a region the account HAS enabled from one it merely could.
 */
export type OptInStatus = 'opt-in-not-required' | 'opted-in' | 'not-opted-in';

export interface DiscoveredRegion {
  regionCode: string;
  partition: string;
  /**
   * `true` only for a region that genuinely requires opting in. Null is not
   * used here because DescribeRegions always tells us — it is the *absence*
   * of this call that produces NULL in the catalog.
   */
  optInRequired: boolean;
  /**
   * AVAILABLE   — usable by this account now
   * NOT_OPTED_IN— exists, requires opt-in, and this account has not
   * UNKNOWN     — AWS returned a status this code does not recognise
   */
  status: 'AVAILABLE' | 'NOT_OPTED_IN' | 'UNKNOWN';
  optInStatus: string;
}

/**
 * Maps AWS's own vocabulary to the catalog's.
 *
 * An unrecognised status becomes UNKNOWN, never AVAILABLE. AWS has added
 * region states before; treating a state we do not understand as usable is
 * how a scan gets pointed at a region the account cannot reach, and the
 * resulting failures look like a broken connector rather than an
 * unrecognised opt-in state.
 */
export function classifyOptIn(optInStatus: string): Pick<DiscoveredRegion, 'optInRequired' | 'status'> {
  switch (optInStatus) {
    case 'opt-in-not-required':
      return { optInRequired: false, status: 'AVAILABLE' };
    case 'opted-in':
      return { optInRequired: true, status: 'AVAILABLE' };
    case 'not-opted-in':
      return { optInRequired: true, status: 'NOT_OPTED_IN' };
    default:
      return { optInRequired: true, status: 'UNKNOWN' };
  }
}

/**
 * Parses the DescribeRegions XML response.
 *
 * Deliberately tolerant of field order and of items missing `optInStatus`:
 * a region we cannot classify is returned as UNKNOWN rather than dropped,
 * because silently omitting a region from the catalog is indistinguishable
 * from AWS not having it.
 */
export function parseDescribeRegions(xml: string): DiscoveredRegion[] {
  const out: DiscoveredRegion[] = [];
  for (const item of xml.split('<item>').slice(1)) {
    const code = /<regionName>([^<]+)<\/regionName>/.exec(item)?.[1]?.trim();
    if (!code) continue;
    const optIn = /<optInStatus>([^<]+)<\/optInStatus>/.exec(item)?.[1]?.trim() ?? 'unknown';
    const partition = partitionForRegion(code);
    out.push({
      regionCode: code,
      // A region whose prefix matches no known partition convention is still
      // a real region AWS just told us about; recording it as 'aws' would be
      // a guess, so the unresolved case is carried through as-is.
      partition: partition ?? 'unknown',
      optInStatus: optIn,
      ...classifyOptIn(optIn),
    });
  }
  return out;
}

/**
 * Calls ec2:DescribeRegions for a connection.
 *
 * `AllRegions=true` so the catalog learns about regions this account has NOT
 * opted into. Without it AWS returns only enabled regions, and "not returned"
 * would be indistinguishable from "does not exist" — the catalog could then
 * never say NOT_OPTED_IN, which is the state most worth knowing.
 */
export async function describeRegions(
  creds: AwsCreds,
  region: string,
): Promise<{ ok: true; regions: DiscoveredRegion[] } | { ok: false; error: string }> {
  const result = await callQueryApi(creds, {
    service: 'ec2',
    region,
    host: `ec2.${region}.amazonaws.com`,
    action: 'DescribeRegions',
    version: EC2_API_VERSION,
    params: { AllRegions: 'true' },
  });

  if (!result.ok) return { ok: false, error: result.errorMessage ?? result.errorCode ?? `DescribeRegions failed (HTTP ${result.status})` };
  const regions = parseDescribeRegions(typeof result.body === 'string' ? result.body : '');
  // An empty parse from a successful call means the response shape changed.
  // Reporting that as "zero regions" would wipe the catalog's meaning, so it
  // is an error instead.
  if (regions.length === 0) return { ok: false, error: 'DescribeRegions returned no parseable regions' };
  return { ok: true, regions };
}
