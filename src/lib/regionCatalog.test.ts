import { describe, it, expect } from 'vitest';
import { classifyOptIn, parseDescribeRegions } from './regionCatalog';

/**
 * AWS-05. The catalog previously held 17 regions, every one with
 * `opt_in_required = NULL` and `status = UNKNOWN`, because it was seeded
 * from observation: seeing a resource in a region proves the region exists
 * and proves nothing about whether the account may use it.
 *
 * `ec2:DescribeRegions` with `AllRegions=true` is the provider's own answer.
 */
const XML = `<DescribeRegionsResponse>
  <regionInfo>
    <item><regionName>us-east-1</regionName><regionEndpoint>ec2.us-east-1.amazonaws.com</regionEndpoint><optInStatus>opt-in-not-required</optInStatus></item>
    <item><regionName>ap-east-1</regionName><regionEndpoint>ec2.ap-east-1.amazonaws.com</regionEndpoint><optInStatus>not-opted-in</optInStatus></item>
    <item><regionName>me-south-1</regionName><regionEndpoint>ec2.me-south-1.amazonaws.com</regionEndpoint><optInStatus>opted-in</optInStatus></item>
  </regionInfo>
</DescribeRegionsResponse>`;

describe('classifyOptIn', () => {
  it('opt-in-not-required is available and requires no opt-in', () => {
    expect(classifyOptIn('opt-in-not-required')).toEqual({ optInRequired: false, status: 'AVAILABLE' });
  });

  it('opted-in is available but DID require opting in', () => {
    expect(classifyOptIn('opted-in')).toEqual({ optInRequired: true, status: 'AVAILABLE' });
  });

  /** The state the old catalog could never express. */
  it('not-opted-in is NOT available', () => {
    expect(classifyOptIn('not-opted-in')).toEqual({ optInRequired: true, status: 'NOT_OPTED_IN' });
  });

  /**
   * The load-bearing default. AWS has added region states before. Treating
   * an unrecognised one as AVAILABLE points scans at a region the account
   * cannot reach, and the resulting failures look like a broken connector
   * rather than an unrecognised opt-in state.
   */
  it('an unrecognised status is UNKNOWN, never AVAILABLE', () => {
    const r = classifyOptIn('some-future-aws-state');
    expect(r.status).toBe('UNKNOWN');
    expect(r.status).not.toBe('AVAILABLE');
  });
});

describe('parseDescribeRegions', () => {
  it('extracts every region with its opt-in state', () => {
    const regions = parseDescribeRegions(XML);
    expect(regions.map((r) => r.regionCode)).toEqual(['us-east-1', 'ap-east-1', 'me-south-1']);
    expect(regions.find((r) => r.regionCode === 'ap-east-1')?.status).toBe('NOT_OPTED_IN');
    expect(regions.find((r) => r.regionCode === 'me-south-1')?.optInRequired).toBe(true);
  });

  it('derives partition by AWS prefix convention', () => {
    const gov = parseDescribeRegions('<item><regionName>us-gov-west-1</regionName><optInStatus>opt-in-not-required</optInStatus></item>');
    expect(gov[0].partition).toBe('aws-us-gov');
    const cn = parseDescribeRegions('<item><regionName>cn-north-1</regionName><optInStatus>opt-in-not-required</optInStatus></item>');
    expect(cn[0].partition).toBe('aws-cn');
  });

  /**
   * A region we cannot classify is kept as UNKNOWN rather than dropped.
   * Silently omitting it from the catalog is indistinguishable from AWS not
   * having the region at all.
   */
  it('keeps a region whose optInStatus is missing, as UNKNOWN', () => {
    const regions = parseDescribeRegions('<item><regionName>eu-west-9</regionName></item>');
    expect(regions).toHaveLength(1);
    expect(regions[0].status).toBe('UNKNOWN');
  });

  it('ignores items with no region name rather than emitting a blank region', () => {
    expect(parseDescribeRegions('<item><optInStatus>opted-in</optInStatus></item>')).toEqual([]);
  });

  it('returns nothing for an empty or unparseable body', () => {
    expect(parseDescribeRegions('')).toEqual([]);
    expect(parseDescribeRegions('<Error>AccessDenied</Error>')).toEqual([]);
  });

  /**
   * The current production catalog is 17 rows of UNKNOWN. This asserts the
   * parser produces a genuinely different answer — otherwise the whole
   * exercise would replace one unknown with another.
   */
  it('produces states the observation-seeded catalog could not', () => {
    const states = new Set(parseDescribeRegions(XML).map((r) => r.status));
    expect(states.has('AVAILABLE')).toBe(true);
    expect(states.has('NOT_OPTED_IN')).toBe(true);
  });
});
