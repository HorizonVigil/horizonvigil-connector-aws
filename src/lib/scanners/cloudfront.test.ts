import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * CloudFront had no test file at all, which is how this bug shipped and how
 * the fix for it was then lost again when a branch was superseded: reverting
 * the one-line fix broke nothing in a 1,092-test suite.
 *
 * THE BUG. `listAll` narrowed each page to its `<Items>` block before pulling
 * item elements out of it:
 *
 *     extractListItems(extractSection(list, 'Items'), itemTag)
 *
 * `extractSection` is NOT nesting-aware -- it slices to the FIRST matching
 * close tag, and its own docstring limits it to container tags "none of which
 * recurse into themselves". CloudFront's `<Items>` recurses: a
 * DistributionSummary contains `<Aliases><Items>`, `<Origins><Items>` and
 * `<CacheBehaviors><Items>`. So the slice ran from the list's own `<Items>`
 * to the `</Items>` closing *Aliases*, cutting the summary in half. The
 * depth-aware item reader then saw an opening `<DistributionSummary>` that
 * never closed and returned nothing.
 *
 * Every distribution carrying an alias or a second origin vanished from
 * inventory -- and a scan reporting fewer distributions than exist looks
 * exactly like an account that owns fewer distributions.
 */
const fetchTextMock = vi.fn();
vi.mock('./scannerSupport', async (importOriginal: () => Promise<Record<string, unknown>>) => ({
  ...(await importOriginal()),
  fetchText: (...args: unknown[]) => fetchTextMock(...args),
}));

import { scanCloudFront } from './cloudfront';
import type { ScannedResource, ScannerContext } from './types';

const ctx = { creds: { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' }, region: 'us-east-1' } as unknown as ScannerContext;

const ok = (text: string) =>
  Promise.resolve({ ok: true, status: 200, headers: new Headers(), text });

/**
 * A DistributionSummary shaped the way the real API returns one: nested
 * `<Items>` inside Aliases and Origins, which is the whole point of the
 * fixture. A summary with no nested Items would pass under the bug too.
 */
const aliasedSummary = `
    <DistributionSummary>
      <Id>E1ALIASED</Id>
      <ARN>arn:aws:cloudfront::111122223333:distribution/E1ALIASED</ARN>
      <Status>Deployed</Status>
      <DomainName>d111111abcdef8.cloudfront.net</DomainName>
      <Aliases>
        <Quantity>2</Quantity>
        <Items>
          <CNAME>www.example.com</CNAME>
          <CNAME>cdn.example.com</CNAME>
        </Items>
      </Aliases>
      <Origins>
        <Quantity>2</Quantity>
        <Items>
          <Origin>
            <Id>s3-origin</Id>
            <DomainName>assets.s3.amazonaws.com</DomainName>
            <S3OriginConfig><OriginAccessIdentity></OriginAccessIdentity></S3OriginConfig>
          </Origin>
          <Origin>
            <Id>custom-origin</Id>
            <DomainName>api.example.com</DomainName>
            <CustomOriginConfig>
              <OriginProtocolPolicy>https-only</OriginProtocolPolicy>
              <OriginSslProtocols><Quantity>1</Quantity><Items><SslProtocol>TLSv1.2</SslProtocol></Items></OriginSslProtocols>
            </CustomOriginConfig>
          </Origin>
        </Items>
      </Origins>
      <DefaultCacheBehavior><ViewerProtocolPolicy>redirect-to-https</ViewerProtocolPolicy></DefaultCacheBehavior>
      <ViewerCertificate>
        <CloudFrontDefaultCertificate>false</CloudFrontDefaultCertificate>
        <MinimumProtocolVersion>TLSv1.2_2021</MinimumProtocolVersion>
      </ViewerCertificate>
      <WebACLId>arn:aws:wafv2::111122223333:global/webacl/prod/abc</WebACLId>
      <Enabled>true</Enabled>
    </DistributionSummary>`;

/** No nested Items at all -- survives even the buggy narrowing. */
const plainSummary = `
    <DistributionSummary>
      <Id>E2PLAIN</Id>
      <ARN>arn:aws:cloudfront::111122223333:distribution/E2PLAIN</ARN>
      <Status>Deployed</Status>
      <DomainName>d222222abcdef8.cloudfront.net</DomainName>
      <Enabled>false</Enabled>
    </DistributionSummary>`;

const distributionList = (summaries: string, opts: { truncated?: boolean; nextMarker?: string } = {}) => `
<DistributionList xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/">
  <Marker></Marker>
  <MaxItems>100</MaxItems>
  <IsTruncated>${opts.truncated ? 'true' : 'false'}</IsTruncated>
  ${opts.nextMarker ? `<NextMarker>${opts.nextMarker}</NextMarker>` : ''}
  <Quantity>2</Quantity>
  <Items>${summaries}
  </Items>
</DistributionList>`;

const emptyOais = `
<CloudFrontOriginAccessIdentityList>
  <IsTruncated>false</IsTruncated><Quantity>0</Quantity><Items></Items>
</CloudFrontOriginAccessIdentityList>`;

/** Routes by URL path, because scanCloudFront walks two lists concurrently. */
function serve(pages: { distributions: string[]; oais?: string }) {
  let distCall = 0;
  fetchTextMock.mockImplementation((_client: unknown, url: string) => {
    if (String(url).includes('/origin-access-identity/')) return ok(pages.oais ?? emptyOais);
    const body = pages.distributions[Math.min(distCall, pages.distributions.length - 1)];
    distCall += 1;
    return ok(body);
  });
}

const ofType = (out: ScannedResource[], t: string) => out.filter((r) => r.resourceTypeKey === t);

beforeEach(() => { fetchTextMock.mockReset(); });

describe('scanCloudFront inventory is not truncated by nested <Items>', () => {
  it('returns a distribution that carries aliases and a second origin', async () => {
    serve({ distributions: [distributionList(aliasedSummary + plainSummary)] });
    const out = await scanCloudFront(ctx);

    // Under the bug this array was EMPTY -- both summaries were lost, because
    // the truncation happened inside the first one and took the rest of the
    // page with it.
    expect(ofType(out, 'cloudfront_distribution').map((r) => r.resourceId)).toEqual(['E1ALIASED', 'E2PLAIN']);
  });

  it('keeps the whole summary, not a truncated shell of it', async () => {
    serve({ distributions: [distributionList(aliasedSummary)] });
    const out = await scanCloudFront(ctx);
    const dist = ofType(out, 'cloudfront_distribution')[0];

    // Returning the row but losing everything after the first </Items> would
    // be the same defect wearing a different result: present in the count,
    // wrong in the evidence.
    expect(dist.metadata?.aliases).toEqual(['www.example.com', 'cdn.example.com']);
    expect((dist.metadata?.origins as { id: string }[]).map((o) => o.id)).toEqual(['s3-origin', 'custom-origin']);
    expect(dist.metadata?.minimumProtocolVersion).toBe('TLSv1.2_2021');
    expect(dist.metadata?.webAclId).toBe('arn:aws:wafv2::111122223333:global/webacl/prod/abc');
    expect(dist.resourceName).toBe('d111111abcdef8.cloudfront.net');
    expect(dist.state).toBe('Deployed');
  });

  /**
   * `enabled` is read from `withoutSections(top, DISTRIBUTION_NESTED)`
   * precisely because the first `<Enabled>` in the raw XML belongs to
   * DefaultCacheBehavior/TrustedSigners. Pinned here so a future simplification
   * of that call cannot quietly start reporting the wrong field.
   */
  it('reads Enabled from the distribution, not from a nested section', async () => {
    serve({ distributions: [distributionList(aliasedSummary + plainSummary)] });
    const out = await scanCloudFront(ctx);
    const byId = new Map(ofType(out, 'cloudfront_distribution').map((r) => [r.resourceId, r]));
    expect(byId.get('E1ALIASED')?.metadata?.enabled).toBe(true);
    expect(byId.get('E2PLAIN')?.metadata?.enabled).toBe(false);
  });

  /**
   * IsTruncated and NextMarker are read from the list with its Items stripped,
   * so a `<NextMarker>` occurring inside an item cannot drive the walk. The
   * pagination lines sit immediately beside the fixed line and had no coverage
   * either.
   */
  it('follows NextMarker across pages and stops when the walk completes', async () => {
    serve({
      distributions: [
        distributionList(aliasedSummary, { truncated: true, nextMarker: 'PAGE2' }),
        distributionList(plainSummary),
      ],
    });
    const out = await scanCloudFront(ctx);
    expect(ofType(out, 'cloudfront_distribution').map((r) => r.resourceId)).toEqual(['E1ALIASED', 'E2PLAIN']);
  });

  /**
   * The security-relevant half of the same defect. `originsWithDeprecatedTls`,
   * `originsAllowingHttp` and `s3OriginsWithoutAccessControl` are counts over
   * the origins array, so a list silently cut short does not merely lose
   * evidence -- it reports zero findings on a distribution that has them. The
   * offending origin is deliberately LAST, and the one before it carries the
   * nested `<Items>` that used to end the slice.
   */
  it('counts a deprecated-TLS origin that sits after a nested <Items>', async () => {
    const withDeprecated = `
    <DistributionSummary>
      <Id>E4TLS</Id>
      <Status>Deployed</Status>
      <DomainName>d444444abcdef8.cloudfront.net</DomainName>
      <Origins>
        <Quantity>2</Quantity>
        <Items>
          <Origin>
            <Id>modern</Id><DomainName>ok.example.com</DomainName>
            <CustomOriginConfig>
              <OriginProtocolPolicy>https-only</OriginProtocolPolicy>
              <OriginSslProtocols><Quantity>1</Quantity><Items><SslProtocol>TLSv1.2</SslProtocol></Items></OriginSslProtocols>
            </CustomOriginConfig>
          </Origin>
          <Origin>
            <Id>legacy</Id><DomainName>old.example.com</DomainName>
            <CustomOriginConfig>
              <OriginProtocolPolicy>http-only</OriginProtocolPolicy>
              <OriginSslProtocols><Quantity>1</Quantity><Items><SslProtocol>TLSv1</SslProtocol></Items></OriginSslProtocols>
            </CustomOriginConfig>
          </Origin>
        </Items>
      </Origins>
      <Enabled>true</Enabled>
    </DistributionSummary>`;

    serve({ distributions: [distributionList(withDeprecated)] });
    const dist = ofType(await scanCloudFront(ctx), 'cloudfront_distribution')[0];

    expect((dist.metadata?.origins as { id: string }[]).map((o) => o.id)).toEqual(['modern', 'legacy']);
    // Both were 0 before the fix: the finding existed and the scan denied it.
    expect(dist.metadata?.originsWithDeprecatedTls).toBe(1);
    expect(dist.metadata?.originsAllowingHttp).toBe(1);
  });

  it('reads origin access identities from their own list', async () => {
    serve({
      distributions: [distributionList(plainSummary)],
      oais: `
<CloudFrontOriginAccessIdentityList>
  <IsTruncated>false</IsTruncated>
  <Quantity>1</Quantity>
  <Items>
    <CloudFrontOriginAccessIdentitySummary>
      <Id>E3OAI</Id>
      <S3CanonicalUserId>abc123canonical</S3CanonicalUserId>
      <Comment>legacy private s3 origin</Comment>
    </CloudFrontOriginAccessIdentitySummary>
  </Items>
</CloudFrontOriginAccessIdentityList>`,
    });
    const out = await scanCloudFront(ctx);
    const oai = ofType(out, 'cloudfront_oai')[0];
    expect(oai.resourceId).toBe('E3OAI');
    expect(oai.metadata?.s3CanonicalUserId).toBe('abc123canonical');
    expect(oai.resourceName).toBe('legacy private s3 origin');
  });
});
