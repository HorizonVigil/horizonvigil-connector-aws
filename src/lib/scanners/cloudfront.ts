import { createAwsClient } from '../awsApi';
import { extractSection, extractListItems, field, boolField } from '../xmlList';
import { fetchText, reportListingFailure, snippet } from './scannerSupport';
import { withoutSections } from './xmlShape';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CLOUDFRONT_RESOURCE_TYPES = ['cloudfront_distribution', 'cloudfront_oai'] as const;

const API = 'https://cloudfront.amazonaws.com/2020-05-31';
const PAGE_SIZE = 100;
const MAX_PAGES = 50;

/** Nested sections of a DistributionSummary whose children reuse top-level names. */
const DISTRIBUTION_NESTED = [
  'Aliases', 'Origins', 'OriginGroups', 'DefaultCacheBehavior', 'CacheBehaviors',
  'CustomErrorResponses', 'ViewerCertificate', 'Restrictions', 'AliasICPRecordals',
];

/** `<Section><Quantity/><Items><Tag>…</Tag></Items></Section>` → the Tag items. */
const itemsOf = (xml: string | null, tag: string): string[] =>
  extractListItems(extractSection(xml ?? '', 'Items'), tag);

/** Security evidence for one distribution. */
export function distributionEvidence(dist: string) {
  const top = withoutSections(dist, DISTRIBUTION_NESTED);
  const viewerCert = extractSection(dist, 'ViewerCertificate') ?? '';
  const defaultBehavior = extractSection(dist, 'DefaultCacheBehavior') ?? '';
  const behaviors = itemsOf(extractSection(dist, 'CacheBehaviors'), 'CacheBehavior');
  const originsXml = itemsOf(extractSection(dist, 'Origins'), 'Origin');
  const geo = extractSection(extractSection(dist, 'Restrictions') ?? '', 'GeoRestriction') ?? '';

  const viewerPolicies = [field(defaultBehavior, 'ViewerProtocolPolicy'), ...behaviors.map((b) => field(b, 'ViewerProtocolPolicy'))]
    .filter((v): v is string => !!v);

  const origins = originsXml.map((o) => {
    const s3 = extractSection(o, 'S3OriginConfig');
    const custom = extractSection(o, 'CustomOriginConfig');
    return {
      id: field(o, 'Id'),
      domainName: field(o, 'DomainName'),
      kind: s3 !== null ? 's3' : custom !== null ? 'custom' : 'unknown',
      originAccessControlId: field(o, 'OriginAccessControlId') || null,
      originAccessIdentity: s3 !== null ? (field(s3, 'OriginAccessIdentity') || null) : null,
      originProtocolPolicy: custom !== null ? field(custom, 'OriginProtocolPolicy') : null,
      originSslProtocols: custom !== null ? itemsOf(extractSection(custom, 'OriginSslProtocols'), 'SslProtocol').map((p) => p.trim()) : [],
    };
  });

  return {
    metadata: {
      arn: field(top, 'ARN'),
      // Read from the distribution itself: the old code's first <Enabled>
      // was DefaultCacheBehavior/TrustedSigners/Enabled.
      enabled: boolField(top, 'Enabled'),
      comment: field(top, 'Comment'),
      priceClass: field(top, 'PriceClass'),
      lastModifiedTime: field(top, 'LastModifiedTime'),
      httpVersion: field(top, 'HttpVersion'),
      ipv6Enabled: boolField(top, 'IsIPV6Enabled') ?? null,
      staging: boolField(top, 'Staging') ?? null,
      aliases: itemsOf(extractSection(dist, 'Aliases'), 'CNAME').map((a) => a.trim()),
      // FSBP CloudFront.6: associated with AWS WAF.
      webAclId: field(top, 'WebACLId') || null,
      // FSBP CloudFront.3/.10: HTTPS to viewers and origins.
      viewerProtocolPolicies: [...new Set(viewerPolicies)],
      allowsHttpToViewers: viewerPolicies.includes('allow-all'),
      // FSBP CloudFront.7/.8: custom certificate, SNI, modern TLS.
      usesDefaultCertificate: boolField(viewerCert, 'CloudFrontDefaultCertificate') ?? null,
      minimumProtocolVersion: field(viewerCert, 'MinimumProtocolVersion'),
      sslSupportMethod: field(viewerCert, 'SSLSupportMethod'),
      acmCertificateArn: field(viewerCert, 'ACMCertificateArn'),
      geoRestrictionType: field(geo, 'RestrictionType'),
      origins,
      // FSBP CloudFront.13: S3 origins should use Origin Access Control.
      s3OriginsWithoutAccessControl: origins.filter((o) => o.kind === 's3' && !o.originAccessControlId && !o.originAccessIdentity).length,
      originsAllowingHttp: origins.filter((o) => o.originProtocolPolicy === 'http-only' || o.originProtocolPolicy === 'match-viewer').length,
      originsWithDeprecatedTls: origins.filter((o) => o.originSslProtocols.some((p) => p === 'SSLv3' || p === 'TLSv1' || p === 'TLSv1.1')).length,
    },
    relationships: {
      webAclId: field(top, 'WebACLId') || null,
      acmCertificateArn: field(viewerCert, 'ACMCertificateArn'),
      originDomainNames: origins.map((o) => o.domainName).filter((v): v is string => !!v),
    },
  };
}

/**
 * Walks a CloudFront list (Marker / NextMarker / IsTruncated). Never throws.
 * Returns the raw item XML and whether the walk completed.
 */
async function listAll(client: ReturnType<typeof createAwsClient>, path: string, listTag: string, itemTag: string) {
  const items: string[] = [];
  const seen = new Set<string>();
  let marker: string | null = null;
  for (let page = 0; page < MAX_PAGES; page++) {
    const url = `${API}${path}?MaxItems=${PAGE_SIZE}${marker ? `&Marker=${encodeURIComponent(marker)}` : ''}`;
    const res = await fetchText(client, url, { method: 'GET' });
    if (!res.ok) return { items, complete: false, firstPageFailed: page === 0, status: res.status, error: res.error ?? snippet(res.text) };
    const list = extractSection(res.text, listTag) ?? res.text;
    // The list's own <Items> precedes any nested one, so this is the top-level list.
    items.push(...extractListItems(extractSection(list, 'Items'), itemTag));
    const truncated = field(withoutSections(list, ['Items']), 'IsTruncated') === 'true';
    const next = field(withoutSections(list, ['Items']), 'NextMarker');
    if (!truncated || !next) return { items, complete: true, firstPageFailed: false };
    if (seen.has(next)) return { items, complete: false, firstPageFailed: false, error: 'repeated NextMarker' };
    seen.add(next);
    marker = next;
  }
  return { items, complete: false, firstPageFailed: false, error: `page cap ${MAX_PAGES} reached` };
}

/**
 * CloudFront — REST-XML, global (GLOBAL_SCANNERS), signed against us-east-1.
 *
 * What changed, and why:
 *  - `enabled` was WRONG for most distributions. The regex reader returns
 *    the first <Enabled> anywhere, and DefaultCacheBehavior/TrustedSigners/
 *    Enabled comes before the distribution's own. Top-level fields are now
 *    read with nested sections stripped.
 *  - Both lists paginate (Marker/NextMarker; 100 per page), and failures are
 *    reported rather than returned as [] -- which finalize read as deletions.
 *  - Edge-security evidence: WAF association, viewer and origin protocol
 *    policies, certificate and minimum TLS version, S3 origins without
 *    OAC/OAI, deprecated origin TLS, geo restriction. (Access logging is not
 *    in the list summary; it needs GetDistributionConfig per distribution.)
 */
export async function scanCloudFront(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'cloudfront', 'us-east-1');
  const [dists, oais] = await Promise.all([
    listAll(client, '/distribution', 'DistributionList', 'DistributionSummary'),
    listAll(client, '/origin-access-identity/cloudfront', 'CloudFrontOriginAccessIdentityList', 'CloudFrontOriginAccessIdentitySummary'),
  ]);
  for (const [action, w] of [['ListDistributions', dists], ['ListCloudFrontOriginAccessIdentities', oais]] as const) {
    if (w.complete) continue;
    console.error(`CloudFront ${action} ${w.firstPageFailed ? 'failed' : 'was incomplete'} (continuing with what was read): ${'error' in w ? w.error : ''}`);
    reportListingFailure(ctx, w.firstPageFailed
      ? { service: 'cloudfront', action, region: 'us-east-1', httpStatus: 'status' in w ? w.status : undefined }
      : { service: 'cloudfront', action, region: 'us-east-1', truncated: true });
  }

  const out: ScannedResource[] = [];
  for (const dist of dists.items) {
    const top = withoutSections(dist, DISTRIBUTION_NESTED);
    const id = field(top, 'Id');
    if (!id) continue;
    const evidence = distributionEvidence(dist);
    out.push({
      resourceTypeKey: 'cloudfront_distribution', resourceId: id, region: null,
      resourceName: field(top, 'DomainName') ?? undefined, state: field(top, 'Status') ?? undefined,
      metadata: evidence.metadata,
      relationships: evidence.relationships,
    });
  }

  // Origin Access Identity — the legacy (pre-2022) mechanism for private S3
  // origins, superseded by Origin Access Control but still widely in use.
  for (const oai of oais.items) {
    const id = field(oai, 'Id');
    if (!id) continue;
    out.push({
      resourceTypeKey: 'cloudfront_oai', resourceId: id, region: null,
      resourceName: field(oai, 'Comment') ?? undefined, metadata: { s3CanonicalUserId: field(oai, 'S3CanonicalUserId') },
    });
  }
  return out;
}