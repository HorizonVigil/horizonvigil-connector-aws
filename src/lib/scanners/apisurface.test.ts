import { beforeEach, describe, expect, it, vi } from 'vitest';

/** API Gateway, AppSync and CloudFront — the internet-facing API surface. */
const fetchMock = vi.fn();
vi.mock('aws4fetch', () => ({
  AwsClient: class {
    fetch(url: string, init?: RequestInit) {
      return fetchMock(url, init);
    }
  },
}));

import { scanApiGateway } from './apigateway';
import { scanAppSync } from './appsync';
import { distributionEvidence, scanCloudFront } from './cloudfront';

type Failure = { action?: string };

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ctx = { creds, region: 'eu-west-1' };
const json = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status }));
const xml = (body: string, status = 200) => Promise.resolve(new Response(body, { status }));

beforeEach(() => { fetchMock.mockReset(); });

describe('API Gateway', () => {
  function serve() {
    fetchMock.mockImplementation((url: string) => {
      if (url.includes('/restapis?')) {
        return url.includes('position=p2')
          ? json({ item: [{ id: 'rest-2', name: 'b', endpointConfiguration: { types: ['PRIVATE'] } }] })
          : json({ item: [{ id: 'rest-1', name: 'a', endpointConfiguration: { types: ['EDGE'] }, policy: JSON.stringify({ Statement: [{ Effect: 'Allow', Principal: '*', Action: 'execute-api:Invoke' }] }) }], position: 'p2' });
      }
      if (url.includes('/restapis/rest-1/stages')) return json({ item: [{ stageName: 'prod', methodSettings: { '*/*': { loggingLevel: 'INFO', dataTraceEnabled: true } } }] });
      if (url.includes('/restapis/')) return json({ item: [] });
      // v2: the WIRE format is camelCase.
      if (url.includes('/v2/apis?')) {
        return json({ items: [
          { apiId: 'http-1', name: 'h', protocolType: 'HTTP', corsConfiguration: { allowOrigins: ['*'] } },
          { apiId: 'ws-1', name: 'w', protocolType: 'WEBSOCKET' },
        ] });
      }
      if (url.includes('/v2/apis/http-1/routes')) return json({ items: [{ routeKey: 'GET /public', authorizationType: 'NONE' }, { routeKey: 'GET /me', authorizationType: 'JWT' }] });
      if (url.includes('/v2/apis/')) return json({ items: [] });
      return json({}, 404);
    });
  }

  it('gives HTTP and WebSocket APIs their real identity and type (camelCase wire format)', async () => {
    serve();
    const out = await scanApiGateway(ctx);
    expect(out.find((r) => r.resourceId === 'http-1')?.resourceTypeKey).toBe('apigateway_http_api');
    expect(out.find((r) => r.resourceId === 'ws-1')?.resourceTypeKey).toBe('apigateway_websocket_api');
  });

  it('reads every page of REST APIs (position)', async () => {
    serve();
    const rest = (await scanApiGateway(ctx)).filter((r) => r.resourceTypeKey === 'apigateway_rest_api');
    expect(rest.map((r) => r.resourceId)).toEqual(['rest-1', 'rest-2']);
    expect(rest[1].metadata?.isPrivate).toBe(true);
  });

  it('records a public resource policy, stage logging and full data tracing', async () => {
    serve();
    const rest1 = (await scanApiGateway(ctx)).find((r) => r.resourceId === 'rest-1');
    expect(rest1?.metadata).toMatchObject({ resourcePolicy: { allowsAnonymous: true }, stagesCollected: true });
    expect((rest1?.metadata?.stages as unknown[])[0]).toMatchObject({ stageName: 'prod', loggingLevel: 'INFO', dataTraceEnabled: true, webAclArn: null });
  });

  it('counts HTTP API routes with NO authorization, and wildcard CORS', async () => {
    serve();
    const http = (await scanApiGateway(ctx)).find((r) => r.resourceId === 'http-1');
    expect(http?.metadata).toMatchObject({ routeCount: 2, unauthenticatedRouteCount: 1, unauthenticatedRouteKeys: ['GET /public'], corsAllowsAnyOrigin: true });
  });

  it('reports a failed list', async () => {
    const failures: Failure[] = [];
    fetchMock.mockImplementation(() => json({}, 403));
    await scanApiGateway({ creds: { ...creds, onCallFailure: (f: Failure) => failures.push(f) }, region: 'eu-west-1' });
    expect(failures.map((f) => f.action)).toEqual(expect.arrayContaining(['GetApis', 'GetRestApis']));
  });
});

describe('AppSync', () => {
  it('reads past the 25-API first page', async () => {
    fetchMock.mockImplementation((url: string) => (url.includes('nextToken=t2')
      ? json({ graphqlApis: [{ apiId: 'g2', name: 'b' }] })
      : json({ graphqlApis: [{ apiId: 'g1', name: 'a', authenticationType: 'API_KEY' }], nextToken: 't2' })));
    const out = await scanAppSync(ctx);
    expect(out.map((r) => r.resourceId)).toEqual(['g1', 'g2']);
    expect(out[0].metadata).toMatchObject({ usesApiKeyAuth: true, introspectionEnabled: true, wafProtected: false });
  });

  it('no longer gives id-less APIs a shared placeholder identity', async () => {
    fetchMock.mockImplementation(() => json({ graphqlApis: [{ name: 'x' }, { name: 'y' }] }));
    const out = await scanAppSync(ctx);
    expect(out.every((r) => r.resourceId === '')).toBe(true);
    expect(out.some((r) => r.resourceId.includes('unknown'))).toBe(false);
  });
});

describe('CloudFront', () => {
  /** A distribution whose TrustedSigners/Enabled=false precedes its own Enabled=true. */
  const summary = (id: string) =>
    `<Id>${id}</Id><ARN>arn:aws:cloudfront::1:distribution/${id}</ARN><Status>Deployed</Status><DomainName>${id}.cloudfront.net</DomainName>` +
    `<Aliases><Quantity>1</Quantity><Items><CNAME>www.example.com</CNAME></Items></Aliases>` +
    `<Origins><Quantity>1</Quantity><Items><Origin><Id>s3</Id><DomainName>b.s3.amazonaws.com</DomainName><OriginPath/><S3OriginConfig><OriginAccessIdentity/></S3OriginConfig><OriginAccessControlId/></Origin></Items></Origins>` +
    `<DefaultCacheBehavior><TargetOriginId>s3</TargetOriginId><TrustedSigners><Enabled>false</Enabled><Quantity>0</Quantity></TrustedSigners><ViewerProtocolPolicy>allow-all</ViewerProtocolPolicy></DefaultCacheBehavior>` +
    `<CacheBehaviors><Quantity>0</Quantity></CacheBehaviors><Comment>site</Comment><PriceClass>PriceClass_All</PriceClass><Enabled>true</Enabled>` +
    `<ViewerCertificate><CloudFrontDefaultCertificate>true</CloudFrontDefaultCertificate><MinimumProtocolVersion>TLSv1</MinimumProtocolVersion></ViewerCertificate>` +
    `<Restrictions><GeoRestriction><RestrictionType>none</RestrictionType><Quantity>0</Quantity></GeoRestriction></Restrictions><WebACLId></WebACLId>`;

  const listSummary = (id: string) => `<Id>${id}</Id><ARN>arn:aws:cloudfront::1:distribution/${id}</ARN><Status>Deployed</Status><DomainName>${id}.cloudfront.net</DomainName><Enabled>true</Enabled>`;

  it('reads the distribution\'s OWN Enabled flag, not TrustedSigners/Enabled', () => {
    expect(distributionEvidence(summary('E1')).metadata.enabled).toBe(true);
  });

  it('records HTTP-allowed viewers, default certificate, no WAF, and an S3 origin without OAC/OAI', () => {
    const md = distributionEvidence(summary('E1')).metadata;
    expect(md).toMatchObject({ allowsHttpToViewers: true, usesDefaultCertificate: true, webAclId: null, s3OriginsWithoutAccessControl: 1, aliases: ['www.example.com'] });
  });

  it('follows NextMarker across pages and reports a failed OAI list', async () => {
    const failures: Failure[] = [];
    fetchMock.mockImplementation((url: string) => {
      if (url.includes('/distribution')) {
        return url.includes('Marker=m2')
          ? xml(`<DistributionList><IsTruncated>false</IsTruncated><Items><DistributionSummary>${listSummary('E2')}</DistributionSummary></Items></DistributionList>`)
          : xml(`<DistributionList><IsTruncated>true</IsTruncated><NextMarker>m2</NextMarker><Items><DistributionSummary>${listSummary('E1')}</DistributionSummary></Items></DistributionList>`);
      }
      return xml('<Error/>', 403);
    });
    const out = await scanCloudFront({ creds: { ...creds, onCallFailure: (f: Failure) => failures.push(f) }, region: 'us-east-1' });
    expect(out.map((r) => r.resourceId)).toEqual(['E1', 'E2']);
    expect(failures.some((f) => f.action === 'ListCloudFrontOriginAccessIdentities')).toBe(true);
  });
});