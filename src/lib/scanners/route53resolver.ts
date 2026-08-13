import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ROUTE53RESOLVER_RESOURCE_TYPES = ['route53_resolver_endpoint'] as const;

interface ResolverEndpoint { Id: string; Arn?: string; Name?: string; Direction?: string; Status?: string; VpcId?: string; IpAddressCount?: number }
interface ListResolverEndpointsResponse { ResolverEndpoints?: ResolverEndpoint[] }

export async function scanRoute53Resolver(ctx: ScannerContext): Promise<ScannedResource[]> {
  const result = await callJsonApi(ctx.creds, {
    service: 'route53resolver', region: ctx.region, host: `route53resolver.${ctx.region}.amazonaws.com`,
    target: 'Route53Resolver.ListResolverEndpoints', body: {},
  });
  if (!result.ok) {
    console.error(`Route 53 Resolver ListResolverEndpoints failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const endpoints = (result.body as ListResolverEndpointsResponse).ResolverEndpoints ?? [];
  return endpoints.map((e) => ({
    resourceTypeKey: 'route53_resolver_endpoint', resourceId: e.Arn ?? e.Id, region: ctx.region, resourceName: e.Name,
    state: e.Status, metadata: { direction: e.Direction, ipAddressCount: e.IpAddressCount }, relationships: { vpcId: e.VpcId },
  }));
}
