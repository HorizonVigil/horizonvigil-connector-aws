import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SERVICEDISCOVERY_RESOURCE_TYPES = ['cloud_map_namespace'] as const;

interface NamespaceSummary { Id: string; Arn?: string; Name?: string; Type?: string; ServiceCount?: number }
interface ListNamespacesResponse { Namespaces?: NamespaceSummary[] }

/** AWS Cloud Map — target prefix (Route53AutoNaming_v20170314) reflects Cloud Map's original "Route 53 Auto Naming" internal name. */
export async function scanServiceDiscovery(ctx: ScannerContext): Promise<ScannedResource[]> {
  const result = await callJsonApi(ctx.creds, {
    service: 'servicediscovery', region: ctx.region, host: `servicediscovery.${ctx.region}.amazonaws.com`,
    target: 'Route53AutoNaming_v20170314.ListNamespaces', body: {},
  });
  if (!result.ok) {
    console.error(`Cloud Map ListNamespaces failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const namespaces = (result.body as ListNamespacesResponse).Namespaces ?? [];
  return namespaces.map((n) => ({
    resourceTypeKey: 'cloud_map_namespace', resourceId: n.Arn ?? n.Id, region: ctx.region, resourceName: n.Name,
    metadata: { type: n.Type, serviceCount: n.ServiceCount },
  }));
}
