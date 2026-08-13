import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const STORAGEGATEWAY_RESOURCE_TYPES = ['storage_gateway_gateway'] as const;

interface GatewayInfo { GatewayARN: string; GatewayId?: string; GatewayName?: string; GatewayType?: string; GatewayOperationalState?: string; Ec2InstanceId?: string }
interface ListGatewaysResponse { Gateways?: GatewayInfo[] }

export async function scanStorageGateway(ctx: ScannerContext): Promise<ScannedResource[]> {
  const result = await callJsonApi(ctx.creds, {
    service: 'storagegateway', region: ctx.region, host: `storagegateway.${ctx.region}.amazonaws.com`,
    target: 'StorageGateway_20130630.ListGateways', body: {},
  });
  if (!result.ok) {
    console.error(`Storage Gateway ListGateways failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const gateways = (result.body as ListGatewaysResponse).Gateways ?? [];
  return gateways.map((g) => ({
    resourceTypeKey: 'storage_gateway_gateway', resourceId: g.GatewayARN, region: ctx.region, resourceName: g.GatewayName,
    state: g.GatewayOperationalState, metadata: { type: g.GatewayType }, relationships: { ec2InstanceId: g.Ec2InstanceId },
  }));
}
