import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DIRECTCONNECT_RESOURCE_TYPES = ['direct_connect_connection', 'direct_connect_virtual_interface'] as const;

interface Connection { connectionId: string; connectionName?: string; connectionState?: string; bandwidth?: string; location?: string; region?: string }
interface DescribeConnectionsResponse { connections?: Connection[] }
interface VirtualInterface { virtualInterfaceId: string; virtualInterfaceName?: string; virtualInterfaceState?: string; connectionId?: string; vlan?: number }
interface DescribeVirtualInterfacesResponse { virtualInterfaces?: VirtualInterface[] }

/** AWS Direct Connect — target prefix (OvertureService) confirmed against AWS's API reference element-ID anchors ("DX-..."), API version 2012-10-25. */
export async function scanDirectConnect(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `directconnect.${ctx.region}.amazonaws.com`;
  const call = async (target: string, body: Record<string, unknown> = {}) =>
    callJsonApi(ctx.creds, { service: 'directconnect', region: ctx.region, host, target: `OvertureService.${target}`, body });

  const out: ScannedResource[] = [];

  const connResult = await call('DescribeConnections');
  if (!connResult.ok) {
    console.error(`Direct Connect DescribeConnections failed in ${ctx.region} (continuing without it): ${connResult.errorMessage ?? connResult.errorCode ?? connResult.status}`);
    return out;
  }
  for (const c of (connResult.body as DescribeConnectionsResponse).connections ?? []) {
    out.push({
      resourceTypeKey: 'direct_connect_connection', resourceId: c.connectionId, region: ctx.region, resourceName: c.connectionName,
      state: c.connectionState, metadata: { bandwidth: c.bandwidth, location: c.location },
    });
  }

  const viResult = await call('DescribeVirtualInterfaces');
  for (const vi of (viResult.ok ? (viResult.body as DescribeVirtualInterfacesResponse).virtualInterfaces : []) ?? []) {
    out.push({
      resourceTypeKey: 'direct_connect_virtual_interface', resourceId: vi.virtualInterfaceId, region: ctx.region, resourceName: vi.virtualInterfaceName,
      state: vi.virtualInterfaceState, metadata: { vlan: vi.vlan }, relationships: { connectionId: vi.connectionId },
    });
  }

  return out;
}
