import { callJsonApi } from '../awsApi';
import { reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DIRECTCONNECT_RESOURCE_TYPES = ['direct_connect_connection', 'direct_connect_virtual_interface'] as const;

interface Connection {
  connectionId: string; connectionName?: string; connectionState?: string; bandwidth?: string; location?: string; region?: string;
  ownerAccount?: string; partnerName?: string; providerName?: string; awsDevice?: string; awsDeviceV2?: string;
  jumboFrameCapable?: boolean; hasLogicalRedundancy?: string; macSecCapable?: boolean; portEncryptionStatus?: string; encryptionMode?: string;
  lagId?: string; vlan?: number;
}
interface BgpPeer { bgpPeerId?: string; asn?: number; authKey?: string; addressFamily?: string; bgpStatus?: string }
interface VirtualInterface {
  virtualInterfaceId: string; virtualInterfaceName?: string; virtualInterfaceState?: string; connectionId?: string; vlan?: number;
  virtualInterfaceType?: string; ownerAccount?: string; amazonSideAsn?: number; asn?: number; mtu?: number; jumboFrameCapable?: boolean;
  directConnectGatewayId?: string; virtualGatewayId?: string; bgpPeers?: BgpPeer[]; siteLinkEnabled?: boolean;
}

/** Link-security evidence for one connection. */
export function connectionEvidence(c: Connection) {
  return {
    bandwidth: c.bandwidth, location: c.location,
    ownerAccount: c.ownerAccount ?? null,
    partnerName: c.partnerName ?? null,
    providerName: c.providerName ?? null,
    // A connection with no logical redundancy is a single point of failure.
    hasLogicalRedundancy: c.hasLogicalRedundancy ?? null,
    // MACsec: layer-2 encryption of traffic on the link.
    macSecCapable: c.macSecCapable ?? false,
    portEncryptionStatus: c.portEncryptionStatus ?? null,
    encryptionMode: c.encryptionMode ?? null,
    jumboFrameCapable: c.jumboFrameCapable ?? null,
  };
}

/** Evidence for one virtual interface. BGP auth keys are NEVER stored -- only whether one is set. */
export function virtualInterfaceEvidence(vi: VirtualInterface, ownAccount: string | null) {
  const peers = vi.bgpPeers ?? [];
  return {
    vlan: vi.vlan,
    virtualInterfaceType: vi.virtualInterfaceType ?? null,
    // A public VIF advertises routes to AWS public endpoints.
    isPublic: vi.virtualInterfaceType === 'public',
    ownerAccount: vi.ownerAccount ?? null,
    // A hosted VIF owned by another account.
    crossAccount: !!(vi.ownerAccount && ownAccount && vi.ownerAccount !== ownAccount),
    amazonSideAsn: vi.amazonSideAsn ?? null,
    customerAsn: vi.asn ?? null,
    mtu: vi.mtu ?? null,
    bgpPeerCount: peers.length,
    bgpPeersWithoutAuthKey: peers.filter((p) => !p.authKey).length,
    bgpPeerStatuses: peers.map((p) => p.bgpStatus ?? null),
    siteLinkEnabled: vi.siteLinkEnabled ?? false,
  };
}

/**
 * AWS Direct Connect connections and virtual interfaces (JSON-RPC,
 * OvertureService). Neither call paginates -- each returns everything.
 *
 * What changed: a failed DescribeVirtualInterfaces used to be swallowed
 * (every VIF then looked deleted); both failures are now reported, and a
 * failed DescribeConnections no longer skips virtual interfaces. Each
 * resource carries link-security evidence (MACsec, redundancy, public or
 * cross-account VIFs, BGP authentication).
 */
export async function scanDirectConnect(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `directconnect.${ctx.region}.amazonaws.com`;
  const call = (target: string) =>
    callJsonApi(ctx.creds, { service: 'directconnect', region: ctx.region, host, target: `OvertureService.${target}`, body: {} });

  const [connResult, viResult] = await Promise.all([call('DescribeConnections'), call('DescribeVirtualInterfaces')]);
  const out: ScannedResource[] = [];

  const connections = connResult.ok ? ((connResult.body as { connections?: Connection[] })?.connections ?? []) : [];
  if (!connResult.ok) {
    console.error(`Direct Connect DescribeConnections failed in ${ctx.region} (continuing without it): ${connResult.errorMessage ?? connResult.errorCode ?? connResult.status}`);
    reportListingFailure(ctx, { service: 'directconnect', action: 'DescribeConnections', region: ctx.region, httpStatus: connResult.status });
  }
  // The account that owns the connections, for spotting cross-account VIFs.
  const ownAccount = connections.find((c) => c.ownerAccount)?.ownerAccount ?? null;

  for (const c of connections) {
    if (!c?.connectionId) continue;
    out.push({
      resourceTypeKey: 'direct_connect_connection', resourceId: c.connectionId, region: ctx.region, resourceName: c.connectionName,
      state: c.connectionState,
      metadata: connectionEvidence(c),
      relationships: { lagId: c.lagId ?? null },
    });
  }

  if (!viResult.ok) {
    console.error(`Direct Connect DescribeVirtualInterfaces failed in ${ctx.region} (continuing without it): ${viResult.errorMessage ?? viResult.errorCode ?? viResult.status}`);
    reportListingFailure(ctx, { service: 'directconnect', action: 'DescribeVirtualInterfaces', region: ctx.region, httpStatus: viResult.status });
  }
  for (const vi of (viResult.ok ? (viResult.body as { virtualInterfaces?: VirtualInterface[] })?.virtualInterfaces : []) ?? []) {
    if (!vi?.virtualInterfaceId) continue;
    out.push({
      resourceTypeKey: 'direct_connect_virtual_interface', resourceId: vi.virtualInterfaceId, region: ctx.region, resourceName: vi.virtualInterfaceName,
      state: vi.virtualInterfaceState,
      metadata: virtualInterfaceEvidence(vi, ownAccount),
      relationships: {
        connectionId: vi.connectionId,
        directConnectGatewayId: vi.directConnectGatewayId ?? null,
        virtualGatewayId: vi.virtualGatewayId ?? null,
      },
    });
  }
  return out;
}