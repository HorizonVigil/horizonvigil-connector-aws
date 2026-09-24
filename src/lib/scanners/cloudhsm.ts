import { reportWalk, toIso, walkJsonRpc } from './restJson';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CLOUDHSM_RESOURCE_TYPES = ['cloudhsm_cluster'] as const;

interface Hsm { HsmId?: string; AvailabilityZone?: string; SubnetId?: string; EniIp?: string; State?: string }
export interface Cluster {
  ClusterId: string; State?: string; StateMessage?: string; HsmType?: string; CreateTimestamp?: number; VpcId?: string;
  Hsms?: Hsm[];
  BackupPolicy?: string;
  BackupRetentionPolicy?: { Type?: string; Value?: string };
  SecurityGroup?: string;
  SubnetMapping?: Record<string, string>;
  Mode?: string;
  NetworkType?: string;
  SourceBackupId?: string;
}

/** Evidence for one CloudHSM v2 cluster. Raw createTimestamp is kept for existing consumers. */
export function clusterMetadata(c: Cluster) {
  const hsms = c.Hsms ?? [];
  const azs = [...new Set(hsms.map((h) => h.AvailabilityZone).filter((v): v is string => !!v))];
  return {
    stateMessage: c.StateMessage,
    hsmType: c.HsmType,
    createTimestamp: c.CreateTimestamp,
    createdAtIso: toIso(c.CreateTimestamp),
    hsmCount: hsms.length,
    // A single HSM, or all HSMs in one AZ, is a key-availability risk.
    hsmAvailabilityZones: azs,
    multiAz: azs.length > 1,
    // FIPS vs non-FIPS mode on newer HSM types.
    mode: c.Mode ?? null,
    networkType: c.NetworkType ?? null,
    backupPolicy: c.BackupPolicy ?? null,
    backupRetentionDays: c.BackupRetentionPolicy?.Type === 'DAYS' && c.BackupRetentionPolicy.Value ? Number(c.BackupRetentionPolicy.Value) : null,
    restoredFromBackupId: c.SourceBackupId ?? null,
  };
}

/**
 * CloudHSM v2 clusters (JSON-RPC, target prefix BaldrApiService, signing
 * service "cloudhsm").
 *
 * DescribeClusters is paginated (NextToken); the previous version read one
 * page and returned [] on failure, both of which finalize reads as deletion.
 * It now reads every page and reports an incomplete walk. Each cluster
 * carries HSM placement (multi-AZ), mode, security group and subnets.
 */
export async function scanCloudHsm(ctx: ScannerContext): Promise<ScannedResource[]> {
  const walk = await walkJsonRpc<Cluster>(ctx, {
    service: 'cloudhsm', host: `cloudhsmv2.${ctx.region}.amazonaws.com`,
    target: 'BaldrApiService.DescribeClusters', body: { MaxResults: 25 },
  }, 'Clusters');
  reportWalk(ctx, walk, 'cloudhsm', 'DescribeClusters');

  return walk.items.filter((c) => !!c?.ClusterId).map((c) => ({
    resourceTypeKey: 'cloudhsm_cluster', resourceId: c.ClusterId, region: ctx.region,
    state: c.State,
    metadata: clusterMetadata(c),
    relationships: {
      vpcId: c.VpcId,
      securityGroupId: c.SecurityGroup ?? null,
      subnetIds: Object.values(c.SubnetMapping ?? {}),
    },
  }));
}