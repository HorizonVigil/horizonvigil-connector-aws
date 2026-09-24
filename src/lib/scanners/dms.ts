import { reportWalk, toIso, walkJsonRpc } from './restJson';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AmazonDMSv20160101';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DMS_RESOURCE_TYPES = ['dms_replication_instance', 'dms_replication_task'] as const;

export interface ReplicationInstance {
  ReplicationInstanceArn: string;
  ReplicationInstanceIdentifier: string;
  ReplicationInstanceClass?: string;
  ReplicationInstanceStatus?: string;
  EngineVersion?: string;
  AvailabilityZone?: string;
  MultiAZ?: boolean;
  PubliclyAccessible?: boolean;
  AllocatedStorage?: number;
  InstanceCreateTime?: number;
  KmsKeyId?: string;
  AutoMinorVersionUpgrade?: boolean;
  NetworkType?: string;
  VpcSecurityGroups?: { VpcSecurityGroupId?: string }[];
  ReplicationSubnetGroup?: { VpcId?: string; Subnets?: { SubnetIdentifier?: string }[] };
}
export interface ReplicationTask {
  ReplicationTaskArn: string;
  ReplicationTaskIdentifier: string;
  Status?: string;
  MigrationType?: string;
  ReplicationInstanceArn?: string;
  SourceEndpointArn?: string;
  TargetEndpointArn?: string;
  ReplicationTaskCreationDate?: number;
  ReplicationTaskStartDate?: number;
  StopReason?: string;
  ReplicationTaskSettings?: string;
}
interface Endpoint { EndpointArn?: string; EndpointType?: string; EngineName?: string; SslMode?: string; KmsKeyId?: string }

/** `Logging.EnableLogging` from the task's settings JSON; null when unreadable. */
export function taskLoggingEnabled(settings: string | undefined): boolean | null {
  if (!settings) return null;
  try {
    const parsed = JSON.parse(settings) as { Logging?: { EnableLogging?: boolean } };
    return parsed.Logging?.EnableLogging ?? false;
  } catch {
    return null;
  }
}

/**
 * AWS Database Migration Service (JSON-RPC, AmazonDMSv20160101). Regional.
 *
 * What changed, and why:
 *  - Instances and tasks paginate (Marker; 100 per page). The previous
 *    version read one page, so the 101st looked deleted.
 *  - Failures are reported rather than logged and dropped.
 *  - Evidence for FSBP DMS controls: public accessibility, KMS key and
 *    minor-version upgrades on instances; task logging; and each task's
 *    source/target endpoint engine and SSL mode (one DescribeEndpoints walk,
 *    so no endpoint type is needed in the catalog). Task settings JSON is
 *    parsed for the logging flag only and is not stored.
 */
export async function scanDms(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `dms.${ctx.region}.amazonaws.com`;
  const opts = { tokenIn: 'Marker', tokenOut: 'Marker' };
  const [instances, tasks, endpoints] = await Promise.all([
    walkJsonRpc<ReplicationInstance>(ctx, { service: 'dms', host, target: `${TARGET_PREFIX}.DescribeReplicationInstances`, body: { MaxRecords: 100 } }, 'ReplicationInstances', opts),
    walkJsonRpc<ReplicationTask>(ctx, { service: 'dms', host, target: `${TARGET_PREFIX}.DescribeReplicationTasks`, body: { MaxRecords: 100 } }, 'ReplicationTasks', opts),
    walkJsonRpc<Endpoint>(ctx, { service: 'dms', host, target: `${TARGET_PREFIX}.DescribeEndpoints`, body: { MaxRecords: 100 } }, 'Endpoints', opts),
  ]);
  reportWalk(ctx, instances, 'dms', 'DescribeReplicationInstances');
  reportWalk(ctx, tasks, 'dms', 'DescribeReplicationTasks');
  const endpointByArn = new Map(endpoints.items.filter((e) => e?.EndpointArn).map((e) => [e.EndpointArn as string, e]));

  const out: ScannedResource[] = [];
  for (const ri of instances.items) {
    if (!ri?.ReplicationInstanceArn) continue;
    out.push({
      resourceTypeKey: 'dms_replication_instance', resourceId: ri.ReplicationInstanceArn, region: ctx.region,
      resourceName: ri.ReplicationInstanceIdentifier, state: ri.ReplicationInstanceStatus,
      metadata: {
        instanceClass: ri.ReplicationInstanceClass, engineVersion: ri.EngineVersion, availabilityZone: ri.AvailabilityZone,
        multiAZ: ri.MultiAZ, publiclyAccessible: ri.PubliclyAccessible, allocatedStorage: ri.AllocatedStorage,
        createdAt: ri.InstanceCreateTime, createdAtIso: toIso(ri.InstanceCreateTime), vpcId: ri.ReplicationSubnetGroup?.VpcId,
        kmsKeyId: ri.KmsKeyId ?? null,
        autoMinorVersionUpgrade: ri.AutoMinorVersionUpgrade ?? null,
        networkType: ri.NetworkType ?? null,
      },
      relationships: {
        vpcId: ri.ReplicationSubnetGroup?.VpcId ?? null,
        securityGroupIds: (ri.VpcSecurityGroups ?? []).map((g) => g.VpcSecurityGroupId).filter((v): v is string => !!v),
        subnetIds: (ri.ReplicationSubnetGroup?.Subnets ?? []).map((s) => s.SubnetIdentifier).filter((v): v is string => !!v),
      },
    });
  }

  for (const t of tasks.items) {
    if (!t?.ReplicationTaskArn) continue;
    const source = t.SourceEndpointArn ? endpointByArn.get(t.SourceEndpointArn) : undefined;
    const target = t.TargetEndpointArn ? endpointByArn.get(t.TargetEndpointArn) : undefined;
    out.push({
      resourceTypeKey: 'dms_replication_task', resourceId: t.ReplicationTaskArn, region: ctx.region,
      resourceName: t.ReplicationTaskIdentifier, state: t.Status,
      metadata: {
        migrationType: t.MigrationType, createdAt: t.ReplicationTaskCreationDate, startDate: t.ReplicationTaskStartDate,
        createdAtIso: toIso(t.ReplicationTaskCreationDate), startDateIso: toIso(t.ReplicationTaskStartDate),
        stopReason: t.StopReason,
        loggingEnabled: taskLoggingEnabled(t.ReplicationTaskSettings),
        endpointsCollected: endpoints.complete,
        sourceEngine: source?.EngineName ?? null,
        targetEngine: target?.EngineName ?? null,
        // "none" means the migration crosses the network unencrypted.
        sourceSslMode: source?.SslMode ?? null,
        targetSslMode: target?.SslMode ?? null,
      },
      relationships: {
        replicationInstanceArn: t.ReplicationInstanceArn, sourceEndpointArn: t.SourceEndpointArn, targetEndpointArn: t.TargetEndpointArn,
      },
    });
  }
  return out;
}