import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AmazonDMSv20160101';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DMS_RESOURCE_TYPES = ['dms_replication_instance', 'dms_replication_task'] as const;

interface ReplicationInstance {
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
  ReplicationSubnetGroup?: { VpcId?: string };
}
interface ReplicationTask {
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
}

/**
 * AWS Database Migration Service — JSON-RPC 1.1, like athena.ts/ce.ts,
 * target prefix `AmazonDMSv20160101` confirmed against AWS's own published
 * API reference sample requests (DescribeReplicationInstances,
 * DescribeReplicationTasks), which show
 * `X-Amz-Target: AmazonDMSv20160101.<Operation>` verbatim. Regional, not
 * global — DMS is a per-region service like Athena, so this belongs in
 * discovery.ts's REGIONAL_SCANNERS, not GLOBAL_SCANNERS.
 *
 * Both calls only pull a single page (MaxRecords: 100, no Marker/NextToken
 * follow-up loop) — fine for a first pass per the task guidance, but an
 * account with more than 100 replication instances or tasks in one region
 * will silently miss the rest until pagination is added.
 *
 * UNVERIFIED against a real account's actual response shape until this runs
 * against a live connection and gets checked -- same disclosed-uncertainty
 * convention as inspector2.ts/ce.ts (field names below are transcribed from
 * AWS's published API reference docs, not exercised against a live DMS
 * deployment).
 */
export async function scanDms(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `dms.${ctx.region}.amazonaws.com`;
  const out: ScannedResource[] = [];

  const instances = await callJsonApi(ctx.creds, {
    service: 'dms', region: ctx.region, host, target: `${TARGET_PREFIX}.DescribeReplicationInstances`, body: { MaxRecords: 100 },
  });
  if (!instances.ok) {
    console.error(`DMS DescribeReplicationInstances failed in ${ctx.region} (continuing without it): ${instances.errorMessage ?? instances.errorCode ?? instances.status}`);
  } else {
    for (const ri of (instances.body as { ReplicationInstances?: ReplicationInstance[] }).ReplicationInstances ?? []) {
      out.push({
        resourceTypeKey: 'dms_replication_instance', resourceId: ri.ReplicationInstanceArn, region: ctx.region,
        resourceName: ri.ReplicationInstanceIdentifier, state: ri.ReplicationInstanceStatus,
        metadata: {
          instanceClass: ri.ReplicationInstanceClass, engineVersion: ri.EngineVersion, availabilityZone: ri.AvailabilityZone,
          multiAZ: ri.MultiAZ, publiclyAccessible: ri.PubliclyAccessible, allocatedStorage: ri.AllocatedStorage,
          createdAt: ri.InstanceCreateTime, vpcId: ri.ReplicationSubnetGroup?.VpcId,
        },
      });
    }
  }

  const tasks = await callJsonApi(ctx.creds, {
    service: 'dms', region: ctx.region, host, target: `${TARGET_PREFIX}.DescribeReplicationTasks`, body: { MaxRecords: 100 },
  });
  if (!tasks.ok) {
    console.error(`DMS DescribeReplicationTasks failed in ${ctx.region} (continuing without it): ${tasks.errorMessage ?? tasks.errorCode ?? tasks.status}`);
  } else {
    for (const t of (tasks.body as { ReplicationTasks?: ReplicationTask[] }).ReplicationTasks ?? []) {
      out.push({
        resourceTypeKey: 'dms_replication_task', resourceId: t.ReplicationTaskArn, region: ctx.region,
        resourceName: t.ReplicationTaskIdentifier, state: t.Status,
        metadata: {
          migrationType: t.MigrationType, createdAt: t.ReplicationTaskCreationDate, startDate: t.ReplicationTaskStartDate,
          stopReason: t.StopReason,
        },
        relationships: {
          replicationInstanceArn: t.ReplicationInstanceArn, sourceEndpointArn: t.SourceEndpointArn, targetEndpointArn: t.TargetEndpointArn,
        },
      });
    }
  }

  return out;
}
