import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems, field, numField, boolField } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2015-02-02';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ELASTICACHE_RESOURCE_TYPES = ['elasticache_cluster', 'elasticache_replication_group', 'elasticache_snapshot'] as const;

/** Clusters, replication groups (Redis/Valkey multi-node topologies), and snapshots — one signer, 3 Query-protocol calls. ElastiCache repeats a named tag per list rather than the generic `<member>` EC2/IAM/CloudFormation use, same convention as RDS's `<DBInstance>`. */
export async function scanElastiCache(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `elasticache.${ctx.region}.amazonaws.com`;
  const call = async (action: string): Promise<string> => {
    const result = await callQueryApi(ctx.creds, { service: 'elasticache', region: ctx.region, host: endpoint, action, version: VERSION });
    if (!result.ok) {
      console.error(`ElastiCache ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return '';
    }
    return result.body as string;
  };

  const [clusters, replicationGroups, snapshots] = await Promise.all([
    call('DescribeCacheClusters'),
    call('DescribeReplicationGroups'),
    call('DescribeSnapshots'),
  ]);

  const out: ScannedResource[] = [];
  for (const cc of extractListItems(extractSection(clusters, 'CacheClusters'), 'CacheCluster')) {
    const id = field(cc, 'CacheClusterId');
    if (!id) continue;
    out.push({
      resourceTypeKey: 'elasticache_cluster', resourceId: field(cc, 'ARN') ?? id, region: ctx.region, resourceName: id,
      state: field(cc, 'CacheClusterStatus') ?? undefined,
      metadata: {
        engine: field(cc, 'Engine'), engineVersion: field(cc, 'EngineVersion'), nodeType: field(cc, 'CacheNodeType'),
        numNodes: numField(cc, 'NumCacheNodes'), createTime: field(cc, 'CacheClusterCreateTime'), availabilityZone: field(cc, 'PreferredAvailabilityZone'),
      },
    });
  }
  for (const rg of extractListItems(extractSection(replicationGroups, 'ReplicationGroups'), 'ReplicationGroup')) {
    const id = field(rg, 'ReplicationGroupId');
    if (!id) continue;
    out.push({
      resourceTypeKey: 'elasticache_replication_group', resourceId: field(rg, 'ARN') ?? id, region: ctx.region, resourceName: field(rg, 'Description') ?? id,
      state: field(rg, 'Status') ?? undefined,
      metadata: { nodeType: field(rg, 'CacheNodeType'), clusterEnabled: boolField(rg, 'ClusterEnabled'), multiAz: field(rg, 'MultiAZ') },
    });
  }
  for (const sn of extractListItems(extractSection(snapshots, 'Snapshots'), 'Snapshot')) {
    const id = field(sn, 'SnapshotName');
    if (!id) continue;
    out.push({
      resourceTypeKey: 'elasticache_snapshot', resourceId: field(sn, 'ARN') ?? id, region: ctx.region, resourceName: id,
      state: field(sn, 'SnapshotStatus') ?? undefined,
      metadata: { engine: field(sn, 'Engine'), nodeType: field(sn, 'CacheNodeType'), snapshotSource: field(sn, 'SnapshotSource') },
      relationships: { cacheClusterId: field(sn, 'CacheClusterId'), replicationGroupId: field(sn, 'ReplicationGroupId') },
    });
  }
  return out;
}
