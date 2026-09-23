import { extractSection, extractListItems, field, numField, boolField } from '../xmlList';
import { describeAllQuery } from './queryMarker';
import { memberTexts, withoutSections } from './xmlShape';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2015-02-02';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ELASTICACHE_RESOURCE_TYPES = ['elasticache_cluster', 'elasticache_replication_group', 'elasticache_snapshot'] as const;

/** Nested lists whose children reuse top-level element names (Status, …). */
const CLUSTER_NESTED = ['CacheNodes', 'SecurityGroups', 'CacheSecurityGroups', 'PendingModifiedValues', 'NotificationConfiguration', 'CacheParameterGroup', 'LogDeliveryConfigurations'];
const GROUP_NESTED = ['NodeGroups', 'MemberClusters', 'MemberClustersOutpostArns', 'PendingModifiedValues', 'GlobalReplicationGroupInfo', 'LogDeliveryConfigurations', 'UserGroupIds'];

const boolOrNull = (xml: string, name: string): boolean | null => boolField(xml, name) ?? null;

/** Security evidence for a cache cluster (FSBP ElastiCache.1–.7). */
export function cacheClusterEvidence(cc: string) {
  const top = withoutSections(cc, CLUSTER_NESTED);
  return {
    engine: field(top, 'Engine'), engineVersion: field(top, 'EngineVersion'), nodeType: field(top, 'CacheNodeType'),
    numNodes: numField(top, 'NumCacheNodes'), createTime: field(top, 'CacheClusterCreateTime'), availabilityZone: field(top, 'PreferredAvailabilityZone'),
    atRestEncryptionEnabled: boolOrNull(top, 'AtRestEncryptionEnabled'),
    transitEncryptionEnabled: boolOrNull(top, 'TransitEncryptionEnabled'),
    authTokenEnabled: boolOrNull(top, 'AuthTokenEnabled'),
    autoMinorVersionUpgrade: boolOrNull(top, 'AutoMinorVersionUpgrade'),
    snapshotRetentionLimit: numField(top, 'SnapshotRetentionLimit') ?? null,
    cacheSubnetGroupName: field(top, 'CacheSubnetGroupName'),
    ipDiscovery: field(top, 'IpDiscovery'),
    networkType: field(top, 'NetworkType'),
  };
}

/** Security evidence for a replication group (Redis/Valkey topology). */
export function replicationGroupEvidence(rg: string) {
  const top = withoutSections(rg, GROUP_NESTED);
  return {
    nodeType: field(top, 'CacheNodeType'),
    clusterEnabled: boolField(top, 'ClusterEnabled'),
    // Kept as the raw string ("enabled"/"disabled") for existing consumers.
    multiAz: field(top, 'MultiAZ'),
    automaticFailover: field(top, 'AutomaticFailover'),
    atRestEncryptionEnabled: boolOrNull(top, 'AtRestEncryptionEnabled'),
    transitEncryptionEnabled: boolOrNull(top, 'TransitEncryptionEnabled'),
    transitEncryptionMode: field(top, 'TransitEncryptionMode'),
    authTokenEnabled: boolOrNull(top, 'AuthTokenEnabled'),
    kmsKeyId: field(top, 'KmsKeyId'),
    snapshotRetentionLimit: numField(top, 'SnapshotRetentionLimit') ?? null,
    autoMinorVersionUpgrade: boolOrNull(top, 'AutoMinorVersionUpgrade'),
    engine: field(top, 'Engine'),
  };
}

/**
 * ElastiCache clusters, replication groups and snapshots (Query protocol;
 * named list items like RDS's).
 *
 * What changed, and why:
 *  - All three Describe* calls paginate (Marker; 100 per page). The previous
 *    version read one page, so cluster 101 looked deleted.
 *  - Fields are read from each item's top level: the regex reader used to be
 *    able to return a nested node's or log configuration's <Status>.
 *  - Evidence: encryption at rest and in transit, AUTH, automatic failover,
 *    backup retention, minor-version upgrades, subnet group, security groups.
 */
export async function scanElastiCache(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `elasticache.${ctx.region}.amazonaws.com`;
  const base = { service: 'elasticache', host, version: VERSION, pageSizeParam: 'MaxRecords', pageSize: '100' };

  const [clusters, groups, snapshots] = await Promise.all([
    describeAllQuery(ctx, { ...base, action: 'DescribeCacheClusters', listSection: 'CacheClusters', itemTag: 'CacheCluster' }),
    describeAllQuery(ctx, { ...base, action: 'DescribeReplicationGroups', listSection: 'ReplicationGroups', itemTag: 'ReplicationGroup' }),
    describeAllQuery(ctx, { ...base, pageSize: '50', action: 'DescribeSnapshots', listSection: 'Snapshots', itemTag: 'Snapshot' }),
  ]);

  const out: ScannedResource[] = [];
  for (const cc of clusters.items) {
    const top = withoutSections(cc, CLUSTER_NESTED);
    const id = field(top, 'CacheClusterId');
    if (!id) continue;
    out.push({
      resourceTypeKey: 'elasticache_cluster', resourceId: field(top, 'ARN') ?? id, region: ctx.region, resourceName: id,
      state: field(top, 'CacheClusterStatus') ?? undefined,
      metadata: cacheClusterEvidence(cc),
      relationships: {
        replicationGroupId: field(top, 'ReplicationGroupId'),
        securityGroupIds: extractListItems(extractSection(cc, 'SecurityGroups'), 'member')
          .map((m) => field(m, 'SecurityGroupId')).filter((v): v is string => !!v),
      },
    });
  }
  for (const rg of groups.items) {
    const top = withoutSections(rg, GROUP_NESTED);
    const id = field(top, 'ReplicationGroupId');
    if (!id) continue;
    out.push({
      resourceTypeKey: 'elasticache_replication_group', resourceId: field(top, 'ARN') ?? id, region: ctx.region, resourceName: field(top, 'Description') ?? id,
      state: field(top, 'Status') ?? undefined,
      metadata: replicationGroupEvidence(rg),
      relationships: { memberClusterIds: memberTexts(rg, 'MemberClusters', 'ClusterId'), kmsKeyId: field(top, 'KmsKeyId') },
    });
  }
  for (const sn of snapshots.items) {
    const top = withoutSections(sn, ['NodeSnapshots']);
    const id = field(top, 'SnapshotName');
    if (!id) continue;
    out.push({
      resourceTypeKey: 'elasticache_snapshot', resourceId: field(top, 'ARN') ?? id, region: ctx.region, resourceName: id,
      state: field(top, 'SnapshotStatus') ?? undefined,
      metadata: {
        engine: field(top, 'Engine'), nodeType: field(top, 'CacheNodeType'), snapshotSource: field(top, 'SnapshotSource'),
        kmsKeyId: field(top, 'KmsKeyId'),
      },
      relationships: { cacheClusterId: field(top, 'CacheClusterId'), replicationGroupId: field(top, 'ReplicationGroupId') },
    });
  }
  return out;
}
