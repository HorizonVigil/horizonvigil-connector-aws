import { extractSection, extractListItems, field, boolField, numField } from '../xmlList';
import {
  clusterEvidence, describeAllRds, memberStrings, NON_RDS_CLUSTER_ENGINES, rdsTags, vpcSecurityGroupIds, type RdsWalk,
} from './rdsQuery';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const RDS_RESOURCE_TYPES = ['rds_instance', 'rds_cluster', 'rds_snapshot', 'rds_parameter_group', 'rds_subnet_group', 'rds_option_group', 'rds_proxy'] as const;

const boolOrNull = (xml: string, name: string): boolean | null => boolField(xml, name) ?? null;
const numOrNull = (xml: string, name: string): number | null => {
  const n = numField(xml, name);
  return typeof n === 'number' && Number.isFinite(n) ? n : null;
};

/**
 * Per-operation outcome, kept on the scanner's return path for logs and for
 * any caller that wants it. Not stamped onto every resource: identical
 * per-resource copies of run-scoped data make every row look modified on
 * every scan.
 */
export interface RdsScanOperation {
  action: string;
  pages: number;
  items: number;
  termination: RdsWalk['termination'];
  detail?: string;
}

/**
 * RDS inventory: instances, clusters, instance snapshots, parameter/subnet/
 * option groups, and proxies.
 *
 * What changed, and why it matters:
 *
 * 1. EVERY PAGE is read (rdsQuery.ts). Each Describe* returns at most 100
 *    records; the previous version read page one only, with no truncation
 *    signal, so the 101st snapshot onward looked deleted to finalize.
 *    Automated snapshots cross 100 routinely.
 *
 * 2. DocumentDB and Neptune clusters are EXCLUDED from rds_cluster.
 *    DescribeDBClusters with no filter returns every engine on the shared
 *    control plane, so each DocumentDB/Neptune cluster was inventoried twice
 *    -- once here and once by docdb.ts/neptune.ts. (Their instances stay
 *    here as rds_instance: there is no docdb/neptune instance type, and
 *    dropping them would lose them entirely.)
 *
 * 3. The security evidence the headline RDS checks need is collected:
 *    encryption + key, deletion protection, backup retention, IAM auth,
 *    public accessibility, log exports, CA certificate, minor-version
 *    upgrades, enhanced monitoring, proxy TLS enforcement.
 *
 * Existing metadata keys are kept with the same names and meanings.
 */
export async function scanRds(ctx: ScannerContext): Promise<ScannedResource[]> {
  const [instances, clusters, snapshots, parameterGroups, subnetGroups, optionGroups, proxies] = await Promise.all([
    describeAllRds(ctx, 'DescribeDBInstances', 'DBInstances', 'DBInstance'),
    describeAllRds(ctx, 'DescribeDBClusters', 'DBClusters', 'DBCluster'),
    describeAllRds(ctx, 'DescribeDBSnapshots', 'DBSnapshots', 'DBSnapshot'),
    describeAllRds(ctx, 'DescribeDBParameterGroups', 'DBParameterGroups', 'DBParameterGroup'),
    describeAllRds(ctx, 'DescribeDBSubnetGroups', 'DBSubnetGroups', 'DBSubnetGroup'),
    describeAllRds(ctx, 'DescribeOptionGroups', 'OptionGroupsList', 'OptionGroup'),
    describeAllRds(ctx, 'DescribeDBProxies', 'DBProxies', 'DBProxy'),
  ]);

  const out: ScannedResource[] = [];

  for (const db of instances.items) {
    const id = field(db, 'DBInstanceIdentifier');
    const tags = rdsTags(db);
    const endpointSection = extractSection(db, 'Endpoint');
    const subnetGroup = extractSection(db, 'DBSubnetGroup');
    out.push({
      resourceTypeKey: 'rds_instance', resourceId: id ?? '', region: ctx.region,
      resourceName: tags['Name'] ?? id ?? undefined,
      state: field(db, 'DBInstanceStatus') ?? undefined, tags,
      metadata: {
        engine: field(db, 'Engine'), engineVersion: field(db, 'EngineVersion'), instanceClass: field(db, 'DBInstanceClass'),
        allocatedStorageGiB: numField(db, 'AllocatedStorage'), multiAz: boolField(db, 'MultiAZ'),
        publiclyAccessible: boolField(db, 'PubliclyAccessible'), storageType: field(db, 'StorageType'),
        createTime: field(db, 'InstanceCreateTime'), endpoint: endpointSection ? field(endpointSection, 'Address') : null,
        port: endpointSection ? numField(endpointSection, 'Port') : undefined,

        arn: field(db, 'DBInstanceArn'),
        dbiResourceId: field(db, 'DbiResourceId'),
        // Encryption at rest.
        storageEncrypted: boolOrNull(db, 'StorageEncrypted'),
        kmsKeyId: field(db, 'KmsKeyId'),
        // Resilience.
        backupRetentionPeriod: numOrNull(db, 'BackupRetentionPeriod'),
        deletionProtection: boolOrNull(db, 'DeletionProtection'),
        copyTagsToSnapshot: boolOrNull(db, 'CopyTagsToSnapshot'),
        // Access.
        iamDatabaseAuthenticationEnabled: boolOrNull(db, 'IAMDatabaseAuthenticationEnabled'),
        caCertificateIdentifier: field(db, 'CACertificateIdentifier'),
        // Patching / observability.
        autoMinorVersionUpgrade: boolOrNull(db, 'AutoMinorVersionUpgrade'),
        enabledCloudwatchLogsExports: memberStrings(db, 'EnabledCloudwatchLogsExports'),
        monitoringInterval: numOrNull(db, 'MonitoringInterval'),
        performanceInsightsEnabled: boolOrNull(db, 'PerformanceInsightsEnabled'),
      },
      relationships: {
        dbClusterIdentifier: field(db, 'DBClusterIdentifier'),
        vpcId: subnetGroup ? field(subnetGroup, 'VpcId') : null,
        securityGroupIds: vpcSecurityGroupIds(db),
        dbSubnetGroupName: subnetGroup ? field(subnetGroup, 'DBSubnetGroupName') : null,
      },
    });
  }

  for (const cl of clusters.items) {
    // Inventoried by docdb.ts / neptune.ts under their own types.
    const engine = field(cl, 'Engine');
    if (engine && NON_RDS_CLUSTER_ENGINES.has(engine)) continue;
    const id = field(cl, 'DBClusterIdentifier');
    const tags = rdsTags(cl);
    const evidence = clusterEvidence(cl);
    out.push({
      resourceTypeKey: 'rds_cluster', resourceId: id ?? '', region: ctx.region,
      resourceName: tags['Name'] ?? id ?? undefined,
      state: field(cl, 'Status') ?? undefined, tags,
      metadata: evidence.metadata,
      relationships: evidence.relationships,
    });
  }

  for (const sn of snapshots.items) {
    const id = field(sn, 'DBSnapshotIdentifier');
    const tags = rdsTags(sn);
    out.push({
      resourceTypeKey: 'rds_snapshot', resourceId: id ?? '', region: ctx.region,
      resourceName: tags['Name'] ?? id ?? undefined,
      state: field(sn, 'Status') ?? undefined, tags,
      metadata: {
        engine: field(sn, 'Engine'), allocatedStorageGiB: numField(sn, 'AllocatedStorage'), snapshotType: field(sn, 'SnapshotType'),
        encrypted: boolField(sn, 'Encrypted'), createTime: field(sn, 'SnapshotCreateTime'),
        arn: field(sn, 'DBSnapshotArn'),
        kmsKeyId: field(sn, 'KmsKeyId'),
        engineVersion: field(sn, 'EngineVersion'),
        storageType: field(sn, 'StorageType'),
      },
      relationships: { dbInstanceIdentifier: field(sn, 'DBInstanceIdentifier') },
    });
  }

  for (const pg of parameterGroups.items) {
    const name = field(pg, 'DBParameterGroupName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'rds_parameter_group', resourceId: field(pg, 'DBParameterGroupArn') ?? name, region: ctx.region, resourceName: name,
      metadata: { family: field(pg, 'DBParameterGroupFamily'), description: field(pg, 'Description') },
    });
  }

  for (const sg of subnetGroups.items) {
    const name = field(sg, 'DBSubnetGroupName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'rds_subnet_group', resourceId: field(sg, 'DBSubnetGroupArn') ?? name, region: ctx.region, resourceName: name,
      state: field(sg, 'SubnetGroupStatus') ?? undefined,
      metadata: { description: field(sg, 'DBSubnetGroupDescription') },
      relationships: {
        vpcId: field(sg, 'VpcId'),
        subnetIds: extractListItems(extractSection(sg, 'Subnets'), 'Subnet')
          .map((s) => field(s, 'SubnetIdentifier'))
          .filter((v): v is string => !!v),
      },
    });
  }

  for (const og of optionGroups.items) {
    const name = field(og, 'OptionGroupName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'rds_option_group', resourceId: field(og, 'OptionGroupArn') ?? name, region: ctx.region, resourceName: name,
      metadata: {
        engineName: field(og, 'EngineName'), majorEngineVersion: field(og, 'MajorEngineVersion'), description: field(og, 'OptionGroupDescription'),
        optionNames: extractListItems(extractSection(og, 'Options'), 'Option')
          .map((o) => field(o, 'OptionName'))
          .filter((v): v is string => !!v),
      },
      relationships: { vpcId: field(og, 'VpcId') },
    });
  }

  for (const px of proxies.items) {
    const name = field(px, 'DBProxyName');
    if (!name) continue;
    const auth = extractListItems(extractSection(px, 'Auth'), 'member');
    out.push({
      resourceTypeKey: 'rds_proxy', resourceId: field(px, 'DBProxyArn') ?? name, region: ctx.region, resourceName: name,
      state: field(px, 'Status') ?? undefined,
      metadata: {
        engineFamily: field(px, 'EngineFamily'), createdDate: field(px, 'CreatedDate'),
        // TLS enforcement between clients and the proxy.
        requireTls: boolOrNull(px, 'RequireTLS'),
        debugLogging: boolOrNull(px, 'DebugLogging'),
        iamAuth: auth.map((a) => field(a, 'IAMAuth')).filter((v): v is string => !!v),
      },
      relationships: {
        vpcId: field(px, 'VpcId'),
        securityGroupIds: memberStrings(px, 'VpcSecurityGroupIds'),
        subnetIds: memberStrings(px, 'VpcSubnetIds'),
      },
    });
  }

  const operations: RdsScanOperation[] = [
    ['DescribeDBInstances', instances], ['DescribeDBClusters', clusters], ['DescribeDBSnapshots', snapshots],
    ['DescribeDBParameterGroups', parameterGroups], ['DescribeDBSubnetGroups', subnetGroups],
    ['DescribeOptionGroups', optionGroups], ['DescribeDBProxies', proxies],
  ].map(([action, w]) => {
    const walk = w as RdsWalk;
    return { action: action as string, pages: walk.pages, items: walk.items.length, termination: walk.termination, detail: walk.detail };
  });
  const incomplete = operations.filter((o) => o.termination !== 'complete');
  if (incomplete.length > 0) {
    console.error(`RDS scan in ${ctx.region} is partial: ${incomplete.map((o) => `${o.action}=${o.termination}`).join(', ')}`);
  }

  return out;
}