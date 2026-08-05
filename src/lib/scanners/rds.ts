import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems, field, boolField, numField } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2014-10-31';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const RDS_RESOURCE_TYPES = ['rds_instance', 'rds_cluster', 'rds_snapshot', 'rds_parameter_group', 'rds_subnet_group', 'rds_option_group', 'rds_proxy'] as const;

/**
 * RDS's Query-protocol tags don't match EC2's `tagSet`/`item`/`key`/`value`
 * shape (see xmlList.ts's tagsFromSet) — RDS wraps them as
 * `<TagList><Tag><Key>.../<Value>...</Tag></TagList>`, capitalized field
 * names. Small enough to not be worth generalizing tagsFromSet over.
 */
function rdsTags(xml: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const tag of extractListItems(extractSection(xml, 'TagList'), 'Tag')) {
    const key = field(tag, 'Key');
    if (key) out[key] = field(tag, 'Value') ?? '';
  }
  return out;
}

/** Instances, Aurora clusters, and manual/automated snapshots — one signer, 3 Describe* calls, same shape as scanEc2. */
export async function scanRds(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `rds.${ctx.region}.amazonaws.com`;
  const call = async (action: string): Promise<string> => {
    const result = await callQueryApi(ctx.creds, { service: 'rds', region: ctx.region, host: endpoint, action, version: VERSION });
    if (!result.ok) {
      console.error(`RDS ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return '';
    }
    return result.body as string;
  };

  const [instances, clusters, snapshots, parameterGroups, subnetGroups, optionGroups, proxies] = await Promise.all([
    call('DescribeDBInstances'),
    call('DescribeDBClusters'),
    call('DescribeDBSnapshots'),
    call('DescribeDBParameterGroups'),
    call('DescribeDBSubnetGroups'),
    call('DescribeOptionGroups'),
    call('DescribeDBProxies'),
  ]);

  const out: ScannedResource[] = [];

  for (const db of extractListItems(extractSection(instances, 'DBInstances'), 'DBInstance')) {
    const tags = rdsTags(db);
    const endpointSection = extractSection(db, 'Endpoint');
    const subnetGroup = extractSection(db, 'DBSubnetGroup');
    out.push({
      resourceTypeKey: 'rds_instance', resourceId: field(db, 'DBInstanceIdentifier')!, region: ctx.region,
      resourceName: tags['Name'] ?? field(db, 'DBInstanceIdentifier') ?? undefined,
      state: field(db, 'DBInstanceStatus') ?? undefined, tags,
      metadata: {
        engine: field(db, 'Engine'), engineVersion: field(db, 'EngineVersion'), instanceClass: field(db, 'DBInstanceClass'),
        allocatedStorageGiB: numField(db, 'AllocatedStorage'), multiAz: boolField(db, 'MultiAZ'),
        publiclyAccessible: boolField(db, 'PubliclyAccessible'), storageType: field(db, 'StorageType'),
        createTime: field(db, 'InstanceCreateTime'), endpoint: endpointSection ? field(endpointSection, 'Address') : null,
        port: endpointSection ? numField(endpointSection, 'Port') : undefined,
      },
      relationships: {
        dbClusterIdentifier: field(db, 'DBClusterIdentifier'),
        vpcId: subnetGroup ? field(subnetGroup, 'VpcId') : null,
        securityGroupIds: extractListItems(extractSection(db, 'VpcSecurityGroups'), 'VpcSecurityGroupMembership').map(m => field(m, 'VpcSecurityGroupId')),
      },
    });
  }

  for (const cl of extractListItems(extractSection(clusters, 'DBClusters'), 'DBCluster')) {
    const tags = rdsTags(cl);
    out.push({
      resourceTypeKey: 'rds_cluster', resourceId: field(cl, 'DBClusterIdentifier')!, region: ctx.region,
      resourceName: tags['Name'] ?? field(cl, 'DBClusterIdentifier') ?? undefined,
      state: field(cl, 'Status') ?? undefined, tags,
      metadata: {
        engine: field(cl, 'Engine'), engineVersion: field(cl, 'EngineVersion'), endpoint: field(cl, 'Endpoint'),
        allocatedStorageGiB: numField(cl, 'AllocatedStorage'), multiAz: boolField(cl, 'MultiAZ'), createTime: field(cl, 'ClusterCreateTime'),
      },
      relationships: {
        securityGroupIds: extractListItems(extractSection(cl, 'VpcSecurityGroups'), 'VpcSecurityGroupMembership').map(m => field(m, 'VpcSecurityGroupId')),
      },
    });
  }

  for (const sn of extractListItems(extractSection(snapshots, 'DBSnapshots'), 'DBSnapshot')) {
    const tags = rdsTags(sn);
    out.push({
      resourceTypeKey: 'rds_snapshot', resourceId: field(sn, 'DBSnapshotIdentifier')!, region: ctx.region,
      resourceName: tags['Name'] ?? field(sn, 'DBSnapshotIdentifier') ?? undefined,
      state: field(sn, 'Status') ?? undefined, tags,
      metadata: {
        engine: field(sn, 'Engine'), allocatedStorageGiB: numField(sn, 'AllocatedStorage'), snapshotType: field(sn, 'SnapshotType'),
        encrypted: boolField(sn, 'Encrypted'), createTime: field(sn, 'SnapshotCreateTime'),
      },
      relationships: { dbInstanceIdentifier: field(sn, 'DBInstanceIdentifier') },
    });
  }

  for (const pg of extractListItems(extractSection(parameterGroups, 'DBParameterGroups'), 'DBParameterGroup')) {
    const name = field(pg, 'DBParameterGroupName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'rds_parameter_group', resourceId: field(pg, 'DBParameterGroupArn') ?? name, region: ctx.region, resourceName: name,
      metadata: { family: field(pg, 'DBParameterGroupFamily'), description: field(pg, 'Description') },
    });
  }
  for (const sg of extractListItems(extractSection(subnetGroups, 'DBSubnetGroups'), 'DBSubnetGroup')) {
    const name = field(sg, 'DBSubnetGroupName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'rds_subnet_group', resourceId: field(sg, 'DBSubnetGroupArn') ?? name, region: ctx.region, resourceName: name,
      state: field(sg, 'SubnetGroupStatus') ?? undefined,
      metadata: { description: field(sg, 'DBSubnetGroupDescription') },
      relationships: { vpcId: field(sg, 'VpcId') },
    });
  }
  for (const og of extractListItems(extractSection(optionGroups, 'OptionGroupsList'), 'OptionGroup')) {
    const name = field(og, 'OptionGroupName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'rds_option_group', resourceId: field(og, 'OptionGroupArn') ?? name, region: ctx.region, resourceName: name,
      metadata: { engineName: field(og, 'EngineName'), majorEngineVersion: field(og, 'MajorEngineVersion'), description: field(og, 'OptionGroupDescription') },
      relationships: { vpcId: field(og, 'VpcId') },
    });
  }
  for (const px of extractListItems(extractSection(proxies, 'DBProxies'), 'DBProxy')) {
    const name = field(px, 'DBProxyName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'rds_proxy', resourceId: field(px, 'DBProxyArn') ?? name, region: ctx.region, resourceName: name,
      state: field(px, 'Status') ?? undefined,
      metadata: { engineFamily: field(px, 'EngineFamily'), createdDate: field(px, 'CreatedDate') },
      relationships: { vpcId: field(px, 'VpcId') },
    });
  }

  return out;
}
