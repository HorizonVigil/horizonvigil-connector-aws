import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems, field, boolField, numField } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2014-10-31';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const NEPTUNE_RESOURCE_TYPES = ['neptune_cluster'] as const;

/** Same shared-RDS-API-filtered-by-engine shape as docdb.ts — see that file's comment. */
export async function scanNeptune(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `rds.${ctx.region}.amazonaws.com`;
  const result = await callQueryApi(ctx.creds, {
    service: 'rds', region: ctx.region, host: endpoint, action: 'DescribeDBClusters', version: VERSION,
    params: { 'Filters.member.1.Name': 'engine', 'Filters.member.1.Values.member.1': 'neptune' },
  });
  if (!result.ok) {
    console.error(`Neptune DescribeDBClusters failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const xml = result.body as string;
  const out: ScannedResource[] = [];
  for (const cl of extractListItems(extractSection(xml, 'DBClusters'), 'DBCluster')) {
    out.push({
      resourceTypeKey: 'neptune_cluster', resourceId: field(cl, 'DBClusterIdentifier')!, region: ctx.region,
      resourceName: field(cl, 'DBClusterIdentifier') ?? undefined, state: field(cl, 'Status') ?? undefined,
      metadata: {
        engineVersion: field(cl, 'EngineVersion'), endpoint: field(cl, 'Endpoint'),
        storageEncrypted: boolField(cl, 'StorageEncrypted'), backupRetentionPeriod: numField(cl, 'BackupRetentionPeriod'),
        createTime: field(cl, 'ClusterCreateTime'),
      },
      relationships: {
        securityGroupIds: extractListItems(extractSection(cl, 'VpcSecurityGroups'), 'VpcSecurityGroupMembership').map(m => field(m, 'VpcSecurityGroupId')),
      },
    });
  }
  return out;
}
