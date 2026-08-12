import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems, field, boolField, numField } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2014-10-31';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DOCDB_RESOURCE_TYPES = ['docdb_cluster'] as const;

/**
 * DocumentDB clusters are DescribeDBClusters calls against the plain RDS API
 * (same host/service/version as rds.ts — "docdb" isn't a distinct signing
 * service, it's an engine value on the shared RDS control plane), filtered
 * server-side to just the docdb engine family so this doesn't re-list every
 * Aurora/MySQL/Postgres cluster rds.ts already covers under rds_cluster.
 */
export async function scanDocDb(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `rds.${ctx.region}.amazonaws.com`;
  const result = await callQueryApi(ctx.creds, {
    service: 'rds', region: ctx.region, host: endpoint, action: 'DescribeDBClusters', version: VERSION,
    params: { 'Filters.member.1.Name': 'engine', 'Filters.member.1.Values.member.1': 'docdb' },
  });
  if (!result.ok) {
    console.error(`DocumentDB DescribeDBClusters failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const xml = result.body as string;
  const out: ScannedResource[] = [];
  for (const cl of extractListItems(extractSection(xml, 'DBClusters'), 'DBCluster')) {
    out.push({
      resourceTypeKey: 'docdb_cluster', resourceId: field(cl, 'DBClusterIdentifier')!, region: ctx.region,
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
