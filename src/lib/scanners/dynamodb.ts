import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'DynamoDB_20120810';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DYNAMODB_RESOURCE_TYPES = ['dynamodb_table', 'dynamodb_backup', 'dynamodb_global_table'] as const;

interface DescribeTableResponse {
  Table?: {
    TableName: string; TableStatus?: string; ItemCount?: number; TableSizeBytes?: number;
    CreationDateTime?: number; TableArn?: string;
    BillingModeSummary?: { BillingMode?: string };
    ProvisionedThroughput?: { ReadCapacityUnits?: number; WriteCapacityUnits?: number };
  };
}
interface BackupSummary {
  TableName?: string; BackupArn: string; BackupName?: string; BackupSizeBytes?: number; BackupStatus?: string; BackupType?: string; BackupCreationDateTime?: number;
}
interface GlobalTable {
  GlobalTableName: string; ReplicationGroup?: { RegionName?: string }[];
}

/**
 * DynamoDB is JSON-RPC, not Query-protocol like ec2/rds/sns/sqs — ListTables
 * only returns bare table names, so a DescribeTable call per table fills in
 * status/size/billing mode. Capped at 45 tables per region-step (1
 * ListTables + up to 45 DescribeTable calls stays under Cloudflare's
 * free-tier ~50 subrequest budget for one invocation) — an account with
 * more than that in a single region needs a paginated/chunked version of
 * this scanner, not built yet.
 */
export async function scanDynamoDb(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `dynamodb.${ctx.region}.amazonaws.com`;
  const listResult = await callJsonApi(ctx.creds, { service: 'dynamodb', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListTables`, body: {} });
  if (!listResult.ok) {
    console.error(`DynamoDB ListTables failed in ${ctx.region} (continuing without it): ${listResult.errorMessage ?? listResult.errorCode ?? listResult.status}`);
    return [];
  }

  const tableNames = ((listResult.body as { TableNames?: string[] }).TableNames ?? []).slice(0, 45);
  const out: ScannedResource[] = [];

  const descriptions = await Promise.all(tableNames.map((name) =>
    callJsonApi(ctx.creds, { service: 'dynamodb', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.DescribeTable`, body: { TableName: name } }),
  ));

  for (let i = 0; i < tableNames.length; i++) {
    const desc = descriptions[i];
    const name = tableNames[i];
    if (!desc.ok) {
      console.error(`DynamoDB DescribeTable(${name}) failed in ${ctx.region} (continuing without it): ${desc.errorMessage ?? desc.errorCode ?? desc.status}`);
      out.push({ resourceTypeKey: 'dynamodb_table', resourceId: name, region: ctx.region, resourceName: name });
      continue;
    }
    const table = (desc.body as DescribeTableResponse).Table;
    out.push({
      resourceTypeKey: 'dynamodb_table', resourceId: table?.TableArn ?? name, region: ctx.region, resourceName: name,
      state: table?.TableStatus, metadata: {
        itemCount: table?.ItemCount, sizeBytes: table?.TableSizeBytes, createdAt: table?.CreationDateTime,
        billingMode: table?.BillingModeSummary?.BillingMode ?? 'PROVISIONED',
        readCapacityUnits: table?.ProvisionedThroughput?.ReadCapacityUnits, writeCapacityUnits: table?.ProvisionedThroughput?.WriteCapacityUnits,
      },
    });
  }

  const backupsResult = await callJsonApi(ctx.creds, { service: 'dynamodb', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListBackups`, body: {} });
  if (!backupsResult.ok) {
    console.error(`DynamoDB ListBackups failed in ${ctx.region} (continuing without it): ${backupsResult.errorMessage ?? backupsResult.errorCode ?? backupsResult.status}`);
  } else {
    for (const b of (backupsResult.body as { BackupSummaries?: BackupSummary[] }).BackupSummaries ?? []) {
      out.push({
        resourceTypeKey: 'dynamodb_backup', resourceId: b.BackupArn, region: ctx.region, resourceName: b.BackupName,
        state: b.BackupStatus, metadata: { sizeBytes: b.BackupSizeBytes, backupType: b.BackupType, createdAt: b.BackupCreationDateTime },
        relationships: { tableName: b.TableName },
      });
    }
  }

  // Global Tables are an account-wide concept (one row per table, not per
  // region), listed here scoped to ctx.region like every other call in this
  // scanner — a table with a replica in multiple scan regions will appear
  // once per region it replicates into, same "one row per region-step"
  // shape resource_lifecycle_events already expects from every scanner.
  const globalTablesResult = await callJsonApi(ctx.creds, { service: 'dynamodb', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListGlobalTables`, body: { RegionName: ctx.region } });
  if (!globalTablesResult.ok) {
    console.error(`DynamoDB ListGlobalTables failed in ${ctx.region} (continuing without it): ${globalTablesResult.errorMessage ?? globalTablesResult.errorCode ?? globalTablesResult.status}`);
  } else {
    for (const gt of (globalTablesResult.body as { GlobalTables?: GlobalTable[] }).GlobalTables ?? []) {
      out.push({
        resourceTypeKey: 'dynamodb_global_table', resourceId: `${gt.GlobalTableName}`, region: ctx.region, resourceName: gt.GlobalTableName,
        metadata: { replicaRegions: (gt.ReplicationGroup ?? []).map((r) => r.RegionName) },
      });
    }
  }

  return out;
}
