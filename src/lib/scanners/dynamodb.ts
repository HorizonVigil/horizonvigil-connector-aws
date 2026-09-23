import { callJsonApi } from '../awsApi';
import { reportWalk, toIso, walkJsonRpc } from './restJson';
import { mapWithConcurrency, reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'DynamoDB_20120810';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DYNAMODB_RESOURCE_TYPES = ['dynamodb_table', 'dynamodb_backup', 'dynamodb_global_table'] as const;

/** DescribeTable follow-ups per region-step (Workers subrequest budget). */
const MAX_TABLE_DETAILS = 40;
/** DescribeContinuousBackups (PITR) follow-ups per region-step. */
const MAX_PITR_LOOKUPS = 20;
const CONCURRENCY = 6;

export interface TableDescription {
  TableName: string; TableStatus?: string; ItemCount?: number; TableSizeBytes?: number;
  CreationDateTime?: number; TableArn?: string;
  BillingModeSummary?: { BillingMode?: string };
  ProvisionedThroughput?: { ReadCapacityUnits?: number; WriteCapacityUnits?: number };
  SSEDescription?: { Status?: string; SSEType?: string; KMSMasterKeyArn?: string };
  DeletionProtectionEnabled?: boolean;
  TableClassSummary?: { TableClass?: string };
  StreamSpecification?: { StreamEnabled?: boolean; StreamViewType?: string };
  Replicas?: { RegionName?: string; ReplicaStatus?: string }[];
  GlobalTableVersion?: string;
}
interface BackupSummary {
  TableName?: string; BackupArn: string; BackupName?: string; BackupSizeBytes?: number; BackupStatus?: string; BackupType?: string;
  BackupCreationDateTime?: number; BackupExpiryDateTime?: number;
}
interface GlobalTable { GlobalTableName: string; ReplicationGroup?: { RegionName?: string }[] }

/**
 * ARN for a table that was listed but not described, built from a described
 * sibling's ARN (same partition/region/account). Keeps a table's identity
 * stable whether or not its DescribeTable ran this step -- the previous
 * version fell back to the bare NAME, so the same table flipped between two
 * identities (read as delete + create) depending on whether its describe
 * succeeded or it fell past the cap.
 */
export function siblingArn(sampleArn: string | undefined, marker: string, name: string): string | null {
  if (!sampleArn) return null;
  const idx = sampleArn.indexOf(marker);
  return idx < 0 ? null : `${sampleArn.slice(0, idx + marker.length)}${name}`;
}

/** Security + resilience evidence for one table (FSBP DynamoDB.1–.6). */
export function tableEvidence(t: TableDescription | undefined, pitr: boolean | null | undefined) {
  if (!t) return { detailsCollected: false };
  const sse = t.SSEDescription;
  return {
    detailsCollected: true,
    // Kept exactly as before.
    itemCount: t.ItemCount, sizeBytes: t.TableSizeBytes, createdAt: t.CreationDateTime,
    billingMode: t.BillingModeSummary?.BillingMode ?? 'PROVISIONED',
    readCapacityUnits: t.ProvisionedThroughput?.ReadCapacityUnits, writeCapacityUnits: t.ProvisionedThroughput?.WriteCapacityUnits,
    createdAtIso: toIso(t.CreationDateTime),
    // Every table is encrypted; no SSEDescription means the AWS-owned key.
    encryptionType: sse?.Status === 'ENABLED' ? (sse.SSEType ?? 'KMS') : 'AWS_OWNED',
    customerManagedKmsKeyArn: sse?.SSEType === 'KMS' ? (sse.KMSMasterKeyArn ?? null) : null,
    deletionProtectionEnabled: t.DeletionProtectionEnabled ?? false,
    // DynamoDB.2: point-in-time recovery. null = not checked this step.
    pointInTimeRecoveryEnabled: pitr ?? null,
    tableClass: t.TableClassSummary?.TableClass ?? 'STANDARD',
    streamEnabled: t.StreamSpecification?.StreamEnabled ?? false,
    // Global tables version 2019.11.21 replicas live on the table itself.
    replicaRegions: (t.Replicas ?? []).map((r) => r.RegionName).filter((v): v is string => !!v),
    globalTableVersion: t.GlobalTableVersion ?? null,
  };
}

/**
 * DynamoDB (JSON-RPC, DynamoDB_20120810).
 *
 * What changed, and why:
 *  - ListTables paginates (ExclusiveStartTableName / LastEvaluatedTableName).
 *    The previous version kept the first 45 names SILENTLY: table 46 onward
 *    looked deleted. Every listed table is now emitted; DescribeTable is
 *    bounded by MAX_TABLE_DETAILS, and tables past it are recorded with
 *    `detailsCollected: false` under a stable ARN identity (see siblingArn).
 *  - ListBackups and ListGlobalTables paginate too; failures are reported.
 *  - Evidence: encryption key type, deletion protection, point-in-time
 *    recovery (bounded DescribeContinuousBackups), streams, replicas.
 *
 * Note: ItemCount/TableSizeBytes refresh about every six hours, so table
 * rows change a few times a day by nature. Kept for existing consumers.
 */
export async function scanDynamoDb(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `dynamodb.${ctx.region}.amazonaws.com`;
  const call = (action: string, body: Record<string, unknown>) =>
    callJsonApi(ctx.creds, { service: 'dynamodb', region: ctx.region, host, target: `${TARGET_PREFIX}.${action}`, body });

  const [tablesWalk, backupsWalk, globalWalk] = await Promise.all([
    walkJsonRpc<string>(ctx, { service: 'dynamodb', host, target: `${TARGET_PREFIX}.ListTables`, body: { Limit: 100 } }, 'TableNames',
      { tokenIn: 'ExclusiveStartTableName', tokenOut: 'LastEvaluatedTableName' }),
    walkJsonRpc<BackupSummary>(ctx, { service: 'dynamodb', host, target: `${TARGET_PREFIX}.ListBackups`, body: { Limit: 100 } }, 'BackupSummaries',
      { tokenIn: 'ExclusiveStartBackupArn', tokenOut: 'LastEvaluatedBackupArn' }),
    walkJsonRpc<GlobalTable>(ctx, { service: 'dynamodb', host, target: `${TARGET_PREFIX}.ListGlobalTables`, body: { RegionName: ctx.region, Limit: 100 } }, 'GlobalTables',
      { tokenIn: 'ExclusiveStartGlobalTableName', tokenOut: 'LastEvaluatedGlobalTableName' }),
  ]);
  reportWalk(ctx, tablesWalk, 'dynamodb', 'ListTables');
  reportWalk(ctx, backupsWalk, 'dynamodb', 'ListBackups');
  reportWalk(ctx, globalWalk, 'dynamodb', 'ListGlobalTables');

  const names = [...new Set(tablesWalk.items.filter((n): n is string => typeof n === 'string' && n !== ''))];
  const described = new Map<string, TableDescription>();
  await mapWithConcurrency(names.slice(0, MAX_TABLE_DETAILS), CONCURRENCY, async (name) => {
    const r = await call('DescribeTable', { TableName: name });
    const table = r.ok ? (r.body as { Table?: TableDescription } | null)?.Table : undefined;
    if (table) described.set(name, table);
    else console.error(`DynamoDB DescribeTable(${name}) failed in ${ctx.region}; recording it without details.`);
  });
  const pitr = new Map<string, boolean>();
  await mapWithConcurrency([...described.keys()].slice(0, MAX_PITR_LOOKUPS), CONCURRENCY, async (name) => {
    const r = await call('DescribeContinuousBackups', { TableName: name });
    const status = r.ok ? (r.body as { ContinuousBackupsDescription?: { PointInTimeRecoveryDescription?: { PointInTimeRecoveryStatus?: string } } } | null)
      ?.ContinuousBackupsDescription?.PointInTimeRecoveryDescription?.PointInTimeRecoveryStatus : undefined;
    if (status) pitr.set(name, status === 'ENABLED');
  });

  const sampleArn = [...described.values()].find((t) => t.TableArn)?.TableArn;
  const out: ScannedResource[] = [];
  let unidentifiable = 0;
  for (const name of names) {
    const t = described.get(name);
    const arn = t?.TableArn ?? siblingArn(sampleArn, ':table/', name);
    if (!arn) { unidentifiable++; continue; }
    out.push({
      resourceTypeKey: 'dynamodb_table', resourceId: arn, region: ctx.region, resourceName: name,
      state: t?.TableStatus,
      metadata: tableEvidence(t, pitr.get(name)),
      relationships: { kmsKeyArn: t?.SSEDescription?.KMSMasterKeyArn ?? null },
    });
  }
  if (unidentifiable > 0) {
    // No table could be described, so no ARN can be built: emitting names
    // would change identities. Report instead so existing rows are kept.
    console.error(`DynamoDB ${ctx.region}: ${unidentifiable} table(s) could not be identified by ARN this step; coverage degraded.`);
    reportListingFailure(ctx, { service: 'dynamodb', action: 'DescribeTable', region: ctx.region });
  }

  for (const b of backupsWalk.items) {
    if (!b?.BackupArn) continue;
    out.push({
      resourceTypeKey: 'dynamodb_backup', resourceId: b.BackupArn, region: ctx.region, resourceName: b.BackupName,
      state: b.BackupStatus,
      metadata: {
        sizeBytes: b.BackupSizeBytes, backupType: b.BackupType, createdAt: b.BackupCreationDateTime,
        createdAtIso: toIso(b.BackupCreationDateTime), expiresAtIso: toIso(b.BackupExpiryDateTime),
      },
      relationships: { tableName: b.TableName },
    });
  }

  // Legacy (2017.11.29) global tables. Version 2019.11.21 replicas are
  // recorded on each table (replicaRegions) instead.
  for (const gt of globalWalk.items) {
    if (!gt?.GlobalTableName) continue;
    out.push({
      resourceTypeKey: 'dynamodb_global_table', resourceId: gt.GlobalTableName, region: ctx.region, resourceName: gt.GlobalTableName,
      metadata: { replicaRegions: (gt.ReplicationGroup ?? []).map((r) => r.RegionName) },
    });
  }

  return out;
}
