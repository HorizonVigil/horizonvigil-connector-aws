import { callQueryApi } from '../awsApi';
import { DEFAULT_MAX_PAGES, incompleteSink, type PaginationTermination } from '../pagination';
import { extractSection, extractListItems, field, boolField, numField } from '../xmlList';
import type { ScannerContext } from './types';

/**
 * Shared plumbing for everything on the RDS control plane: rds.ts, docdb.ts
 * and neptune.ts all call the same API (same host, service and version --
 * DocumentDB and Neptune are engine values on it, not separate services).
 *
 * WHY THIS FILE EXISTS
 *
 * None of the three scanners paginated. Every RDS Describe* call returns at
 * most MaxRecords (default and max 100) and a <Marker> for the rest. An
 * account with 101 instances -- or, far more commonly, 101 automated
 * snapshots -- got the first page only, with no truncation signal, so finalize
 * read everything after record 100 as deleted.
 *
 * RDS paginates on `Marker`, not `NextToken`, so this walks it explicitly
 * rather than guessing what the shared NextToken walker would send.
 */

export const RDS_API_VERSION = '2014-10-31';
const PAGE_SIZE = '100';

export interface RdsWalk {
  items: string[];
  pages: number;
  termination: PaginationTermination;
  detail?: string;
}

/**
 * Every item of `listSection`/`itemTag` across every page of `action`.
 *
 * A failed page ends the walk with termination 'failed' and keeps what was
 * read; callQueryApi's terminal-failure path has already reported it, which
 * is what excludes the type from tombstoning. A page cap or a repeated marker
 * is reported here through the shared incomplete sink.
 */
export async function describeAllRds(
  ctx: ScannerContext,
  action: string,
  listSection: string,
  itemTag: string,
  params: Record<string, string> = {},
): Promise<RdsWalk> {
  const onIncomplete = incompleteSink(ctx.creds);
  const host = `rds.${ctx.region}.amazonaws.com`;
  const items: string[] = [];
  const seenMarkers = new Set<string>();
  let marker: string | null = null;
  let pages = 0;

  for (;;) {
    if (pages >= DEFAULT_MAX_PAGES) {
      const detail = `RDS ${action} hit the ${DEFAULT_MAX_PAGES}-page cap in ${ctx.region}`;
      console.error(detail);
      onIncomplete('PAGINATION_TRUNCATED', detail);
      return { items, pages, termination: 'page_cap', detail };
    }

    const result = await callQueryApi(ctx.creds, {
      service: 'rds', region: ctx.region, host, action, version: RDS_API_VERSION,
      params: { ...params, MaxRecords: PAGE_SIZE, ...(marker ? { Marker: marker } : {}) },
    });
    if (!result.ok) {
      const detail = `RDS ${action} failed in ${ctx.region} after ${pages} page(s): ${result.errorMessage ?? result.errorCode ?? result.status}`;
      console.error(`${detail} (continuing with what was read)`);
      return { items, pages, termination: 'failed', detail };
    }

    pages += 1;
    const xml = result.body as string;
    items.push(...extractListItems(extractSection(xml, listSection), itemTag));

    // <Marker> is a result-level element; no RDS list item contains one.
    const next = field(xml, 'Marker');
    if (!next) return { items, pages, termination: 'complete' };
    if (seenMarkers.has(next)) {
      const detail = `RDS ${action} returned a repeated Marker in ${ctx.region}`;
      console.error(detail);
      onIncomplete('PAGINATION_TRUNCATED', detail);
      return { items, pages, termination: 'repeated_token', detail };
    }
    seenMarkers.add(next);
    marker = next;
  }
}

// ── Shared extraction ────────────────────────────────────────────────────────

/**
 * RDS tags: `<TagList><Tag><Key>…</Key><Value>…</Value></Tag></TagList>`
 * (capitalized, unlike EC2's tagSet/item/key/value).
 */
export function rdsTags(xml: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const tag of extractListItems(extractSection(xml, 'TagList'), 'Tag')) {
    const key = field(tag, 'Key');
    if (key) out[key] = field(tag, 'Value') ?? '';
  }
  return out;
}

/** VPC security group IDs, with nulls removed (the old code kept them). */
export function vpcSecurityGroupIds(xml: string): string[] {
  return extractListItems(extractSection(xml, 'VpcSecurityGroups'), 'VpcSecurityGroupMembership')
    .map((m) => field(m, 'VpcSecurityGroupId'))
    .filter((v): v is string => !!v);
}

/** A list of plain `<member>` strings (EnabledCloudwatchLogsExports, VpcSubnetIds…). */
export function memberStrings(xml: string, section: string): string[] {
  return extractListItems(extractSection(xml, section), 'member')
    .map((s) => s.trim())
    .filter(Boolean);
}

const boolOrNull = (xml: string, name: string): boolean | null => boolField(xml, name) ?? null;
const numOrNull = (xml: string, name: string): number | null => {
  const n = numField(xml, name);
  return typeof n === 'number' && Number.isFinite(n) ? n : null;
};

/** Engines whose clusters are inventoried by their own scanners, not rds.ts. */
export const NON_RDS_CLUSTER_ENGINES: ReadonlySet<string> = new Set(['docdb', 'neptune']);

/**
 * Security + operational evidence for a DBCluster, shared by rds_cluster,
 * docdb_cluster and neptune_cluster so the three cannot drift.
 *
 * Every key the previous scanners wrote is kept with the same name and
 * meaning (engine, engineVersion, endpoint, allocatedStorageGiB, multiAz,
 * storageEncrypted, backupRetentionPeriod, createTime).
 */
export function clusterEvidence(cl: string) {
  return {
    metadata: {
      engine: field(cl, 'Engine'),
      engineVersion: field(cl, 'EngineVersion'),
      engineMode: field(cl, 'EngineMode'),
      endpoint: field(cl, 'Endpoint'),
      readerEndpoint: field(cl, 'ReaderEndpoint'),
      port: numOrNull(cl, 'Port'),
      allocatedStorageGiB: numField(cl, 'AllocatedStorage'),
      multiAz: boolField(cl, 'MultiAZ'),
      createTime: field(cl, 'ClusterCreateTime'),
      arn: field(cl, 'DBClusterArn'),
      resourceId: field(cl, 'DbClusterResourceId'),

      // Encryption at rest.
      storageEncrypted: boolField(cl, 'StorageEncrypted'),
      kmsKeyId: field(cl, 'KmsKeyId'),
      // Resilience.
      backupRetentionPeriod: numField(cl, 'BackupRetentionPeriod'),
      deletionProtection: boolOrNull(cl, 'DeletionProtection'),
      copyTagsToSnapshot: boolOrNull(cl, 'CopyTagsToSnapshot'),
      // Access.
      iamDatabaseAuthenticationEnabled: boolOrNull(cl, 'IAMDatabaseAuthenticationEnabled'),
      publiclyAccessible: boolOrNull(cl, 'PubliclyAccessible'),
      // Audit logging (e.g. DocumentDB "audit", Aurora "audit"/"postgresql").
      enabledCloudwatchLogsExports: memberStrings(cl, 'EnabledCloudwatchLogsExports'),
      autoMinorVersionUpgrade: boolOrNull(cl, 'AutoMinorVersionUpgrade'),
      memberCount: extractListItems(extractSection(cl, 'DBClusterMembers'), 'DBClusterMember').length,
    },
    relationships: {
      securityGroupIds: vpcSecurityGroupIds(cl),
      // In a DBCluster this is a plain name (unlike DBInstance's structure).
      dbSubnetGroupName: field(cl, 'DBSubnetGroup'),
      memberInstanceIds: extractListItems(extractSection(cl, 'DBClusterMembers'), 'DBClusterMember')
        .map((m) => field(m, 'DBInstanceIdentifier'))
        .filter((v): v is string => !!v),
    },
  };
}