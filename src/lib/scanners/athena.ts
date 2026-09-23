import { callJsonApi } from '../awsApi';
import { reportWalk, toIso, walkJsonRpc } from './restJson';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AmazonAthena';
/** GetWorkGroup follow-ups per region (encryption / enforcement evidence). */
const MAX_WORKGROUP_DETAILS = 30;
const DETAIL_CONCURRENCY = 4;

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ATHENA_RESOURCE_TYPES = ['athena_workgroup', 'athena_data_catalog'] as const;

interface WorkGroupSummary {
  Name: string; State?: string; Description?: string; CreationTime?: number;
  EngineVersion?: { EffectiveEngineVersion?: string };
}
interface DataCatalogSummary { CatalogName: string; Type?: string; Status?: string; ConnectionType?: string }
interface WorkGroupConfiguration {
  ResultConfiguration?: {
    OutputLocation?: string;
    EncryptionConfiguration?: { EncryptionOption?: string; KmsKey?: string };
    ExpectedBucketOwner?: string;
    AclConfiguration?: { S3AclOption?: string };
  };
  EnforceWorkGroupConfiguration?: boolean;
  PublishCloudWatchMetricsEnabled?: boolean;
  BytesScannedCutoffPerQuery?: number;
  ExecutionRole?: string;
}

/** Evidence from GetWorkGroup; `configurationCollected: false` means NOT_ASSESSED. */
export function workgroupEvidence(config: WorkGroupConfiguration | null) {
  if (!config) {
    return { configurationCollected: false, resultsEncrypted: null, encryptionOption: null, enforceWorkGroupConfiguration: null, outputLocation: null, publishCloudWatchMetricsEnabled: null, bytesScannedCutoffPerQuery: null };
  }
  const enc = config.ResultConfiguration?.EncryptionConfiguration;
  return {
    configurationCollected: true,
    // Query results at rest (FSBP Athena: workgroups should encrypt results).
    resultsEncrypted: !!enc?.EncryptionOption,
    encryptionOption: enc?.EncryptionOption ?? null,
    kmsKey: enc?.KmsKey ?? null,
    // Without enforcement, any client-side setting overrides the workgroup's encryption.
    enforceWorkGroupConfiguration: config.EnforceWorkGroupConfiguration ?? false,
    outputLocation: config.ResultConfiguration?.OutputLocation ?? null,
    expectedBucketOwner: config.ResultConfiguration?.ExpectedBucketOwner ?? null,
    publishCloudWatchMetricsEnabled: config.PublishCloudWatchMetricsEnabled ?? false,
    bytesScannedCutoffPerQuery: config.BytesScannedCutoffPerQuery ?? null,
    executionRole: config.ExecutionRole ?? null,
  };
}

/**
 * Athena workgroups and data catalogs.
 *
 * Both lists paginate now (NextToken); failures are reported so finalize
 * does not read a failed list as deletions. Each workgroup carries results
 * encryption and enforcement evidence from a bounded GetWorkGroup pass.
 */
export async function scanAthena(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `athena.${ctx.region}.amazonaws.com`;
  const [wgWalk, dcWalk] = await Promise.all([
    walkJsonRpc<WorkGroupSummary>(ctx, { service: 'athena', host, target: `${TARGET_PREFIX}.ListWorkGroups`, body: { MaxResults: 50 } }, 'WorkGroups'),
    walkJsonRpc<DataCatalogSummary>(ctx, { service: 'athena', host, target: `${TARGET_PREFIX}.ListDataCatalogs`, body: { MaxResults: 50 } }, 'DataCatalogsSummary'),
  ]);
  reportWalk(ctx, wgWalk, 'athena', 'ListWorkGroups');
  reportWalk(ctx, dcWalk, 'athena', 'ListDataCatalogs');

  const workgroups = wgWalk.items.filter((w) => !!w?.Name);
  const configs = new Map<string, WorkGroupConfiguration | null>();
  await mapWithConcurrency(workgroups.slice(0, MAX_WORKGROUP_DETAILS), DETAIL_CONCURRENCY, async (wg) => {
    const r = await callJsonApi(ctx.creds, { service: 'athena', region: ctx.region, host, target: `${TARGET_PREFIX}.GetWorkGroup`, body: { WorkGroup: wg.Name } });
    configs.set(wg.Name, r.ok ? ((r.body as { WorkGroup?: { Configuration?: WorkGroupConfiguration } })?.WorkGroup?.Configuration ?? {}) : null);
  });

  const out: ScannedResource[] = [];
  for (const wg of workgroups) {
    out.push({
      resourceTypeKey: 'athena_workgroup', resourceId: wg.Name, region: ctx.region, resourceName: wg.Name,
      state: wg.State,
      metadata: {
        description: wg.Description, createdAt: wg.CreationTime, createdAtIso: toIso(wg.CreationTime),
        engineVersion: wg.EngineVersion?.EffectiveEngineVersion,
        ...workgroupEvidence(configs.get(wg.Name) ?? null),
      },
    });
  }
  for (const dc of dcWalk.items) {
    if (!dc?.CatalogName) continue;
    out.push({
      resourceTypeKey: 'athena_data_catalog', resourceId: dc.CatalogName, region: ctx.region, resourceName: dc.CatalogName,
      state: dc.Status,
      metadata: { type: dc.Type, connectionType: dc.ConnectionType ?? null },
    });
  }
  return out;
}