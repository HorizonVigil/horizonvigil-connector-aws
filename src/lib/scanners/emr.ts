import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'ElasticMapReduce';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const EMR_RESOURCE_TYPES = ['emr_cluster'] as const;

interface ClusterSummary {
  Id: string; Name?: string; NormalizedInstanceHours?: number;
  Status?: { State?: string; Timeline?: { CreationDateTime?: number } };
}

/**
 * ListClusters without a ClusterStates filter defaults to active states
 * (STARTING/BOOTSTRAPPING/RUNNING/WAITING/TERMINATING) — this deliberately
 * doesn't pass one, so terminated clusters (EMR's overwhelming majority in
 * any account with real usage history) don't flood the inventory.
 */
export async function scanEmr(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `elasticmapreduce.${ctx.region}.amazonaws.com`;
  const result = await callJsonApi(ctx.creds, { service: 'elasticmapreduce', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListClusters`, body: {} });
  if (!result.ok) {
    console.error(`EMR ListClusters failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  return ((result.body as { Clusters?: ClusterSummary[] }).Clusters ?? []).map((c) => ({
    resourceTypeKey: 'emr_cluster', resourceId: c.Id, region: ctx.region, resourceName: c.Name,
    state: c.Status?.State,
    metadata: { normalizedInstanceHours: c.NormalizedInstanceHours, createdAt: c.Status?.Timeline?.CreationDateTime },
  }));
}
