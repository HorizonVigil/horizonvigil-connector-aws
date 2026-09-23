import { field } from '../xmlList';
import { clusterEvidence, describeAllRds, rdsTags } from './rdsQuery';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const NEPTUNE_RESOURCE_TYPES = ['neptune_cluster'] as const;

/**
 * Neptune clusters: same shared-RDS-API-filtered-by-engine shape as docdb.ts
 * ("neptune" is an engine value on the RDS control plane, not a separate
 * signing service), filtered server-side to the neptune engine. rds.ts
 * excludes neptune clusters from rds_cluster so the same cluster is never
 * inventoried twice.
 *
 * Every page is read (see rdsQuery.ts): the previous version read only the
 * first 100 clusters, and finalize read the rest as deleted.
 *
 * resourceId stays the DBClusterIdentifier (unique per account+region) so
 * existing rows keep their identity; the ARN is carried in metadata.
 */
export async function scanNeptune(ctx: ScannerContext): Promise<ScannedResource[]> {
  const walk = await describeAllRds(ctx, 'DescribeDBClusters', 'DBClusters', 'DBCluster', {
    'Filters.member.1.Name': 'engine', 'Filters.member.1.Values.member.1': 'neptune',
  });

  const out: ScannedResource[] = [];
  for (const cl of walk.items) {
    // Defence in depth: the server-side filter is authoritative, but a
    // non-neptune cluster must never be recorded under this type.
    const engine = field(cl, 'Engine');
    if (engine && engine !== 'neptune') continue;
    const id = field(cl, 'DBClusterIdentifier');
    const evidence = clusterEvidence(cl);
    const tags = rdsTags(cl);
    out.push({
      // `?? ''` not `continue`: admission quarantines an empty identity with a
      // typed reason instead of the record vanishing silently.
      resourceTypeKey: 'neptune_cluster', resourceId: id ?? '', region: ctx.region,
      resourceName: tags['Name'] ?? id ?? undefined, state: field(cl, 'Status') ?? undefined, tags,
      metadata: { ...evidence.metadata, walkComplete: walk.termination === 'complete' },
      relationships: evidence.relationships,
    });
  }
  return out;
}