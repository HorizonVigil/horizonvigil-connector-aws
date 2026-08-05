import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems, field, numField } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2012-12-01';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const REDSHIFT_RESOURCE_TYPES = ['redshift_cluster', 'redshift_snapshot'] as const;

/** Clusters and snapshots — one signer, 2 Query-protocol calls. Redshift repeats a named tag per list, same convention as RDS's `<DBInstance>`/ElastiCache's `<CacheCluster>`. */
export async function scanRedshift(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `redshift.${ctx.region}.amazonaws.com`;
  const call = async (action: string): Promise<string> => {
    const result = await callQueryApi(ctx.creds, { service: 'redshift', region: ctx.region, host: endpoint, action, version: VERSION });
    if (!result.ok) {
      console.error(`Redshift ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return '';
    }
    return result.body as string;
  };

  const [clusters, snapshots] = await Promise.all([call('DescribeClusters'), call('DescribeClusterSnapshots')]);

  const out: ScannedResource[] = [];
  for (const cl of extractListItems(extractSection(clusters, 'Clusters'), 'Cluster')) {
    const id = field(cl, 'ClusterIdentifier');
    if (!id) continue;
    const endpointSection = extractSection(cl, 'Endpoint');
    out.push({
      resourceTypeKey: 'redshift_cluster', resourceId: field(cl, 'ClusterNamespaceArn') ?? id, region: ctx.region, resourceName: id,
      state: field(cl, 'ClusterStatus') ?? undefined,
      metadata: {
        nodeType: field(cl, 'NodeType'), numberOfNodes: numField(cl, 'NumberOfNodes'), dbName: field(cl, 'DBName'),
        createTime: field(cl, 'ClusterCreateTime'), endpoint: endpointSection ? field(endpointSection, 'Address') : null,
        port: endpointSection ? numField(endpointSection, 'Port') : undefined,
      },
      relationships: { vpcId: field(cl, 'VpcId') },
    });
  }
  for (const sn of extractListItems(extractSection(snapshots, 'Snapshots'), 'Snapshot')) {
    const id = field(sn, 'SnapshotIdentifier');
    if (!id) continue;
    out.push({
      resourceTypeKey: 'redshift_snapshot', resourceId: id, region: ctx.region, resourceName: id,
      state: field(sn, 'Status') ?? undefined,
      metadata: { snapshotType: field(sn, 'SnapshotType'), nodeType: field(sn, 'NodeType'), createTime: field(sn, 'SnapshotCreateTime'), encrypted: field(sn, 'Encrypted') },
      relationships: { clusterIdentifier: field(sn, 'ClusterIdentifier') },
    });
  }
  return out;
}
