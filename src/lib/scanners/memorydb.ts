import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const MEMORYDB_RESOURCE_TYPES = ['memorydb_cluster'] as const;

interface Cluster { Name: string; ARN?: string; Status?: string; NodeType?: string; NumberOfShards?: number; Engine?: string; EngineVersion?: string }
interface DescribeClustersResponse { Clusters?: Cluster[] }

/** Amazon MemoryDB — target prefix (AmazonMemoryDB) is a best-effort guess against AWS's simpler modern service-naming convention, UNVERIFIED against a real account. */
export async function scanMemoryDb(ctx: ScannerContext): Promise<ScannedResource[]> {
  const result = await callJsonApi(ctx.creds, {
    service: 'memorydb', region: ctx.region, host: `memory-db.${ctx.region}.amazonaws.com`,
    target: 'AmazonMemoryDB.DescribeClusters', body: {},
  });
  if (!result.ok) {
    console.error(`MemoryDB DescribeClusters failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const clusters = (result.body as DescribeClustersResponse).Clusters ?? [];
  return clusters.map((c) => ({
    resourceTypeKey: 'memorydb_cluster', resourceId: c.ARN ?? c.Name, region: ctx.region, resourceName: c.Name,
    state: c.Status, metadata: { nodeType: c.NodeType, numberOfShards: c.NumberOfShards, engine: c.Engine, engineVersion: c.EngineVersion },
  }));
}
