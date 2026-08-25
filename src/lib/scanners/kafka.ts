import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const KAFKA_RESOURCE_TYPES = ['msk_cluster'] as const;

interface ClusterInfo {
  clusterArn: string; clusterName: string; clusterType?: string; state?: string; creationTime?: string;
}

/** REST-JSON like Lambda/Batch. ListClustersV2 covers both provisioned and serverless MSK clusters in one call, unlike the older v1 ListClusters which only returns provisioned. */
export async function scanKafka(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'kafka', ctx.region);
  const res = await safeFetch(client, `https://kafka.${ctx.region}.amazonaws.com/v1/clusters/v2`, { method: 'GET' });
  const text = await res.text();
  if (!res.ok) {
    console.error(`MSK ListClustersV2 failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }
  const body = text ? (JSON.parse(text) as { clusterInfoList?: ClusterInfo[] }) : {};

  return (body.clusterInfoList ?? []).map((c) => ({
    resourceTypeKey: 'msk_cluster', resourceId: c.clusterArn, region: ctx.region, resourceName: c.clusterName,
    state: c.state, metadata: { clusterType: c.clusterType, createdAt: c.creationTime },
  }));
}
