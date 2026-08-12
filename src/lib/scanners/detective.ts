import { createAwsClient } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DETECTIVE_RESOURCE_TYPES = ['detective_graph'] as const;

interface Graph { Arn: string; CreatedTime?: string }
interface ListGraphsResponse { GraphList?: Graph[] }

/** Amazon Detective — REST-JSON, note the `api.detective.` host prefix (confirmed against AWS's API reference), not just `detective.`. Only returns a result if this account is the administrator of a behavior graph. */
export async function scanDetective(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'detective', ctx.region);
  const res = await client.fetch(`https://api.detective.${ctx.region}.amazonaws.com/graphs/list`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
  });
  const text = await res.text();
  if (!res.ok) {
    console.error(`Detective ListGraphs failed in ${ctx.region} (continuing without it — likely not enabled/not the administrator account): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const graphs = ((text ? JSON.parse(text) : {}) as ListGraphsResponse).GraphList ?? [];
  return graphs.map((g) => ({
    resourceTypeKey: 'detective_graph', resourceId: g.Arn, region: ctx.region, metadata: { createdTime: g.CreatedTime },
  }));
}
