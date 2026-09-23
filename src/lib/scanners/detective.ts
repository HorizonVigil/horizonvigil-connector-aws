import { createAwsClient } from '../awsApi';
import { postJson, reportWalk, walkPages } from './restJson';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DETECTIVE_RESOURCE_TYPES = ['detective_graph'] as const;

interface Graph { Arn: string; CreatedTime?: string }

/**
 * Amazon Detective behavior graphs (REST-JSON; note the `api.detective.`
 * host prefix). A graph is only listed when this account administers it; an
 * account with Detective off gets an empty list, not an error.
 *
 * ListGraphs now paginates and a real failure is reported (it used to return
 * [] and parse the body unguarded).
 */
export async function scanDetective(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'detective', ctx.region);
  const walk = await walkPages<Graph>(
    (token) => postJson(client, `https://api.detective.${ctx.region}.amazonaws.com/graphs/list`, { MaxResults: 200, ...(token ? { NextToken: token } : {}) }),
    (b) => b.GraphList,
    (b) => b.NextToken,
  );
  reportWalk(ctx, walk, 'detective', 'ListGraphs');

  return walk.items.filter((g) => !!g?.Arn).map((g) => ({
    resourceTypeKey: 'detective_graph', resourceId: g.Arn, region: ctx.region, metadata: { createdTime: g.CreatedTime },
  }));
}