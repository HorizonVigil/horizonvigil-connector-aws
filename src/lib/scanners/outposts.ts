import { createAwsClient } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const OUTPOSTS_RESOURCE_TYPES = ['outposts_outpost'] as const;

interface Outpost { OutpostId: string; OutpostArn?: string; Name?: string; LifeCycleStatus?: string; SiteId?: string; AvailabilityZone?: string }
interface ListOutpostsResponse { Outposts?: Outpost[] }

/** AWS Outposts — REST-JSON, GET /outposts. UNVERIFIED against a real account. */
export async function scanOutposts(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'outposts', ctx.region);
  const res = await client.fetch(`https://outposts.${ctx.region}.amazonaws.com/outposts`, { method: 'GET' });
  const text = await res.text();
  if (!res.ok) {
    console.error(`Outposts ListOutposts failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const outposts = ((text ? JSON.parse(text) : {}) as ListOutpostsResponse).Outposts ?? [];
  return outposts.map((o) => ({
    resourceTypeKey: 'outposts_outpost', resourceId: o.OutpostArn ?? o.OutpostId, region: ctx.region, resourceName: o.Name,
    state: o.LifeCycleStatus, metadata: { siteId: o.SiteId, availabilityZone: o.AvailabilityZone },
  }));
}
