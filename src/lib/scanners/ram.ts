import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const RAM_RESOURCE_TYPES = ['ram_resource_share'] as const;

interface ResourceShare { resourceShareArn: string; name?: string; status?: string; owningAccountId?: string; creationTime?: number }
interface GetResourceSharesResponse { resourceShares?: ResourceShare[] }

/** AWS Resource Access Manager — REST-JSON, POST-with-body (not GET) since resourceOwner is a required parameter. */
export async function scanRam(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'ram', ctx.region);
  const res = await safeFetch(client, `https://ram.${ctx.region}.amazonaws.com/getresourceshares`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ resourceOwner: 'SELF' }),
  });
  const text = await res.text();
  if (!res.ok) {
    console.error(`RAM GetResourceShares failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const shares = ((text ? JSON.parse(text) : {}) as GetResourceSharesResponse).resourceShares ?? [];
  return shares.filter((s) => s.status !== 'DELETED').map((s) => ({
    resourceTypeKey: 'ram_resource_share', resourceId: s.resourceShareArn, region: ctx.region, resourceName: s.name,
    state: s.status, metadata: { owningAccountId: s.owningAccountId, creationTime: s.creationTime },
  }));
}
