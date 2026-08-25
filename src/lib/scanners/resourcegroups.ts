import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const RESOURCEGROUPS_RESOURCE_TYPES = ['resource_groups_group'] as const;

interface GroupIdentifier { GroupName?: string; GroupArn: string; OwnerId?: string; Criticality?: number; Description?: string }
interface ListGroupsResponse { GroupIdentifiers?: GroupIdentifier[] }

/** AWS Resource Groups — REST-JSON, POST /groups-list (confirmed against AWS's API reference). Uses GroupIdentifiers, not the deprecated Groups field. */
export async function scanResourceGroups(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'resource-groups', ctx.region);
  const res = await safeFetch(client, `https://resource-groups.${ctx.region}.amazonaws.com/groups-list`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
  });
  const text = await res.text();
  if (!res.ok) {
    console.error(`Resource Groups ListGroups failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const groups = ((text ? JSON.parse(text) : {}) as ListGroupsResponse).GroupIdentifiers ?? [];
  return groups.map((g) => ({
    resourceTypeKey: 'resource_groups_group', resourceId: g.GroupArn, region: ctx.region, resourceName: g.GroupName,
    metadata: { ownerId: g.OwnerId, criticality: g.Criticality, description: g.Description },
  }));
}
