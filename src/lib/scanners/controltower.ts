import { createAwsClient } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CONTROLTOWER_RESOURCE_TYPES = ['control_tower_landing_zone'] as const;

interface LandingZoneSummary { arn: string }
interface ListLandingZonesResponse { landingZones?: LandingZoneSummary[] }

/** AWS Control Tower — REST-JSON, path confirmed against AWS's API reference (`/list-landingzones`, no hyphen before "landingzones"). Returns at most one landing zone, only in accounts where Control Tower is actually set up. */
export async function scanControlTower(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'controltower', ctx.region);
  const res = await client.fetch(`https://controltower.${ctx.region}.amazonaws.com/list-landingzones`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
  });
  const text = await res.text();
  if (!res.ok) {
    console.error(`Control Tower ListLandingZones failed in ${ctx.region} (continuing without it — likely not set up there): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const zones = ((text ? JSON.parse(text) : {}) as ListLandingZonesResponse).landingZones ?? [];
  return zones.map((z) => ({ resourceTypeKey: 'control_tower_landing_zone', resourceId: z.arn, region: ctx.region }));
}
