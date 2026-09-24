import { createAwsClient } from '../awsApi';
import { postJson, reportWalk, walkPages } from './restJson';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CONTROLTOWER_RESOURCE_TYPES = ['control_tower_landing_zone'] as const;

interface LandingZoneSummary { arn: string }
interface LandingZoneDetail {
  arn?: string; status?: string; version?: string; latestAvailableVersion?: string;
  driftStatus?: { status?: string };
}

/** Governance evidence for one landing zone; `detailsCollected: false` means NOT_ASSESSED. */
export function landingZoneEvidence(d: LandingZoneDetail | null) {
  if (!d) return { detailsCollected: false, driftStatus: null, outdated: null };
  return {
    detailsCollected: true,
    version: d.version ?? null,
    latestAvailableVersion: d.latestAvailableVersion ?? null,
    // An out-of-date landing zone misses newer guardrails and fixes.
    outdated: !!d.version && !!d.latestAvailableVersion && d.version !== d.latestAvailableVersion,
    // DRIFTED means the org's actual setup no longer matches Control Tower's.
    driftStatus: d.driftStatus?.status ?? null,
  };
}

/**
 * AWS Control Tower landing zones (REST-JSON, POST /list-landingzones). At
 * most one landing zone, only where Control Tower is set up.
 *
 * The list paginates and a failure is reported (it used to return [] and
 * parse the body unguarded). Each landing zone carries its status, version
 * against the latest available, and drift status from GetLandingZone.
 */
export async function scanControlTower(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'controltower', ctx.region);
  const base = `https://controltower.${ctx.region}.amazonaws.com`;

  const walk = await walkPages<LandingZoneSummary>(
    (token) => postJson(client, `${base}/list-landingzones`, token ? { nextToken: token } : {}),
    (b) => b.landingZones,
    (b) => b.nextToken,
  );
  reportWalk(ctx, walk, 'controltower', 'ListLandingZones');

  const out: ScannedResource[] = [];
  for (const z of walk.items) {
    if (!z?.arn) continue;
    const res = await postJson(client, `${base}/get-landingzone`, { landingZoneIdentifier: z.arn });
    const detail = res.ok ? ((res.body?.landingZone as LandingZoneDetail | undefined) ?? null) : null;
    out.push({
      resourceTypeKey: 'control_tower_landing_zone', resourceId: z.arn, region: ctx.region,
      state: detail?.status,
      metadata: landingZoneEvidence(detail),
    });
  }
  return out;
}