import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const GUARDDUTY_RESOURCE_TYPES = ['guardduty_detector'] as const;

interface DetectorDetail {
  Status?: string; CreatedAt?: string; UpdatedAt?: string; ServiceRole?: string; FindingPublishingFrequency?: string;
}

/**
 * GuardDuty is REST-JSON, like lambda.ts/eks.ts. ListDetectors returns
 * DetectorIds (AWS allows at most one per account per region, so no real
 * N+1 concern), then GetDetector fills in status/config per id.
 */
export async function scanGuardDuty(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'guardduty', ctx.region);
  const base = `https://guardduty.${ctx.region}.amazonaws.com`;
  const getJson = async (path: string): Promise<Record<string, unknown> | null> => {
    const res = await safeFetch(client, `${base}${path}`, { method: 'GET' });
    const text = await res.text();
    if (!res.ok) {
      console.error(`GuardDuty GET ${path} failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };

  const list = await getJson('/detector');
  const ids = (list?.DetectorIds as string[] | undefined) ?? [];

  const out: ScannedResource[] = [];
  for (const id of ids) {
    const detail = await getJson(`/detector/${encodeURIComponent(id)}`);
    const d = detail as DetectorDetail | null;
    out.push({
      resourceTypeKey: 'guardduty_detector', resourceId: id, region: ctx.region, resourceName: id,
      state: d?.Status,
      metadata: { createdAt: d?.CreatedAt, updatedAt: d?.UpdatedAt, findingPublishingFrequency: d?.FindingPublishingFrequency },
      relationships: { serviceRoleArn: d?.ServiceRole },
    });
  }
  return out;
}
