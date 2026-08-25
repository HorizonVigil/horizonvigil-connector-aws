import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const RESILIENCEHUB_RESOURCE_TYPES = ['resiliencehub_app'] as const;

interface AppSummary {
  appArn: string; name?: string; status?: string; complianceStatus?: string; resiliencyScore?: number;
  rtoInSecs?: number; rpoInSecs?: number; creationTime?: number;
}
interface ListAppsResponse { appSummaries?: AppSummary[] }

/** AWS Resilience Hub — REST-JSON, GET with query params (confirmed against AWS's API reference), not a JSON body. */
export async function scanResilienceHub(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'resiliencehub', ctx.region);
  const res = await safeFetch(client, `https://resiliencehub.${ctx.region}.amazonaws.com/list-apps`, { method: 'GET' });
  const text = await res.text();
  if (!res.ok) {
    console.error(`Resilience Hub ListApps failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const apps = ((text ? JSON.parse(text) : {}) as ListAppsResponse).appSummaries ?? [];
  return apps.map((a) => ({
    resourceTypeKey: 'resiliencehub_app', resourceId: a.appArn, region: ctx.region, resourceName: a.name,
    state: a.status, metadata: { complianceStatus: a.complianceStatus, resiliencyScore: a.resiliencyScore, rtoInSecs: a.rtoInSecs, rpoInSecs: a.rpoInSecs, creationTime: a.creationTime },
  }));
}
