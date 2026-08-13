import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const APPRUNNER_RESOURCE_TYPES = ['app_runner_service', 'app_runner_connection'] as const;

interface ServiceSummary { ServiceArn: string; ServiceId?: string; ServiceName?: string; ServiceUrl?: string; Status?: string; CreatedAt?: string }
interface ListServicesResponse { ServiceSummaryList?: ServiceSummary[] }
interface Connection { ConnectionArn: string; ConnectionName?: string; ProviderType?: string; Status?: string }
interface ListConnectionsResponse { ConnectionSummaryList?: Connection[] }

/** AWS App Runner — target prefix (AppRunner_20200515) follows the standard versioned-date convention, UNVERIFIED against a real account. Being sunset for new customers per AWS's own docs (March 2026), kept for existing users' visibility. */
export async function scanAppRunner(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `apprunner.${ctx.region}.amazonaws.com`;
  const call = async (target: string, body: Record<string, unknown> = {}) =>
    callJsonApi(ctx.creds, { service: 'apprunner', region: ctx.region, host, target: `AppRunner_20200515.${target}`, body });

  const out: ScannedResource[] = [];

  const servicesResult = await call('ListServices');
  if (!servicesResult.ok) {
    console.error(`App Runner ListServices failed in ${ctx.region} (continuing without it): ${servicesResult.errorMessage ?? servicesResult.errorCode ?? servicesResult.status}`);
    return out;
  }
  for (const s of (servicesResult.body as ListServicesResponse).ServiceSummaryList ?? []) {
    out.push({ resourceTypeKey: 'app_runner_service', resourceId: s.ServiceArn, region: ctx.region, resourceName: s.ServiceName, state: s.Status, metadata: { serviceUrl: s.ServiceUrl, createdAt: s.CreatedAt } });
  }

  const connResult = await call('ListConnections');
  for (const c of (connResult.ok ? (connResult.body as ListConnectionsResponse).ConnectionSummaryList : []) ?? []) {
    out.push({ resourceTypeKey: 'app_runner_connection', resourceId: c.ConnectionArn, region: ctx.region, resourceName: c.ConnectionName, state: c.Status, metadata: { providerType: c.ProviderType } });
  }

  return out;
}
