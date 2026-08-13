import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CODEDEPLOY_RESOURCE_TYPES = ['codedeploy_application'] as const;

interface ListApplicationsResponse { applications?: string[] }
interface ApplicationInfo { applicationId?: string; applicationName?: string; applicationArn?: string; computePlatform?: string; createTime?: number }
interface BatchGetApplicationsResponse { applicationsInfo?: ApplicationInfo[] }

export async function scanCodeDeploy(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `codedeploy.${ctx.region}.amazonaws.com`;
  const call = async (target: string, body: Record<string, unknown> = {}) =>
    callJsonApi(ctx.creds, { service: 'codedeploy', region: ctx.region, host, target: `CodeDeploy_20141006.${target}`, body });

  const listResult = await call('ListApplications');
  if (!listResult.ok) {
    console.error(`CodeDeploy ListApplications failed in ${ctx.region} (continuing without it): ${listResult.errorMessage ?? listResult.errorCode ?? listResult.status}`);
    return [];
  }
  const names = (listResult.body as ListApplicationsResponse).applications ?? [];
  if (names.length === 0) return [];

  const detailResult = await call('BatchGetApplications', { applicationNames: names.slice(0, 25) });
  if (!detailResult.ok) {
    console.error(`CodeDeploy BatchGetApplications failed in ${ctx.region} (continuing without it): ${detailResult.errorMessage ?? detailResult.errorCode ?? detailResult.status}`);
    return [];
  }

  const apps = (detailResult.body as BatchGetApplicationsResponse).applicationsInfo ?? [];
  return apps.map((a) => ({
    resourceTypeKey: 'codedeploy_application', resourceId: a.applicationArn ?? a.applicationId ?? a.applicationName!, region: ctx.region, resourceName: a.applicationName,
    metadata: { computePlatform: a.computePlatform, createTime: a.createTime },
  }));
}
