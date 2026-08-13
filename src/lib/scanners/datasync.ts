import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DATASYNC_RESOURCE_TYPES = ['datasync_location', 'datasync_task'] as const;

interface LocationListEntry { LocationArn: string; LocationUri?: string }
interface ListLocationsResponse { Locations?: LocationListEntry[] }
interface TaskListEntry { TaskArn: string; Status?: string; Name?: string }
interface ListTasksResponse { Tasks?: TaskListEntry[] }

/** AWS DataSync — target prefix (FmrsService) is a best-effort guess against AWS's internal naming, UNVERIFIED against a real account, same caveat as cloudhsm.ts. */
export async function scanDataSync(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `datasync.${ctx.region}.amazonaws.com`;
  const call = async (target: string, body: Record<string, unknown> = {}) =>
    callJsonApi(ctx.creds, { service: 'datasync', region: ctx.region, host, target: `FmrsService.${target}`, body });

  const out: ScannedResource[] = [];

  const locationsResult = await call('ListLocations');
  if (!locationsResult.ok) {
    console.error(`DataSync ListLocations failed in ${ctx.region} (continuing without it): ${locationsResult.errorMessage ?? locationsResult.errorCode ?? locationsResult.status}`);
    return out;
  }
  for (const l of (locationsResult.body as ListLocationsResponse).Locations ?? []) {
    out.push({ resourceTypeKey: 'datasync_location', resourceId: l.LocationArn, region: ctx.region, resourceName: l.LocationUri });
  }

  const tasksResult = await call('ListTasks');
  for (const t of (tasksResult.ok ? (tasksResult.body as ListTasksResponse).Tasks : []) ?? []) {
    out.push({ resourceTypeKey: 'datasync_task', resourceId: t.TaskArn, region: ctx.region, resourceName: t.Name, state: t.Status });
  }

  return out;
}
