import { callJsonApi } from '../awsApi';
import { reportWalk, walkJsonRpc } from './restJson';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DATASYNC_RESOURCE_TYPES = ['datasync_location', 'datasync_task'] as const;

const TARGET_PREFIX = 'FmrsService';
/** DescribeTask follow-ups per region. */
const MAX_TASK_DETAILS = 25;

interface LocationListEntry { LocationArn: string; LocationUri?: string }
interface TaskListEntry { TaskArn: string; Status?: string; Name?: string; TaskMode?: string }
interface TaskDetail {
  SourceLocationArn?: string; DestinationLocationArn?: string; CloudWatchLogGroupArn?: string; TaskMode?: string;
  Options?: { VerifyMode?: string; LogLevel?: string; OverwriteMode?: string; PreserveDeletedFiles?: string };
  Schedule?: { ScheduleExpression?: string };
}

/** `s3://bucket/prefix` → "s3". Location types matter for data-flow mapping. */
export function locationType(uri: string | undefined): string | null {
  const m = /^([a-z0-9-]+):\/\//i.exec(uri ?? '');
  return m ? m[1].toLowerCase() : null;
}

/**
 * AWS DataSync locations and tasks (JSON-RPC, FmrsService).
 *
 * What changed: both lists paginate (NextToken); a failed ListLocations no
 * longer skips tasks; failures are reported. Tasks carry the data flow
 * (source → destination location), logging and verification settings from a
 * bounded DescribeTask pass; locations carry their storage type.
 */
export async function scanDataSync(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `datasync.${ctx.region}.amazonaws.com`;
  const [locations, tasks] = await Promise.all([
    walkJsonRpc<LocationListEntry>(ctx, { service: 'datasync', host, target: `${TARGET_PREFIX}.ListLocations`, body: { MaxResults: 100 } }, 'Locations'),
    walkJsonRpc<TaskListEntry>(ctx, { service: 'datasync', host, target: `${TARGET_PREFIX}.ListTasks`, body: { MaxResults: 100 } }, 'Tasks'),
  ]);
  reportWalk(ctx, locations, 'datasync', 'ListLocations');
  reportWalk(ctx, tasks, 'datasync', 'ListTasks');

  const taskList = tasks.items.filter((t) => !!t?.TaskArn);
  const details = new Map<string, TaskDetail | null>();
  await mapWithConcurrency(taskList.slice(0, MAX_TASK_DETAILS), 4, async (t) => {
    const r = await callJsonApi(ctx.creds, { service: 'datasync', region: ctx.region, host, target: `${TARGET_PREFIX}.DescribeTask`, body: { TaskArn: t.TaskArn } });
    details.set(t.TaskArn, r.ok ? ((r.body as TaskDetail) ?? null) : null);
  });

  const out: ScannedResource[] = [];
  for (const l of locations.items) {
    if (!l?.LocationArn) continue;
    out.push({
      resourceTypeKey: 'datasync_location', resourceId: l.LocationArn, region: ctx.region, resourceName: l.LocationUri,
      metadata: { locationType: locationType(l.LocationUri) },
    });
  }
  for (const t of taskList) {
    const d = details.get(t.TaskArn) ?? null;
    out.push({
      resourceTypeKey: 'datasync_task', resourceId: t.TaskArn, region: ctx.region, resourceName: t.Name, state: t.Status,
      metadata: {
        detailsCollected: d !== null,
        taskMode: t.TaskMode ?? d?.TaskMode ?? null,
        loggingEnabled: d ? !!d.CloudWatchLogGroupArn : null,
        logLevel: d?.Options?.LogLevel ?? null,
        verifyMode: d?.Options?.VerifyMode ?? null,
        overwriteMode: d?.Options?.OverwriteMode ?? null,
        scheduled: d ? !!d.Schedule?.ScheduleExpression : null,
      },
      relationships: {
        sourceLocationArn: d?.SourceLocationArn ?? null,
        destinationLocationArn: d?.DestinationLocationArn ?? null,
        cloudWatchLogGroupArn: d?.CloudWatchLogGroupArn ?? null,
      },
    });
  }
  return out;
}