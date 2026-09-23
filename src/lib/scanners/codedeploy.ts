import { callJsonApi } from '../awsApi';
import { reportWalk, toIso, walkJsonRpc } from './restJson';
import { mapWithConcurrency, reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CODEDEPLOY_RESOURCE_TYPES = ['codedeploy_application'] as const;

const TARGET_PREFIX = 'CodeDeploy_20141006';
/** BatchGetApplications accepts at most 100 names per call. */
const BATCH_SIZE = 100;

interface ApplicationInfo {
  applicationId?: string; applicationName?: string; applicationArn?: string; computePlatform?: string; createTime?: number;
  linkedToGitHub?: boolean; gitHubAccountName?: string;
}

const chunk = <T>(xs: T[], n: number): T[][] => Array.from({ length: Math.ceil(xs.length / n) }, (_, i) => xs.slice(i * n, i * n + n));

/**
 * CodeDeploy applications (JSON-RPC, CodeDeploy_20141006).
 *
 * What changed, and why:
 *  - ListApplications paginates (nextToken) and BatchGetApplications runs in
 *    chunks of 100; the previous version silently kept the first 25.
 *  - A failed detail batch used to return [] for the whole scan; it now
 *    reports that batch and keeps the rest.
 *  - `applicationName!` (a non-null assertion on provider data) is gone: an
 *    application with no id and no name is recorded with an empty id, which
 *    admission quarantines with a typed reason.
 *
 * Identity note: ApplicationInfo carries no ARN field, so resourceId is the
 * applicationId -- the same value existing rows already use.
 */
export async function scanCodeDeploy(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `codedeploy.${ctx.region}.amazonaws.com`;
  const list = await walkJsonRpc<string>(ctx, { service: 'codedeploy', host, target: `${TARGET_PREFIX}.ListApplications`, body: {} }, 'applications', { tokenIn: 'nextToken', tokenOut: 'nextToken' });
  reportWalk(ctx, list, 'codedeploy', 'ListApplications');
  const names = [...new Set(list.items.filter((n): n is string => typeof n === 'string' && n !== ''))];
  if (names.length === 0) return [];

  const batches = await mapWithConcurrency(chunk(names, BATCH_SIZE), 3, async (batch) => {
    const r = await callJsonApi(ctx.creds, { service: 'codedeploy', region: ctx.region, host, target: `${TARGET_PREFIX}.BatchGetApplications`, body: { applicationNames: batch } });
    return r.ok ? ((r.body as { applicationsInfo?: ApplicationInfo[] })?.applicationsInfo ?? []) : null;
  });
  if (batches.some((b) => b === null)) {
    console.error(`CodeDeploy BatchGetApplications failed for some applications in ${ctx.region}; coverage degraded.`);
    reportListingFailure(ctx, { service: 'codedeploy', action: 'BatchGetApplications', region: ctx.region });
  }

  const out: ScannedResource[] = [];
  for (const apps of batches) {
    for (const a of apps ?? []) {
      if (!a) continue;
      out.push({
        resourceTypeKey: 'codedeploy_application', resourceId: a.applicationArn ?? a.applicationId ?? a.applicationName ?? '', region: ctx.region, resourceName: a.applicationName,
        metadata: {
          computePlatform: a.computePlatform, createTime: a.createTime, createdAtIso: toIso(a.createTime),
          linkedToGitHub: a.linkedToGitHub ?? false,
          gitHubAccountName: a.gitHubAccountName ?? null,
        },
      });
    }
  }
  return out;
}