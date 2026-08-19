import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, errJson, guarded, okJson, type Db } from '@cloudops360/shared-lib';
import type { Env } from '../env';
import { resolveCredentials, type ResolvableConnection } from './permissions';
import { callJsonApi } from '../lib/awsApi';

export const logsRoutes = new Hono<{ Bindings: Env }>();

/**
 * Phase 4 of the admin-console investigation-infrastructure roadmap, real
 * log access -- deliberately NOT an ingestion pipeline. CloudWatch Logs is
 * already the real log store, already indexed, already retained per the
 * customer's own policy; duplicating that into our own DB would mean
 * re-solving storage/retention/cost for data AWS already manages, for a
 * read pattern that's actually narrow: "show me logs around this
 * incident's timestamp," not "full-text search all history." So this
 * calls FilterLogEvents live, on demand, scoped to one resource and a
 * tight time window, and returns results directly -- nothing is ever
 * stored here.
 *
 * Scoped to Lambda functions only in this pass: CloudWatch's log-group
 * naming for Lambda is a fixed convention (/aws/lambda/{function-name}),
 * so no configuration-guessing is needed. ECS/EC2 log groups are
 * per-task-definition/per-agent-config, not derivable from a resource ID
 * alone -- a real future phase, not something to fake here.
 */
async function loadConnectionForCreds(db: Db, orgId: string, connectionId: string): Promise<ResolvableConnection | null> {
  const rows = await db.select<ResolvableConnection[]>('cloud_connections', {
    select: 'id,connection_method,credentials_encrypted,role_arn,external_id,default_region',
    filters: { id: `eq.${connectionId}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
  });
  return rows[0] ?? null;
}

interface ResourceRow { id: string; connection_id: string; resource_type_key: string; resource_name: string | null; region: string | null }

interface FilteredEvent { timestamp?: number; message?: string; logStreamName?: string }

/** GET /api/aws-accounts/accounts/:id/resources/:resourceId/logs?from=&to= — from/to are ISO timestamps; defaults to the last hour if omitted. */
logsRoutes.get('/accounts/:id/resources/:resourceId/logs', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'monitoring', 'read');

    const resources = await db.select<ResourceRow[]>('cloud_resources', {
      select: 'id,connection_id,resource_type_key,resource_name,region',
      filters: { id: `eq.${c.req.param('resourceId')}`, connection_id: `eq.${c.req.param('id')}` },
    });
    const resource = resources[0];
    if (!resource) return errJson(404, 'Resource not found');
    if (resource.resource_type_key !== 'lambda_function') {
      return errJson(400, `Log access is only wired up for Lambda functions in this pass, not "${resource.resource_type_key}".`);
    }
    if (!resource.resource_name || !resource.region) return errJson(400, 'This resource has no name/region on record — re-run Discover Resources.');

    const connection = await loadConnectionForCreds(db, orgId, resource.connection_id);
    if (!connection) return errJson(404, 'Account not found');
    const resolved = await resolveCredentials(c.env, connection);
    if ('error' in resolved) return errJson(400, resolved.error);

    const url = new URL(c.req.url);
    const toParam = url.searchParams.get('to');
    const fromParam = url.searchParams.get('from');
    const endTime = toParam ? new Date(toParam).getTime() : Date.now();
    const startTime = fromParam ? new Date(fromParam).getTime() : endTime - 60 * 60 * 1000;

    const logGroupName = `/aws/lambda/${resource.resource_name}`;
    const host = `logs.${resource.region}.amazonaws.com`;
    const result = await callJsonApi(resolved.creds, {
      service: 'logs', region: resource.region, host, target: 'Logs_20140328.FilterLogEvents',
      body: { logGroupName, startTime, endTime, limit: 1000 },
    });

    if (!result.ok) {
      // A log group that's never been created (function never invoked) is
      // an honest empty result, not a real error -- ResourceNotFoundException.
      if (result.errorCode === 'ResourceNotFoundException') return okJson({ logGroupName, events: [] });
      return errJson(result.status === 403 ? 403 : 502, result.errorMessage ?? `CloudWatch Logs request failed (${result.status})`);
    }

    const events = ((result.body as { events?: FilteredEvent[] }).events ?? []).map((e) => ({
      timestamp: e.timestamp ? new Date(e.timestamp).toISOString() : null,
      message: e.message ?? '',
      logStream: e.logStreamName ?? null,
    }));

    return okJson({ logGroupName, events });
  }),
);
