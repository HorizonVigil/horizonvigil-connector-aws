import { Hono, getAuthContext, requireOrgId, createDb, requireRole, requireMember, getOrgConnectionIds, inFilter, writeAuditLog, guarded, okJson, errJson, type Db } from '@cloudops360/shared-lib';
import type { Env } from '../env';
import { decryptCredentials } from '../lib/crypto';
import { assumeConnectionRole } from '../lib/assumeRole';
import { runFullValidation, type PermissionCheckResult } from '../lib/permissionChecks';
import type { AwsCreds } from '../lib/awsApi';

export const permissionsRoutes = new Hono<{ Bindings: Env }>();

export interface ResolvableConnection {
  id: string;
  connection_method: 'access_key' | 'cross_account_role';
  credentials_encrypted: { iv: string; ciphertext: string } | null;
  role_arn: string | null;
  external_id: string | null;
  default_region: string;
}

/** Shared by any route that needs to make a real AWS call with a connection's own credentials (permission validation, cost sync, ...). */
export async function resolveCredentials(env: Env, connection: ResolvableConnection): Promise<{ creds: AwsCreds } | { error: string }> {
  if (connection.connection_method === 'access_key') {
    if (!connection.credentials_encrypted?.ciphertext) return { error: 'No credentials stored for this connection.' };
    const decrypted = await decryptCredentials(env.ENCRYPTION_KEY, connection.credentials_encrypted);
    return { creds: { accessKeyId: decrypted.accessKeyId, secretAccessKey: decrypted.secretAccessKey } };
  }
  if (!connection.role_arn || !connection.external_id) return { error: 'No role ARN / external ID stored for this connection.' };
  const assumed = await assumeConnectionRole(
    { accessKeyId: env.PLATFORM_AWS_ACCESS_KEY_ID, secretAccessKey: env.PLATFORM_AWS_SECRET_ACCESS_KEY },
    connection.role_arn,
    connection.external_id,
  );
  if (!assumed.ok || !assumed.credentials) return { error: assumed.reason ?? 'Could not assume the connection role.' };
  return { creds: assumed.credentials };
}

/**
 * POST /api/aws-accounts/accounts/:id/permissions/validate — runs real
 * sts:GetCallerIdentity + IAM/Organizations/CloudWatch/CloudTrail/Tagging/
 * Cost Explorer permission probes against the connection's own credentials
 * (or an assumed role), records the run + every check, and updates the
 * connection's status/last_permission_check_at. Editor+ (same bar as
 * triggering any scan/sync elsewhere in this app).
 */
permissionsRoutes.post('/accounts/:id/permissions/validate', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireRole(db, auth.userId, orgId, ['editor'], true);

    const rows = await db.select<ResolvableConnection[]>('cloud_connections', {
      select: 'id,connection_method,credentials_encrypted,role_arn,external_id,default_region',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const connection = rows[0];
    if (!connection) return errJson(404, 'Account not found');

    const [run] = await db.insert<{ id: string }[]>('connection_validation_runs', {
      connection_id: connection.id,
      status: 'running',
      triggered_by: auth.userId,
    });

    // Everything from here on can throw (decryption, the AWS calls themselves,
    // a bad env var) — without this try/catch, an exception would leave the
    // 'running' row above orphaned forever, since nothing else ever marks it
    // failed. Every exit path below must resolve that row one way or another.
    try {
      const resolved = await resolveCredentials(c.env, connection);
      if ('error' in resolved) {
        await db.update('connection_validation_runs', { id: `eq.${run.id}` }, { status: 'failed', finished_at: new Date().toISOString(), error_message: resolved.error }, 'return=minimal');
        await db.update('cloud_connections', { id: `eq.${connection.id}` }, { last_permission_check_at: new Date().toISOString() }, 'return=minimal');
        await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'aws_account.permission_validation_failed', targetType: 'cloud_connection', targetId: connection.id, metadata: { reason: resolved.error } });
        return okJson({ status: 'failed', errorMessage: resolved.error, identity: null, checks: [] });
      }

      const { identity, checks } = await runFullValidation(resolved.creds, connection.default_region || 'us-east-1');
      const overallStatus = checks[0]?.status === 'granted' ? 'succeeded' : 'failed';

      await db.update(
        'connection_validation_runs',
        { id: `eq.${run.id}` },
        {
          status: overallStatus,
          finished_at: new Date().toISOString(),
          identity_arn: identity?.arn ?? null,
          identity_account_id: identity?.accountId ?? null,
          identity_user_id: identity?.userId ?? null,
          error_message: overallStatus === 'failed' ? checks[0]?.detail : null,
        },
        'return=minimal',
      );

      if (checks.length > 0) {
        await db.insert(
          'connection_permission_checks',
          checks.map((check) => ({ run_id: run.id, service: check.service, label: check.label, status: check.status, detail: check.detail, verified: check.verified })),
          'return=minimal',
        );
      }

      const connectionPatch: Record<string, unknown> = { last_permission_check_at: new Date().toISOString() };
      if (overallStatus === 'succeeded') {
        connectionPatch.status = 'connected';
        connectionPatch.error_message = null;
      } else {
        connectionPatch.status = 'error';
        connectionPatch.error_message = checks[0]?.detail ?? 'Validation failed';
      }
      await db.update('cloud_connections', { id: `eq.${connection.id}` }, connectionPatch, 'return=minimal');

      await writeAuditLog(db, {
        orgId,
        actorId: auth.userId,
        action: overallStatus === 'succeeded' ? 'aws_account.permission_validation_succeeded' : 'aws_account.permission_validation_failed',
        targetType: 'cloud_connection',
        targetId: connection.id,
        metadata: { checks: checks.map((ck) => ({ service: ck.service, status: ck.status })) },
      });

      return okJson({ status: overallStatus, identity, checks });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Validation crashed unexpectedly';
      await db.update('connection_validation_runs', { id: `eq.${run.id}` }, { status: 'failed', finished_at: new Date().toISOString(), error_message: message }, 'return=minimal');
      await db.update('cloud_connections', { id: `eq.${connection.id}` }, { status: 'error', error_message: message, last_permission_check_at: new Date().toISOString() }, 'return=minimal');
      await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'aws_account.permission_validation_failed', targetType: 'cloud_connection', targetId: connection.id, metadata: { reason: message } });
      return errJson(500, message);
    }
  }),
);

async function latestRunFor(db: Db, connectionId: string) {
  const runs = await db.select<{ id: string; status: string; identity_arn: string | null; identity_account_id: string | null; started_at: string; finished_at: string | null; error_message: string | null }[]>(
    'connection_validation_runs',
    { select: 'id,status,identity_arn,identity_account_id,started_at,finished_at,error_message', filters: { connection_id: `eq.${connectionId}` }, order: 'started_at.desc', limit: 1 },
  );
  const run = runs[0];
  if (!run) return null;
  const checks = await db.select<PermissionCheckResult[]>('connection_permission_checks', { select: 'service,label,status,detail,verified', filters: { run_id: `eq.${run.id}` } });
  return { run, checks };
}

/** GET /api/aws-accounts/accounts/:id/permissions — the most recent validation run + its checks, without re-running anything. */
permissionsRoutes.get('/accounts/:id/permissions', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMember(db, auth.userId, orgId);

    const latest = await latestRunFor(db, c.req.param('id'));
    return okJson(latest ?? { run: null, checks: [] });
  }),
);

/** GET /api/aws-accounts/accounts/:id/sync-history — every validation run for one account, newest first. */
permissionsRoutes.get('/accounts/:id/sync-history', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMember(db, auth.userId, orgId);

    const runs = await db.select('connection_validation_runs', {
      select: 'id,status,identity_arn,identity_account_id,started_at,finished_at,error_message,triggered_by',
      filters: { connection_id: `eq.${c.req.param('id')}` },
      order: 'started_at.desc',
      limit: 50,
    });
    return okJson({ runs });
  }),
);

/** GET /api/aws-accounts/permissions — org-wide summary: latest run's overall status per connection, for the Permission Validation overview. */
permissionsRoutes.get('/permissions', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMember(db, auth.userId, orgId);

    const connectionIds = await getOrgConnectionIds(db, orgId);
    const connections = await db.select<{ id: string; connection_name: string; last_permission_check_at: string | null }[]>('cloud_connections', {
      select: 'id,connection_name,last_permission_check_at',
      filters: { id: inFilter(connectionIds), provider: 'eq.aws' },
    });

    const summaries = await Promise.all(
      connections.map(async (conn) => {
        const latest = await latestRunFor(db, conn.id);
        const deniedCount = latest?.checks.filter((ck) => ck.status === 'denied').length ?? 0;
        const errorCount = latest?.checks.filter((ck) => ck.status === 'error').length ?? 0;
        return {
          connectionId: conn.id,
          connectionName: conn.connection_name,
          lastCheckedAt: conn.last_permission_check_at,
          overallStatus: latest?.run.status ?? 'never_run',
          deniedCount,
          errorCount,
          checks: latest?.checks ?? [],
        };
      }),
    );

    return okJson({ accounts: summaries });
  }),
);
