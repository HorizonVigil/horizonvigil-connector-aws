import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, getOrgConnectionIds, inFilter, writeAuditLog, guarded, okJson, errJson, type Db, getActiveScope, requirePermittedConnection } from '@horizonvigil/shared-lib';
import { buildCapabilityStatuses, writeCapabilityStatuses } from '../lib/capabilityStatus';
import type { Env } from '../env';
import { decryptCredentials } from '../lib/crypto';
import { assumeConnectionRole } from '../lib/assumeRole';
import { runFullValidation, type PermissionCheckResult, type IdentitySummary } from '../lib/permissionChecks';
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

type ValidationOutcome =
  | { crashed: true; message: string }
  | { crashed: false; status: 'succeeded' | 'failed'; identity: IdentitySummary | null; checks: PermissionCheckResult[]; errorMessage?: string };

/**
 * Runs real sts:GetCallerIdentity + IAM/Organizations/CloudWatch/CloudTrail/
 * Tagging/Cost Explorer permission probes against a connection's own
 * credentials (or an assumed role), records the run + every check, and
 * updates the connection's status/last_permission_check_at — shared by both
 * the interactive route below and /internal/run-due-permission-checks, so
 * a scheduled check writes exactly the same rows a manual click would.
 * `actor` is null for a scheduler-triggered run (no user to attribute an
 * audit log entry to — same "skip audit logging, there's no real actor"
 * convention internalScan.ts's run-due-scans already uses).
 *
 * Everything from resolveCredentials onward can throw (decryption, the AWS
 * calls themselves, a bad env var) — without the inner try/catch, an
 * exception would leave the 'running' row inserted below orphaned forever,
 * since nothing else ever marks it failed. Every exit path resolves that
 * row one way or another before returning.
 */
export async function runConnectionValidation(
  db: Db,
  env: Env,
  connection: ResolvableConnection & { id: string },
  /**
   * `userId` is null on the scheduled path, which has no requesting user.
   * `orgId` is still required there, because capability status is written per
   * org -- an earlier version guarded the write on `actor?.orgId`, and since
   * the scheduled worker passed null outright, the WEEKLY validation (the
   * primary one) silently wrote no capability rows at all.
   */
  actor: { orgId: string; userId: string | null } | null,
): Promise<ValidationOutcome> {
  const [run] = await db.insert<{ id: string }[]>('connection_validation_runs', {
    connection_id: connection.id,
    status: 'running',
    triggered_by: actor?.userId ?? null,
  });

  try {
    const resolved = await resolveCredentials(env, connection);
    if ('error' in resolved) {
      await db.update('connection_validation_runs', { id: `eq.${run.id}` }, { status: 'failed', finished_at: new Date().toISOString(), error_message: resolved.error }, 'return=minimal');
      await db.update('cloud_connections', { id: `eq.${connection.id}` }, { last_permission_check_at: new Date().toISOString() }, 'return=minimal');
      if (actor) await writeAuditLog(db, { orgId: actor.orgId, actorId: actor.userId, action: 'aws_account.permission_validation_failed', targetType: 'cloud_connection', targetId: connection.id, metadata: { reason: resolved.error } });
      return { crashed: false, status: 'failed', errorMessage: resolved.error, identity: null, checks: [] };
    }

    const { identity, checks } = await runFullValidation(resolved.creds, connection.default_region || 'us-east-1');

    /**
     * A validation run cannot be `succeeded` without evidence (§6.1: "An
     * empty required check list cannot be succeeded").
     *
     * This read `checks[0]?.status === 'granted'` -- positional, so it
     * depended entirely on STS happening to be first in the array, and an
     * empty checks array evaluated to `failed` only by accident of
     * `undefined`. Naming the required check makes the rule explicit and
     * order-independent.
     *
     * Denials on OTHER services deliberately do not fail the run: an account
     * that has not enabled Cost Explorer is not a broken connection. That
     * distinction is now carried per capability in
     * connector_capability_status rather than collapsed into one boolean.
     */
    const stsCheck = checks.find((ck) => ck.service === 'sts');
    const overallStatus = checks.length > 0 && stsCheck?.status === 'granted' ? 'succeeded' : 'failed';

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

    /**
     * Per-capability health from this snapshot (§2.3). One blended score per
     * connection cannot say "inventory is fine but Cost Explorer is denied",
     * which is the only form of this information a customer can act on.
     */
    // Both paths supply an org now (the interactive one from the request, the
    // scheduled one from the connection row), so this is no longer skipped in
    // the case that matters most -- the weekly automatic validation.
    if (actor?.orgId) await writeCapabilityStatuses(
      db,
      buildCapabilityStatuses({
        orgId: actor?.orgId ?? '',
        connectionId: connection.id,
        checks,
        snapshotId: run.id,
        connectionStatus: overallStatus === 'succeeded' ? 'connected' : 'error',
      }),
    );

    const connectionPatch: Record<string, unknown> = { last_permission_check_at: new Date().toISOString() };
    if (overallStatus === 'succeeded') {
      connectionPatch.status = 'connected';
      connectionPatch.error_message = null;
    } else {
      connectionPatch.status = 'error';
      connectionPatch.error_message = checks[0]?.detail ?? 'Validation failed';
    }
    await db.update('cloud_connections', { id: `eq.${connection.id}` }, connectionPatch, 'return=minimal');

    if (actor) {
      await writeAuditLog(db, {
        orgId: actor.orgId,
        actorId: actor.userId,
        action: overallStatus === 'succeeded' ? 'aws_account.permission_validation_succeeded' : 'aws_account.permission_validation_failed',
        targetType: 'cloud_connection',
        targetId: connection.id,
        metadata: { checks: checks.map((ck) => ({ service: ck.service, status: ck.status })) },
      });
    }

    return { crashed: false, status: overallStatus, identity, checks };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Validation crashed unexpectedly';
    await db.update('connection_validation_runs', { id: `eq.${run.id}` }, { status: 'failed', finished_at: new Date().toISOString(), error_message: message }, 'return=minimal');
    await db.update('cloud_connections', { id: `eq.${connection.id}` }, { status: 'error', error_message: message, last_permission_check_at: new Date().toISOString() }, 'return=minimal');
    if (actor) await writeAuditLog(db, { orgId: actor.orgId, actorId: actor.userId, action: 'aws_account.permission_validation_failed', targetType: 'cloud_connection', targetId: connection.id, metadata: { reason: message } });
    return { crashed: true, message };
  }
}

/**
 * POST /api/aws-accounts/accounts/:id/permissions/validate — the
 * interactive "Validate Permissions" button's endpoint. Editor+ (same bar
 * as triggering any scan/sync elsewhere in this app).
 */
permissionsRoutes.post('/accounts/:id/permissions/validate', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    // Authorize the caller for THIS connection before reading it: an
    // id + org_id filter proves org ownership, not that this caller is
    // permitted the connection (resource grants / active scope).
    await requirePermittedConnection(db, orgId, auth.userId, c.req.param('id'), getActiveScope(c.req.raw, orgId));
    const rows = await db.select<ResolvableConnection[]>('cloud_connections', {
      select: 'id,connection_method,credentials_encrypted,role_arn,external_id,default_region',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const connection = rows[0];
    if (!connection) return errJson(404, 'Account not found');

    const result = await runConnectionValidation(db, c.env, connection, { orgId, userId: auth.userId });
    if (result.crashed) return errJson(500, result.message);
    return okJson({ status: result.status, identity: result.identity, checks: result.checks, errorMessage: result.errorMessage });
  }),
);

const PERMISSION_CHECK_INTERVAL_DAYS = 7;
const MAX_PERMISSION_CHECKS_PER_RUN = 10;

/**
 * POST /api/aws-accounts/internal/run-due-permission-checks — the automatic
 * counterpart to the interactive route above. Resource discovery already
 * has this (see internalScan.ts's run-due-scans + the scheduled-scan-aws
 * Cloud Scheduler job); permission validation never did, meaning it was
 * genuinely manual-only until now — every connection needed a human to
 * click "Validate Permissions," with no equivalent of auto_scan_enabled/
 * next_scheduled_scan_at for permissions specifically. Same auth pattern as
 * run-due-scans (shared secret + service-role DB, since there's no user
 * session to check) and the same "not reached this cycle, picked up next
 * tick" semantics — next_permission_check_at isn't advanced until a
 * connection is actually checked, so nothing is silently skipped forever.
 *
 * Weekly rather than daily: permissions change far less often than
 * resources, and every check is a handful of real AWS API calls per
 * connection, not worth running on the same cadence as resource discovery.
 */
permissionsRoutes.post('/internal/run-due-permission-checks', (c) =>
  guarded(async () => {
    const secret = c.req.header('x-internal-scan-secret');
    if (!c.env.INTERNAL_SCAN_SECRET) return errJson(503, 'INTERNAL_SCAN_SECRET is not configured — scheduled permission checks are not active in this environment.');
    if (!c.env.SUPABASE_SERVICE_ROLE_KEY) return errJson(503, 'SUPABASE_SERVICE_ROLE_KEY is not configured — scheduled permission checks cannot authenticate to the database in this environment.');
    if (secret !== c.env.INTERNAL_SCAN_SECRET) return errJson(403, 'Invalid or missing X-Internal-Scan-Secret.');

    const db = createDb(c.env, c.env.SUPABASE_SERVICE_ROLE_KEY);
    const now = new Date().toISOString();

    const due = await db.select<(ResolvableConnection & { id: string; org_id: string })[]>('cloud_connections', {
      select: 'id,org_id,connection_method,credentials_encrypted,role_arn,external_id,default_region',
      filters: {
        provider: 'eq.aws',
        or: `(next_permission_check_at.is.null,next_permission_check_at.lte.${now})`,
        status: 'neq.pending',
      },
      limit: MAX_PERMISSION_CHECKS_PER_RUN,
    });

    const results = [];
    for (const connection of due) {
      const result = await runConnectionValidation(db, c.env, connection, { orgId: connection.org_id, userId: null });
      const nextCheck = new Date(Date.now() + PERMISSION_CHECK_INTERVAL_DAYS * 24 * 60 * 60 * 1000).toISOString();
      await db.update('cloud_connections', { id: `eq.${connection.id}` }, { next_permission_check_at: nextCheck }, 'return=minimal');
      results.push({ connectionId: connection.id, status: result.crashed ? 'crashed' : result.status });
    }

    return okJson({ connectionsChecked: results.length, results });
  }),
);

async function latestRunFor(db: Db, connectionId: string) {
  const runs = await db.select<{ id: string; status: string; identity_arn: string | null; identity_account_id: string | null; started_at: string; finished_at: string | null; error_message: string | null }[]>(
    'connection_validation_runs',
    {
      select: 'id,status,identity_arn,identity_account_id,started_at,finished_at,error_message',
      /**
       * AWS-P0-04: this had NO run_type filter, so it returned the latest run
       * of ANY type. Discovery runs outnumber validations 96:24 in
       * production, so the "Latest Validation Run" shown to customers was
       * almost always a DISCOVERY run -- reported as `succeeded`, with its
       * permission checks looked up by that run's id and therefore empty.
       *
       * Verified before the fix: both AWS connections showed
       * latest_run_type=discovery, status=succeeded, 0 checks displayed --
       * while 8 real permission checks existed for each. The evidence was
       * always there; the query threw it away.
       */
      filters: { connection_id: `eq.${connectionId}`, run_type: 'eq.permission_validation' },
      order: 'started_at.desc',
      limit: 1,
    },
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
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const latest = await latestRunFor(db, c.req.param('id'));
    return okJson(latest ?? { run: null, checks: [] });
  }),
);

/**
 * A discovery run only leaves "succeeded" when real step failures stay
 * under the 10% threshold in discovery.ts's runFinalize (deliberately, so
 * a handful of consistently-flaky steps don't flip every run to a scary
 * "error" badge -- see that function's comment). That's the right call for
 * the run-level status, but it means a step that's failed on every single
 * recent run is otherwise invisible unless someone reads error_message on
 * each row by hand. This surfaces that pattern explicitly: any step that
 * failed in at least half of the last 10 discovery runs.
 */
const RECURRING_FAILURE_LOOKBACK = 10;
const RECURRING_FAILURE_MIN_RATIO = 0.5;

interface ValidationRunRow {
  id: string; run_type: string; status: string; started_at: string;
  failed_steps: { step: string; message: string }[] | null;
}

function computeRecurringFailures(runs: ValidationRunRow[]): { step: string; failureCount: number; runsChecked: number; lastMessage: string }[] {
  const discoveryRuns = runs.filter((r) => r.run_type === 'discovery').slice(0, RECURRING_FAILURE_LOOKBACK);
  const byStep = new Map<string, { failureCount: number; lastMessage: string }>();
  for (const run of discoveryRuns) {
    for (const err of run.failed_steps ?? []) {
      const existing = byStep.get(err.step);
      // Runs are newest-first, so the first message seen for a step is its most recent.
      byStep.set(err.step, { failureCount: (existing?.failureCount ?? 0) + 1, lastMessage: existing?.lastMessage ?? err.message });
    }
  }
  const threshold = discoveryRuns.length * RECURRING_FAILURE_MIN_RATIO;
  return [...byStep.entries()]
    .filter(([, v]) => v.failureCount >= threshold && v.failureCount >= 2)
    .map(([step, v]) => ({ step, failureCount: v.failureCount, runsChecked: discoveryRuns.length, lastMessage: v.lastMessage }))
    .sort((a, b) => b.failureCount - a.failureCount);
}

/** GET /api/aws-accounts/accounts/:id/sync-history — every validation run for one account, newest first, plus which steps (if any) have been recurringly failing. */
permissionsRoutes.get('/accounts/:id/sync-history', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const runs = await db.select<ValidationRunRow[]>('connection_validation_runs', {
      select: 'id,run_type,status,identity_arn,identity_account_id,started_at,finished_at,error_message,triggered_by,failed_steps',
      filters: { connection_id: `eq.${c.req.param('id')}` },
      order: 'started_at.desc',
      limit: 50,
    });
    return okJson({ runs, recurringFailures: computeRecurringFailures(runs) });
  }),
);

/** GET /api/aws-accounts/permissions — org-wide summary: latest run's overall status per connection, for the Permission Validation overview. */
permissionsRoutes.get('/permissions', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const connectionIds = await getOrgConnectionIds(db, orgId, auth.userId, getActiveScope(c.req.raw, orgId));
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
