import { Hono, createDb, guarded, okJson, errJson, type Db } from '@cloudops360/shared-lib';
import type { Env } from '../env';
import {
  REGIONAL_SCANNERS, GLOBAL_SCANNERS, FINDING_SCANNERS, METRIC_STEP_NAME,
  loadConnection, regionsFor, runResourceStep, runFindingStep, runMetricStep, runFinalize,
  type StepErrorInput,
} from './discovery';

export const internalScanRoutes = new Hono<{ Bindings: Env }>();

/**
 * Continuous/scheduled scanning — every discovery run elsewhere in this
 * service is 100% on-demand, triggered by a browser clicking "Discover
 * Resources" and driving the /discovery/steps -> /discovery/run-step (many
 * calls) -> /discovery/finalize loop itself. This endpoint is the
 * server-side equivalent for connections that opted into automatic scanning
 * (cloud_connections.auto_scan_enabled) — meant to be called by a Cloud
 * Scheduler job, not a user, so it can't use the normal getAuthContext/
 * requireMember flow (there's no Supabase user session to check). Instead:
 *
 * 1. A shared secret (INTERNAL_SCAN_SECRET) in the X-Internal-Scan-Secret
 *    header authenticates the caller as "this really is our own scheduler,
 *    not a public request". Configured as a Cloud Run env var and matched
 *    against the Cloud Scheduler job `scheduled-scan-aws`, which fires this
 *    endpoint daily at 00:00 IST (see cloud_connections.auto_scan_enabled/
 *    scan_interval_hours, which default to true/24 for every connection).
 * 2. SUPABASE_SERVICE_ROLE_KEY authenticates to Postgres as a service,
 *    bypassing RLS, since there's no per-user access token to forward.
 *    Without it this handler fails cleanly with a 503 rather than silently
 *    doing nothing or crashing.
 *
 * Runs every step for each due connection sequentially in one request
 * (unlike the browser-driven loop, which fires each step as its own HTTP
 * call) — capped at MAX_CONNECTIONS_PER_RUN connections and a per-connection
 * step budget, so one invocation can't run unbounded long; connections not
 * reached this cycle are picked up on Cloud Scheduler's next tick, at worst
 * a bit later than their configured interval, never skipped entirely (their
 * next_scheduled_scan_at isn't advanced until they're actually run).
 */
const MAX_CONNECTIONS_PER_RUN = 5;
const MAX_STEPS_PER_CONNECTION = 60;

interface ConnectionDue { id: string; org_id: string; scan_interval_hours: number }

async function runOneStep(db: Db, orgId: string, env: Env, connectionId: string, stepId: string) {
  if (stepId.startsWith('finding:')) return runFindingStep(db, orgId, env, connectionId, stepId);
  if (stepId.startsWith('metric:')) return runMetricStep(db, orgId, env, connectionId, stepId);
  return runResourceStep(db, orgId, env, connectionId, stepId);
}

internalScanRoutes.post('/internal/run-due-scans', (c) =>
  guarded(async () => {
    const secret = c.req.header('x-internal-scan-secret');
    if (!c.env.INTERNAL_SCAN_SECRET) return errJson(503, 'INTERNAL_SCAN_SECRET is not configured — scheduled scanning is not active in this environment.');
    if (!c.env.SUPABASE_SERVICE_ROLE_KEY) return errJson(503, 'SUPABASE_SERVICE_ROLE_KEY is not configured — scheduled scanning cannot authenticate to the database in this environment.');
    if (secret !== c.env.INTERNAL_SCAN_SECRET) return errJson(403, 'Invalid or missing X-Internal-Scan-Secret.');

    const db = createDb(c.env, c.env.SUPABASE_SERVICE_ROLE_KEY);
    const now = new Date().toISOString();

    const due = await db.select<ConnectionDue[]>('cloud_connections', {
      select: 'id,org_id,scan_interval_hours',
      filters: {
        provider: 'eq.aws', auto_scan_enabled: 'eq.true',
        or: `(next_scheduled_scan_at.is.null,next_scheduled_scan_at.lte.${now})`,
        status: 'neq.pending',
      },
      limit: MAX_CONNECTIONS_PER_RUN,
    });

    const results = [];
    for (const row of due) {
      const connection = await loadConnection(db, row.org_id, row.id);
      if (!connection) continue;

      const runStartedAt = new Date().toISOString();
      const regions = regionsFor(connection);
      const steps = [
        ...regions.flatMap((region) => Object.keys(REGIONAL_SCANNERS).map((name) => `regional:${name}:${region}`)),
        ...Object.keys(GLOBAL_SCANNERS).map((name) => `global:${name}`),
        ...regions.flatMap((region) => Object.keys(FINDING_SCANNERS).map((name) => `finding:${name}:${region}`)),
        ...regions.map((region) => `metric:${METRIC_STEP_NAME}:${region}`),
      ].slice(0, MAX_STEPS_PER_CONNECTION);

      const stepErrors: StepErrorInput[] = [];
      for (const stepId of steps) {
        const result = await runOneStep(db, row.org_id, c.env, row.id, stepId);
        if (result.error) stepErrors.push({ message: `${stepId}: ${result.error}`, severity: result.errorSeverity ?? 'error' });
      }

      const outcome = await runFinalize(db, row.org_id, null, connection, runStartedAt, stepErrors);
      const nextScan = new Date(Date.now() + row.scan_interval_hours * 60 * 60 * 1000).toISOString();
      await db.update('cloud_connections', { id: `eq.${row.id}` }, { next_scheduled_scan_at: nextScan }, 'return=minimal');

      results.push({ connectionId: row.id, ...outcome });
    }

    return okJson({ connectionsScanned: results.length, results });
  }),
);
