import { Hono, createDb, guarded, okJson, errJson, type Db } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import {
  REGIONAL_SCANNERS, GLOBAL_SCANNERS, FINDING_SCANNERS, METRIC_STEP_NAME, SCANNER_RESOURCE_TYPES,
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
 *
 * MAX_STEPS_PER_CONNECTION was originally 60, sized for Cloudflare Workers'
 * free-tier CPU/subrequest budget per invocation — stale now that this runs
 * on Cloud Run (1800s request timeout, no such per-invocation cap). At 60,
 * a 17-region connection with ~55 regional scanners couldn't even finish a
 * single region before hitting the cap, since `steps` always starts at
 * regions[0] with no persisted cross-run cursor — meaning the scheduled
 * path would scan the exact same handful of region-1 scanners every single
 * day, forever, and never reach the other 16 regions at all. Raised to
 * comfortably cover a full sweep (17 regions x ~55 scanners + globals +
 * findings + metrics is roughly 1,100 steps) for one connection well within
 * the request timeout even at a pessimistic ~300ms/call.
 */
// MAX_CONNECTIONS_PER_RUN lowered from 5 to keep the worst case (every due
// connection needing a full sweep in the same invocation) safely under the
// 1800s Cloud Run request timeout: 3 x 1500 x ~300ms ~= 1350s, versus
// 5 x 1500 that could exceed it.
const MAX_CONNECTIONS_PER_RUN = 3;
const MAX_STEPS_PER_CONNECTION = 1500;
// An interactive scan is entirely driven by the browser tab's own loop
// (syncContext.tsx) -- if that tab closes, crashes, sleeps, or loses its
// connection mid-scan, nothing client-side can ever resume it; the server
// has no idea the scan stopped short of finishing. cloud_connections.
// scan_started_at (set at the first call of that loop, cleared by
// runFinalize on real completion) is this job's only signal that a scan
// began and never reached a conclusion. 30 minutes is deliberately
// generous -- a real interactive full sweep can legitimately take longer
// than the server-side sweep above (~22.5 min worst case per its own
// comment) since each step is its own browser-to-Cloud-Run round trip, not
// a tight in-process loop -- so this only ever reclaims scans that are
// genuinely abandoned, not ones still honestly in progress in an open tab.
const ABANDONED_SCAN_THRESHOLD_MINUTES = 30;

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
      const failedStepIds = new Set<string>();
      for (const stepId of steps) {
        const result = await runOneStep(db, row.org_id, c.env, row.id, stepId);
        if (result.error) {
          stepErrors.push({ message: `${stepId}: ${result.error}`, severity: result.errorSeverity ?? 'error' });
          // 'info' (e.g. "service not enabled in this region") is a genuine,
          // successful zero-resources answer, not a failure — only a real
          // error means this step's scanner didn't actually get to check.
          if ((result.errorSeverity ?? 'error') !== 'info') failedStepIds.add(stepId);
        }
      }

      // A scanner's resource types are only safe to vanish-check if EVERY
      // one of the connection's regions for that scanner actually ran this
      // invocation AND SUCCEEDED — two real bugs found the same day
      // (2026-08-12) this endpoint was first exercised with real data: (1)
      // MAX_STEPS_PER_CONNECTION means a typical multi-region connection
      // only completes a fraction of its regional scanners per cycle, so
      // treating "step 1 ran" as "fully checked" mass-deleted resources in
      // regions not yet reached; (2) a step that ran but errored (e.g. a
      // connection with broken/rotated credentials failing every single
      // call) still counted as "checked," wiping out an entire broken
      // connection's resources on the very next scan after the credentials
      // stopped working, instead of leaving them alone until reconnected.
      // Global scanners always fully cover themselves in one step when it
      // runs and succeeds.
      const stepSet = new Set(steps);
      const coveredResourceTypes = [
        ...Object.keys(GLOBAL_SCANNERS).filter((name) => stepSet.has(`global:${name}`) && !failedStepIds.has(`global:${name}`)).flatMap((name) => SCANNER_RESOURCE_TYPES[name] ?? []),
        ...Object.keys(REGIONAL_SCANNERS).filter((name) => regions.every((r) => stepSet.has(`regional:${name}:${r}`) && !failedStepIds.has(`regional:${name}:${r}`))).flatMap((name) => SCANNER_RESOURCE_TYPES[name] ?? []),
      ];

      const outcome = await runFinalize(db, row.org_id, null, connection, runStartedAt, stepErrors, c.env, coveredResourceTypes, steps.length);
      const nextScan = new Date(Date.now() + row.scan_interval_hours * 60 * 60 * 1000).toISOString();
      await db.update('cloud_connections', { id: `eq.${row.id}` }, { next_scheduled_scan_at: nextScan }, 'return=minimal');

      results.push({ connectionId: row.id, ...outcome });
    }

    return okJson({ connectionsScanned: results.length, results });
  }),
);

/**
 * POST /internal/run-first-scans — drains AWS connections that need a full
 * scan completed server-side because nothing client-side is going to
 * finish it for them. Three real cases land here:
 *
 * 1. Bulk-onboarded connections (see bulkImport.ts — every row it inserts
 *    starts 'pending' with no browser session open to call startDiscovery
 *    for it, unlike the interactive wizard, which fires that call itself
 *    right after creating the connection).
 * 2. A newly-created connection whose browser tab closed before its one
 *    auto-triggered scan finished (also left at status='pending').
 * 3. An already-connected account where a user clicked "Discover
 *    Resources" and then closed the tab, lost network, or put the laptop
 *    to sleep before the scan finished — status stays whatever it was
 *    (usually 'connected', from the *previous* successful scan), so this
 *    case is invisible to a status='pending' check alone. Caught instead
 *    via scan_started_at, set by GET /discovery/steps (the loop's first
 *    call) and cleared by runFinalize on real completion — see
 *    ABANDONED_SCAN_THRESHOLD_MINUTES above.
 *
 * All three are otherwise invisible to run-due-scans above forever — that
 * query only looks at next_scheduled_scan_at, which nothing here has
 * reached yet (case 1/2 have never completed a first scan at all; case 3's
 * *previous* successful scan already set it comfortably in the future).
 * Everything else (regions, scanners, findings, metrics,
 * MAX_CONNECTIONS_PER_RUN/MAX_STEPS_PER_CONNECTION safety caps) is
 * identical to run-due-scans.
 */
internalScanRoutes.post('/internal/run-first-scans', (c) =>
  guarded(async () => {
    const secret = c.req.header('x-internal-scan-secret');
    if (!c.env.INTERNAL_SCAN_SECRET) return errJson(503, 'INTERNAL_SCAN_SECRET is not configured — scheduled scanning is not active in this environment.');
    if (!c.env.SUPABASE_SERVICE_ROLE_KEY) return errJson(503, 'SUPABASE_SERVICE_ROLE_KEY is not configured — scheduled scanning cannot authenticate to the database in this environment.');
    if (secret !== c.env.INTERNAL_SCAN_SECRET) return errJson(403, 'Invalid or missing X-Internal-Scan-Secret.');

    const db = createDb(c.env, c.env.SUPABASE_SERVICE_ROLE_KEY);
    const abandonedBefore = new Date(Date.now() - ABANDONED_SCAN_THRESHOLD_MINUTES * 60 * 1000).toISOString();

    const pending = await db.select<{ id: string; org_id: string }[]>('cloud_connections', {
      select: 'id,org_id',
      filters: {
        provider: 'eq.aws', status: 'neq.disconnected',
        or: `(status.eq.pending,scan_started_at.lt.${abandonedBefore})`,
      },
      order: 'created_at.asc',
      limit: MAX_CONNECTIONS_PER_RUN,
    });

    const results = [];
    for (const row of pending) {
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
      const failedStepIds = new Set<string>();
      for (const stepId of steps) {
        const result = await runOneStep(db, row.org_id, c.env, row.id, stepId);
        if (result.error) {
          stepErrors.push({ message: `${stepId}: ${result.error}`, severity: result.errorSeverity ?? 'error' });
          if ((result.errorSeverity ?? 'error') !== 'info') failedStepIds.add(stepId);
        }
      }

      const stepSet = new Set(steps);
      const coveredResourceTypes = [
        ...Object.keys(GLOBAL_SCANNERS).filter((name) => stepSet.has(`global:${name}`) && !failedStepIds.has(`global:${name}`)).flatMap((name) => SCANNER_RESOURCE_TYPES[name] ?? []),
        ...Object.keys(REGIONAL_SCANNERS).filter((name) => regions.every((r) => stepSet.has(`regional:${name}:${r}`) && !failedStepIds.has(`regional:${name}:${r}`))).flatMap((name) => SCANNER_RESOURCE_TYPES[name] ?? []),
      ];

      const outcome = await runFinalize(db, row.org_id, null, connection, runStartedAt, stepErrors, c.env, coveredResourceTypes, steps.length);
      // Enters the normal daily cadence from here on — run-due-scans above
      // now sees this connection, since runFinalize just moved its status
      // off 'pending'. scan_interval_hours isn't loaded here (loadConnection
      // doesn't select it, and a freshly bulk-created row has never had a
      // custom interval set) — 24h matches that column's own default.
      const nextScan = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      await db.update('cloud_connections', { id: `eq.${row.id}` }, { next_scheduled_scan_at: nextScan }, 'return=minimal');

      results.push({ connectionId: row.id, ...outcome });
    }

    return okJson({ connectionsScanned: results.length, results });
  }),
);
