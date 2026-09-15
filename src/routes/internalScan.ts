import { Hono, createDb, guarded, okJson, errJson, type Db } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { planSteps } from './collectionRuns';
import { createOrGetActiveRun } from '../lib/collectionRuns';
import { loadConnection } from './discovery';

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
// scan_started_at (now written by nothing -- see the note below; cleared by
// runFinalize on real completion) is this job's only signal that a scan
// began and never reached a conclusion. 30 minutes is deliberately
// generous -- a real interactive full sweep can legitimately take longer
// than the server-side sweep above (~22.5 min worst case per its own
// comment) since each step is its own browser-to-Cloud-Run round trip, not
// a tight in-process loop -- so this only ever reclaims scans that are
// genuinely abandoned, not ones still honestly in progress in an open tab.
const ABANDONED_SCAN_THRESHOLD_MINUTES = 30;

interface ConnectionDue { id: string; org_id: string; scan_interval_hours: number }

/**
 * Both endpoints below ENQUEUE durable runs; neither executes steps. The
 * inline step helper that used to live here was deleted along with the
 * loops, so there is no dormant executor for a future change to wire back
 * up -- which is how the scheduled path drifted off the durable machinery
 * the first time.
 */
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

    /**
     * AWS-06. This endpoint used to EXECUTE the scan: it looped over due
     * connections calling runResourceStep/runFindingStep/runMetricStep
     * directly, then called runFinalize itself. It never created a
     * collection_runs row.
     *
     * So the path that actually ran in production -- this one, on a
     * schedule, unattended -- had no lease, no checkpoint, no run status and
     * no protection against two overlapping invocations. Cross-check on
     * 2026-09-15 found 4 run rows in total, newest 2026-09-10, while
     * ingestion_batches had grown from 7,960 to 15,422 over the same four
     * days: roughly 7,500 batches written by scans that no run row describes.
     *
     * It now ENQUEUES a durable run per due connection and returns. The
     * worker tick (advance-collection-runs, already on its own schedule)
     * claims a lease, advances a bounded slice, checkpoints, and finalizes.
     *
     * That move also makes vanished-resource safety strictly better rather
     * than merely equivalent: the durable finalize decides eligibility from
     * the COMMITTED collection_run_steps rows, whereas this loop decided it
     * from in-memory counters that only ever saw one invocation.
     *
     * createOrGetActiveRun is idempotent against the partial unique index on
     * active runs, so a connection already collecting is not enqueued twice
     * -- the case this endpoint previously had no defence against at all.
     */
    const results = [];
    for (const row of due) {
      const connection = await loadConnection(db, row.org_id, null, row.id);
      if (!connection) continue;

      const plannedSteps = planSteps(connection as never);
      const { run, created } = await createOrGetActiveRun(db, {
        orgId: row.org_id,
        connectionId: row.id,
        requestedBy: null,
        trigger: 'scheduled',
        plannedSteps,
        // Deterministic per connection per due-window, so a scheduler retry
        // within the same window cannot mint a second run.
        idempotencyKey: `scheduled:${row.id}:${now.slice(0, 13)}`,
      });

      /**
       * Advanced whether or not a run was created. If one was already active
       * the connection is collecting right now, and leaving next_scheduled_
       * scan_at in the past would re-enqueue it on every tick forever.
       */
      const nextScan = new Date(Date.now() + row.scan_interval_hours * 60 * 60 * 1000).toISOString();
      await db.update('cloud_connections', { id: `eq.${row.id}` }, { next_scheduled_scan_at: nextScan }, 'return=minimal');

      results.push({ connectionId: row.id, runId: run.id, status: run.status, created, plannedSteps: plannedSteps.length });
    }

    return okJson({ connectionsEnqueued: results.length, results });
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
 *    case is invisible to a status='pending' check alone.
 *
 *    NOTE (2026-09-10): case 3 no longer fires. It was caught via
 *    scan_started_at, which was written ONLY by GET /discovery/steps -- the
 *    browser step-loop's first call. Phase 1 removed the browser's calls,
 *    Phase 3 replaced the loop with durable server-owned runs, and that
 *    route has now been deleted, so nothing writes the column and the
 *    scan_started_at branch of the filter below can never match.
 *
 *    This is not a regression: an interrupted scan is exactly what
 *    collection_runs' lease expiry already recovers, without needing a
 *    column to infer abandonment from. The branch is left in place because
 *    it is harmless and correctly matches nothing, and removing the column
 *    is a schema change beyond this cleanup -- but it is documented as inert
 *    rather than left implying a check that still runs.
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
      const connection = await loadConnection(db, row.org_id, null, row.id);
      if (!connection) continue;

      /**
       * AWS-06, same change as run-due-scans above. This loop also executed
       * steps inline and finalized them itself, with no run row, no lease and
       * no checkpoint -- and this is the FIRST scan of a brand-new
       * connection, so an interruption left a half-populated inventory with
       * nothing recording where it stopped.
       */
      const plannedSteps = planSteps(connection as never);
      const { run, created } = await createOrGetActiveRun(db, {
        orgId: row.org_id,
        connectionId: row.id,
        requestedBy: null,
        trigger: 'first_scan',
        plannedSteps,
        idempotencyKey: `first-scan:${row.id}`,
      });

      // Enters the normal daily cadence from here on. 24h matches the
      // scan_interval_hours column default; loadConnection does not select
      // it, and a freshly created row has never had a custom interval set.
      const nextScan = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      await db.update('cloud_connections', { id: `eq.${row.id}` }, { next_scheduled_scan_at: nextScan }, 'return=minimal');

      results.push({ connectionId: row.id, runId: run.id, status: run.status, created, plannedSteps: plannedSteps.length });
    }

    return okJson({ connectionsScanned: results.length, results });
  }),
);
