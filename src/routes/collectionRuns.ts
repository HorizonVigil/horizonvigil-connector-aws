import {
  Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, guarded, okJson, errJson,
  writeAuditLog, requirePermittedConnection, getActiveScope, enforceRateLimit,
  describeJobStatus, isTerminal, assertTransition, type Db,
} from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { loadConnection, regionsFor, runResourceStep, runFindingStep, runMetricStep, runFinalize, REGIONAL_SCANNERS, GLOBAL_SCANNERS, FINDING_SCANNERS, METRIC_STEP_NAME, SCANNER_RESOURCE_TYPES } from './discovery';
import {
  createOrGetActiveRun, claimRun, checkpoint, finalizeRun, toRunResponse, isLeaseExpired,
  STEPS_PER_SLICE, type CollectionRunRow,
} from '../lib/collectionRuns';

export const collectionRunRoutes = new Hono<{ Bindings: Env }>();

/** Builds the full step plan server-side. The browser used to fetch this and drive it; it is now an internal detail of a job. */
function planSteps(connection: { scan_regions: string[] | null; default_region: string }): string[] {
  const regions = regionsFor(connection as never);
  return [
    ...regions.flatMap((r) => Object.keys(REGIONAL_SCANNERS).map((n) => `regional:${n}:${r}`)),
    ...Object.keys(GLOBAL_SCANNERS).map((n) => `global:${n}`),
    ...regions.flatMap((r) => Object.keys(FINDING_SCANNERS).map((n) => `finding:${n}:${r}`)),
    ...regions.map((r) => `metric:${METRIC_STEP_NAME}:${r}`),
  ];
}

/**
 * POST /accounts/:id/collection-runs — request a scan.
 *
 * Returns 202 + Location per §14.5. The response is the JOB, not the result:
 * the work happens in a worker, so this returns in well under a second even
 * though the scan itself may take hours.
 */
collectionRunRoutes.post('/accounts/:id/collection-runs', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    const connectionId = c.req.param('id');
    await requirePermittedConnection(db, orgId, auth.userId, connectionId, getActiveScope(c.req.raw, orgId));
    await enforceRateLimit(db, `collection-run:${orgId}`, 60, 3600);

    const connection = await loadConnection(db, orgId, auth.userId, connectionId);
    if (!connection) return errJson(404, 'Account not found');

    // Disconnected connections must not collect (AWS-P0-11). A disconnected
    // account was still offering Sync Now.
    const statusRows = await db.select<{ status: string }[]>('cloud_connections', {
      select: 'status',
      filters: { id: `eq.${connectionId}` },
    });
    if (statusRows[0]?.status === 'disconnected') {
      return errJson(409, 'This connection is disconnected. Reconnect it before collecting.');
    }

    const plannedSteps = planSteps(connection as never);
    // An Idempotency-Key from the client is honoured when present (§14.4);
    // otherwise the active-run index alone still prevents duplicates.
    const idempotencyKey = c.req.header('Idempotency-Key') ?? `auto:${connectionId}:${Date.now()}`;

    const { run, created } = await createOrGetActiveRun(db, {
      orgId,
      connectionId,
      requestedBy: auth.userId,
      trigger: 'user',
      plannedSteps,
      idempotencyKey,
    });

    if (created) {
      await writeAuditLog(db, {
        orgId, actorId: auth.userId, action: 'aws_account.collection_run_queued',
        targetType: 'cloud_connection', targetId: connectionId,
        metadata: { runId: run.id, totalSteps: plannedSteps.length },
      });
    }

    const location = `/api/aws-accounts/collection-runs/${run.id}`;
    return new Response(JSON.stringify({ ok: true, ...toRunResponse(run), created, location }), {
      // 202 for a new job; 200 when an identical one is already in flight, so
      // clicking Sync Now twice is idempotent rather than an error.
      status: created ? 202 : 200,
      headers: { 'Content-Type': 'application/json', Location: location, 'Retry-After': '5' },
    });
  }),
);

/** GET /collection-runs/:id — poll job state. */
collectionRunRoutes.get('/collection-runs/:id', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const rows = await db.select<CollectionRunRow[]>('collection_runs', {
      select: '*',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}` },
    });
    const run = rows[0];
    if (!run) return errJson(404, 'Collection run not found');
    await requirePermittedConnection(db, orgId, auth.userId, run.connection_id, getActiveScope(c.req.raw, orgId));

    return okJson({ ...toRunResponse(run), explanation: describeJobStatus(run.status) });
  }),
);

/** GET /collection-runs/:id/steps — per-step evidence behind the terminal status. */
collectionRunRoutes.get('/collection-runs/:id/steps', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const rows = await db.select<CollectionRunRow[]>('collection_runs', {
      select: 'id,org_id,connection_id',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}` },
    });
    if (!rows[0]) return errJson(404, 'Collection run not found');
    await requirePermittedConnection(db, orgId, auth.userId, rows[0].connection_id, getActiveScope(c.req.raw, orgId));

    const steps = await db.select<Record<string, unknown>[]>('collection_run_steps', {
      select: 'step_id,step_index,status,records_written,error_message,normalized_code,attempts,started_at,finished_at',
      filters: { run_id: `eq.${c.req.param('id')}` },
      order: 'step_index.asc',
      limit: 5000,
    });
    return okJson({ items: steps, total: steps.length });
  }),
);

/**
 * POST /collection-runs/:id/cancel — cooperative cancellation.
 *
 * Sets CANCEL_REQUESTED; the worker observes it between steps and closes the
 * run. It does not mark the run CANCELED directly, because the worker may be
 * mid-step writing rows.
 */
collectionRunRoutes.post('/collection-runs/:id/cancel', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    const rows = await db.select<CollectionRunRow[]>('collection_runs', {
      select: '*',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}` },
    });
    const run = rows[0];
    if (!run) return errJson(404, 'Collection run not found');
    await requirePermittedConnection(db, orgId, auth.userId, run.connection_id, getActiveScope(c.req.raw, orgId));

    if (isTerminal(run.status)) return errJson(409, `This run already finished (${run.status}).`);
    try {
      assertTransition(run.status, 'CANCEL_REQUESTED');
    } catch {
      return errJson(409, `A run in ${run.status} cannot be cancelled.`);
    }

    await db.update('collection_runs', { id: `eq.${run.id}` }, { status: 'CANCEL_REQUESTED', updated_at: new Date().toISOString() }, 'return=minimal');
    await writeAuditLog(db, {
      orgId, actorId: auth.userId, action: 'aws_account.collection_run_cancel_requested',
      targetType: 'cloud_connection', targetId: run.connection_id, metadata: { runId: run.id },
    });
    return okJson({ ...toRunResponse({ ...run, status: 'CANCEL_REQUESTED' }), explanation: describeJobStatus('CANCEL_REQUESTED') });
  }),
);

/** Runs one step and records its outcome as committed evidence. */
async function executeStep(db: Db, env: Env, run: CollectionRunRow, stepId: string, index: number): Promise<{ failed: boolean; degraded: string[] }> {
  const startedAt = new Date().toISOString();
  // null userId: the worker runs under the service role with no requesting
  // user; the run was authorized when it was created.
  const result = stepId.startsWith('finding:')
    ? await runFindingStep(db, run.org_id, null, env, run.connection_id, stepId)
    : stepId.startsWith('metric:')
      ? await runMetricStep(db, run.org_id, null, env, run.connection_id, stepId)
      : await runResourceStep(db, run.org_id, null, env, run.connection_id, stepId);

  const severity = result.errorSeverity ?? 'error';
  const status = result.error ? (severity === 'info' ? 'info' : 'failed') : 'succeeded';

  await db.insert(
    'collection_run_steps',
    {
      run_id: run.id, step_id: stepId, step_index: index, status,
      records_written: result.resourceCount ?? 0,
      error_message: result.error ?? null,
      started_at: startedAt, finished_at: new Date().toISOString(),
    },
    'return=minimal',
  ).catch(() => {
    // A duplicate step row means this slice is being retried after a crash
    // between the step and its checkpoint. The scanners' writes are
    // idempotent upserts, so re-running is safe; swallowing only the
    // duplicate-key case keeps the run advancing.
  });

  return { failed: status === 'failed', degraded: result.degradedResourceTypes ?? [] };
}

/**
 * POST /internal/advance-collection-runs — the worker tick.
 *
 * Claims runs whose lease is free, executes one bounded slice, checkpoints,
 * and returns. Cloud Scheduler calls this; a run spanning several ticks is
 * normal and is exactly what makes progress durable (ADR 0001).
 */
collectionRunRoutes.post('/internal/advance-collection-runs', (c) =>
  guarded(async () => {
    const secret = c.req.header('x-internal-scan-secret');
    if (!c.env.INTERNAL_SCAN_SECRET) return errJson(503, 'INTERNAL_SCAN_SECRET is not configured.');
    if (!c.env.SUPABASE_SERVICE_ROLE_KEY) return errJson(503, 'SUPABASE_SERVICE_ROLE_KEY is not configured.');
    if (secret !== c.env.INTERNAL_SCAN_SECRET) return errJson(403, 'Invalid or missing X-Internal-Scan-Secret.');

    const db = createDb(c.env, c.env.SUPABASE_SERVICE_ROLE_KEY);
    const leaseOwner = `worker:${crypto.randomUUID()}`;
    const now = Date.now();

    const candidates = await db.select<CollectionRunRow[]>('collection_runs', {
      select: '*',
      filters: { status: 'in.(QUEUED,RUNNING,WAITING_RETRY,CANCEL_REQUESTED)' },
      order: 'queued_at.asc',
      limit: 20,
    });

    const results: unknown[] = [];
    for (const run of candidates) {
      // Skip runs another worker currently holds. An expired lease means that
      // worker died, so the run is reclaimable with no human intervention.
      if (run.status === 'RUNNING' && !isLeaseExpired(run, now)) continue;

      if (run.status === 'CANCEL_REQUESTED') {
        const status = await finalizeRun(db, run, { canceled: true });
        results.push({ runId: run.id, status });
        continue;
      }

      if (!(await claimRun(db, run, leaseOwner, now))) continue;

      const steps = run.planned_steps ?? [];
      const start = run.step_cursor;
      const end = Math.min(start + STEPS_PER_SLICE, steps.length);
      const degraded = new Set(run.degraded_resource_types ?? []);
      let completed = run.completed_steps;
      let failed = run.failed_steps;

      for (let i = start; i < end; i++) {
        const outcome = await executeStep(db, c.env, run, steps[i], i);
        for (const t of outcome.degraded) degraded.add(t);
        completed += 1;
        if (outcome.failed) failed += 1;
      }

      await checkpoint(db, run.id, { stepCursor: end, completedSteps: completed, failedSteps: failed, degradedResourceTypes: [...degraded] });

      if (end >= steps.length) {
        // Every planned step is done: close the run from its committed step
        // rows, then run the existing finalize so inventory reconciliation
        // and vanished-resource handling behave exactly as before.
        const connection = await loadConnection(db, run.org_id, null, run.connection_id);
        if (connection) {
          /**
           * Only resource types whose scanner FULLY succeeded this run are
           * eligible for vanished-resource deletion -- the same rule the
           * scheduled worker applies. A scanner that failed in even one
           * region must not be trusted to prove absence, or a partial scan
           * deletes live inventory.
           *
           * Read from committed step rows rather than in-memory counters,
           * because a run spans several worker ticks and no single tick sees
           * them all.
           */
          const allSteps = await db.select<{ step_id: string; status: string }[]>('collection_run_steps', {
            select: 'step_id,status',
            filters: { run_id: `eq.${run.id}` },
            limit: 5000,
          });
          const failedStepIds = new Set(allSteps.filter((s) => s.status === 'failed').map((s) => s.step_id));
          const stepSet = new Set(steps);
          const regions = regionsFor(connection);
          const coveredResourceTypes = [
            ...Object.keys(GLOBAL_SCANNERS)
              .filter((n) => stepSet.has(`global:${n}`) && !failedStepIds.has(`global:${n}`))
              .flatMap((n) => SCANNER_RESOURCE_TYPES[n] ?? []),
            ...Object.keys(REGIONAL_SCANNERS)
              .filter((n) => regions.every((r) => stepSet.has(`regional:${n}:${r}`) && !failedStepIds.has(`regional:${n}:${r}`)))
              .flatMap((n) => SCANNER_RESOURCE_TYPES[n] ?? []),
          ];

          await runFinalize(
            db, run.org_id, run.requested_by, connection,
            run.started_at ?? run.queued_at, [], c.env, coveredResourceTypes,
            steps.length, [...degraded],
          );
        }
        const status = await finalizeRun(db, { ...run, completed_steps: completed, failed_steps: failed });
        results.push({ runId: run.id, status, steps: steps.length });
      } else {
        results.push({ runId: run.id, status: 'RUNNING', progress: `${end}/${steps.length}` });
      }
    }

    return okJson({ advanced: results.length, results });
  }),
);
