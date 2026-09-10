import {
  Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, guarded, okJson, errJson,
  writeAuditLog, requirePermittedConnection, getActiveScope, enforceRateLimit,
  describeJobStatus, isTerminal, assertTransition, type Db,
} from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { loadConnection, regionsFor, runResourceStep, runFindingStep, runMetricStep, runFinalize, REGIONAL_SCANNERS, GLOBAL_SCANNERS, FINDING_SCANNERS, METRIC_STEP_NAME, SCANNER_RESOURCE_TYPES } from './discovery';
import {
  createOrGetActiveRun, claimRun, checkpoint, finalizeRun, toRunResponse, isLeaseExpired,
  queueRetryRun, STEPS_PER_SLICE, type CollectionRunRow,
} from '../lib/collectionRuns';
import { fetchCurManifest, parseCurBatch } from '../lib/curIngest';
import { resolveCredentials } from './permissions';
import { ingestCurFile, advanceCheckpoint, allFilesComplete, finalizeCurRun, type CurCheckpoint } from '../lib/curWorkflow';

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

/**
 * POST /accounts/:id/cur-runs — request a server-owned CUR ingestion.
 *
 * Replaces the browser's nested loop over report files and row chunks (§3.4).
 * Same durable-job contract as discovery: 202 + Location, one active run per
 * connection, resumable across worker ticks.
 */
collectionRunRoutes.post('/accounts/:id/cur-runs', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    const connectionId = c.req.param('id');
    await requirePermittedConnection(db, orgId, auth.userId, connectionId, getActiveScope(c.req.raw, orgId));

    const connection = await loadConnection(db, orgId, auth.userId, connectionId);
    if (!connection) return errJson(404, 'Account not found');

    const cfg = await db.select<{ cur_s3_bucket: string | null; cur_s3_region: string | null; cur_s3_prefix: string | null; cur_report_name: string | null }[]>(
      'cloud_connections',
      { select: 'cur_s3_bucket,cur_s3_region,cur_s3_prefix,cur_report_name', filters: { id: `eq.${connectionId}` } },
    );
    if (!cfg[0]?.cur_s3_bucket) {
      // Honest refusal rather than queuing a job that can only fail.
      return c.json({ ok: false, code: 'cur_not_configured', error: 'No Cost & Usage Report is configured for this account yet.' }, 409);
    }

    const resolved = await resolveCredentials(c.env, connection as never);
    if ('error' in resolved) return errJson(400, resolved.error);

    // The manifest IS the plan: one step per report file, discovered
    // server-side rather than fetched by the browser.
    const manifest = await fetchCurManifest(resolved.creds, {
      bucket: cfg[0].cur_s3_bucket, region: cfg[0].cur_s3_region ?? 'us-east-1',
      prefix: cfg[0].cur_s3_prefix ?? '', reportName: cfg[0].cur_report_name ?? '',
    } as never);
    if ('error' in manifest) return errJson(400, manifest.error);
    const reportKeys = manifest.manifest.reportKeys ?? [];
    if (reportKeys.length === 0) {
      return c.json({ ok: false, code: 'cur_no_data_published', error: 'The report exists but no data files are published for this billing period yet.' }, 409);
    }

    const { run, created } = await createOrGetActiveRun(db, {
      orgId, connectionId, requestedBy: auth.userId, trigger: 'user',
      plannedSteps: reportKeys,
      idempotencyKey: c.req.header('Idempotency-Key') ?? `cur:${connectionId}:${Date.now()}`,
    });
    if (created) {
      await db.update('collection_runs', { id: `eq.${run.id}` }, { capability: 'billing_cur' }, 'return=minimal');
      await writeAuditLog(db, {
        orgId, actorId: auth.userId, action: 'aws_account.cur_run_queued',
        targetType: 'cloud_connection', targetId: connectionId, metadata: { runId: run.id, files: reportKeys.length },
      });
    }

    const location = `/api/aws-accounts/collection-runs/${run.id}`;
    return new Response(JSON.stringify({ ok: true, ...toRunResponse(run), created, location }), {
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

    /**
     * `next_attempt_at` is honoured here, not just written.
     *
     * Without this clause the backoff would be decorative -- a WAITING_RETRY
     * run would be claimed on the very next tick, one minute of scheduled
     * delay becoming zero. `is.null` is required because every non-retry run
     * has a null here and must stay claimable.
     */
    const candidates = await db.select<CollectionRunRow[]>('collection_runs', {
      select: '*',
      filters: {
        status: 'in.(QUEUED,RUNNING,WAITING_RETRY,CANCEL_REQUESTED)',
        or: `(next_attempt_at.is.null,next_attempt_at.lte.${new Date(now).toISOString()})`,
      },
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

      /**
       * CUR ingestion resumes mid-FILE, so it advances one file per tick with
       * a wall-clock budget rather than looping steps. This is the branch
       * that replaces the browser's nested for/while over report files and
       * row chunks (§3.4).
       */
      if (run.capability === 'billing_cur') {
        const outcome = await advanceCurRun(db, c.env, run, now);
        results.push(outcome);
        continue;
      }

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
        /**
         * Read once, used twice: vanished-resource eligibility below and the
         * retry decision after finalize. Both must agree on which steps
         * failed, and both must read the COMMITTED step rows rather than
         * in-memory counters -- a run spans several worker ticks and no
         * single tick sees them all.
         */
        const committedSteps = await db.select<{ step_id: string; status: string }[]>('collection_run_steps', {
          select: 'step_id,status',
          filters: { run_id: `eq.${run.id}` },
          limit: 5000,
        });
        const failedStepIds = new Set(committedSteps.filter((s) => s.status === 'failed').map((s) => s.step_id));

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

        /**
         * Retry the steps that actually failed, as a NEW run linked by
         * `rerun_of` -- the shape the schema already models.
         *
         * Queued AFTER finalizing, because the partial unique index permits
         * only one active run per connection and the original is only just
         * terminal. `info` steps are deliberately not retried: "this account
         * has not enabled Macie" is a settled answer, not a transient one.
         */
        const retryRunId = await queueRetryRun(db, { ...run, completed_steps: completed, failed_steps: failed }, [...failedStepIds]);
        results.push({ runId: run.id, status, steps: steps.length, ...(retryRunId ? { retryRunId } : {}) });
      } else {
        results.push({ runId: run.id, status: 'RUNNING', progress: `${end}/${steps.length}` });
      }
    }

    return okJson({ advanced: results.length, results });
  }),
);

/**
 * Advances one CUR run by a single file.
 *
 * One file per tick keeps each slice comfortably inside the request budget
 * and makes progress durable between them. Ingestion is an idempotent upsert
 * on (connection_id, resource_id, usage_date), so re-running a partially
 * ingested file corrects rather than duplicates -- the checkpoint is an
 * efficiency measure, not a correctness one.
 */
async function advanceCurRun(db: Db, env: Env, run: CollectionRunRow, now: number): Promise<unknown> {
  const files = run.planned_steps ?? [];
  const checkpointData = ((run as unknown as { checkpoint_data?: CurCheckpoint }).checkpoint_data) ?? {};
  const nextFile = files[run.step_cursor];

  if (!nextFile) {
    // Every file finished. cur_last_synced_at is stamped ONLY here, because
    // it is what the UI reads as "your billing data is current as of" --
    // stamping it on a partial ingest would make incomplete cost data look
    // complete.
    if (allFilesComplete(files, new Set(Object.keys(checkpointData)))) {
      await finalizeCurRun(db, run.connection_id, new Date(now).toISOString());
    }
    const status = await finalizeRun(db, run, {}, now);
    return { runId: run.id, capability: 'billing_cur', status };
  }

  const connection = await loadConnection(db, run.org_id, null, run.connection_id);
  if (!connection) {
    await finalizeRun(db, run, {}, now);
    return { runId: run.id, capability: 'billing_cur', status: 'FAILED', error: 'connection_missing' };
  }

  const cfg = await db.select<{ cur_s3_bucket: string | null; cur_s3_region: string | null }[]>('cloud_connections', {
    select: 'cur_s3_bucket,cur_s3_region',
    filters: { id: `eq.${run.connection_id}` },
  });
  const resolved = await resolveCredentials(env, connection as never);
  if ('error' in resolved || !cfg[0]?.cur_s3_bucket) {
    await finalizeRun(db, run, {}, now);
    return { runId: run.id, capability: 'billing_cur', status: 'FAILED', error: 'credentials_or_config_unavailable' };
  }

  const outcome = await ingestCurFile(nextFile, checkpointData, async (key, skipRows) => {
    const batch = await parseCurBatch(resolved.creds, cfg[0].cur_s3_bucket!, cfg[0].cur_s3_region ?? 'us-east-1', key, skipRows);
    if ('error' in batch) return { error: batch.error };
    if (batch.costRows.length > 0) {
      const grouped = new Map<string, { resource_id: string; service: string; region: string | null; usage_date: string; unblended_cost: number }>();
      for (const row of batch.costRows) {
        const k = `${row.resource_id}:${row.usage_date}`;
        const existing = grouped.get(k);
        if (existing) existing.unblended_cost += row.unblended_cost;
        else grouped.set(k, { ...row });
      }
      const rows = [...grouped.values()].map((row) => ({ connection_id: run.connection_id, ...row, unblended_cost: Math.round(row.unblended_cost * 100) / 100 }));
      await db.insert('resource_costs?on_conflict=connection_id,resource_id,usage_date', rows, 'resolution=merge-duplicates,return=minimal');
    }
    return { rowsProcessed: batch.rowsProcessed, done: batch.done };
  });

  const nextCheckpoint = advanceCheckpoint(checkpointData, nextFile, outcome.rowsProcessed);

  await db.insert(
    'collection_run_steps',
    {
      run_id: run.id, step_id: nextFile, step_index: run.step_cursor,
      status: outcome.error ? 'failed' : outcome.done ? 'succeeded' : 'skipped',
      records_written: outcome.rowsProcessed,
      error_message: outcome.error ?? null,
      finished_at: new Date(now).toISOString(),
    },
    'return=minimal',
  ).catch(() => {
    // Duplicate step row means this file is being resumed across ticks, which
    // is the normal path for a large file.
  });

  await db.update(
    'collection_runs',
    { id: `eq.${run.id}` },
    {
      // Only advance past the file once it genuinely finished; an interrupted
      // file keeps the cursor so the next tick resumes it.
      step_cursor: outcome.done ? run.step_cursor + 1 : run.step_cursor,
      completed_steps: outcome.done ? run.completed_steps + 1 : run.completed_steps,
      failed_steps: outcome.error ? run.failed_steps + 1 : run.failed_steps,
      checkpoint_data: nextCheckpoint,
      heartbeat_at: new Date(now).toISOString(),
      lease_expires_at: new Date(now + 15 * 60 * 1000).toISOString(),
      updated_at: new Date(now).toISOString(),
    },
    'return=minimal',
  );

  return { runId: run.id, capability: 'billing_cur', file: nextFile, rows: outcome.rowsProcessed, done: outcome.done };
}
