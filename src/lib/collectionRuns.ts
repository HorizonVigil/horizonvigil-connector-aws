import { type Db, type JobStatus, terminalStatusFor, assertTransition } from '@horizonvigil/shared-lib';

/**
 * Durable collection runs — the server-owned replacement for browser
 * orchestration (ADR 0001, connector build prompt §2.4/§3.1/§3.2).
 *
 * What this replaces: the frontend fetched a 1,628-step plan, looped
 * `run-step` once per step from a tab, accumulated errors in browser memory,
 * and posted its own `runStartedAt`, `stepErrors` and `totalSteps` to
 * `finalize`. Closing the tab, sleeping the laptop, changing networks or
 * losing the token interrupted the run, and the server treated
 * client-submitted timestamps and error lists as authoritative job evidence.
 *
 * The design is claim-and-advance, chosen because Cloud Run caps a request at
 * 60 minutes while observed scans run to ~384 minutes: a worker claims a run
 * under a time-boxed lease, executes a bounded SLICE of steps, writes a
 * checkpoint, and returns. The next tick resumes from the checkpoint. See
 * ADR 0001 for why this rather than Temporal, one long request, or background
 * work after responding.
 */

export interface CollectionRunRow {
  id: string;
  org_id: string;
  connection_id: string;
  capability: string;
  status: JobStatus;
  trigger: string;
  requested_by: string | null;
  idempotency_key: string;
  planned_steps: string[];
  step_cursor: number;
  total_steps: number;
  completed_steps: number;
  failed_steps: number;
  lease_owner: string | null;
  lease_expires_at: string | null;
  attempt: number;
  next_attempt_at: string | null;
  degraded_resource_types: string[];
  error_summary: string | null;
  correlation_id: string;
  queued_at: string;
  started_at: string | null;
  heartbeat_at: string | null;
  finished_at: string | null;
}

/**
 * How long a worker may hold a run before another worker may reclaim it.
 *
 * Longer than a slice so a healthy worker never loses its own run mid-slice,
 * short enough that a worker killed by a deploy or an instance recycle does
 * not strand the run for long. Cloud Run's request ceiling is 60 minutes, so
 * a 15-minute lease cannot outlive the process holding it.
 */
export const LEASE_SECONDS = 15 * 60;

/**
 * Steps executed per worker tick.
 *
 * Bounded so a slice comfortably finishes inside the request budget with room
 * for the finalize write. A 1,628-step scan therefore spans several ticks --
 * which is the point: progress is durable between them, so nothing is lost if
 * the worker dies.
 */
export const STEPS_PER_SLICE = 120;

/** Runs whose lease has expired are reclaimable — this is how a dead worker's run recovers with no human intervention. */
export function isLeaseExpired(run: Pick<CollectionRunRow, 'lease_expires_at'>, now: number = Date.now()): boolean {
  if (!run.lease_expires_at) return true;
  const expiry = Date.parse(run.lease_expires_at);
  return !Number.isFinite(expiry) || expiry <= now;
}

/**
 * Creates a run, or returns the one already in flight.
 *
 * "One manual sync creates one durable job despite repeated clicks or
 * multiple tabs" is enforced by a partial unique index on
 * (connection_id) WHERE status IN (active states) -- in the DATABASE, because
 * an application-level check races exactly as the browser's in-memory
 * per-tab Set did.
 *
 * Returns `created: false` when an active run already exists, so the caller
 * can answer 200 with the existing run instead of erroring. Starting a sync
 * twice is a normal thing for a user to do; it should be idempotent, not a
 * failure.
 */
export async function createOrGetActiveRun(
  db: Db,
  input: { orgId: string; connectionId: string; requestedBy: string | null; trigger: string; plannedSteps: string[]; idempotencyKey: string },
): Promise<{ run: CollectionRunRow; created: boolean }> {
  const existing = await db.select<CollectionRunRow[]>('collection_runs', {
    select: '*',
    filters: {
      connection_id: `eq.${input.connectionId}`,
      status: 'in.(QUEUED,RUNNING,WAITING_RETRY,CANCEL_REQUESTED,PAUSING,PAUSED)',
    },
    limit: 1,
  });
  if (existing[0]) return { run: existing[0], created: false };

  try {
    const [row] = await db.insert<CollectionRunRow[]>('collection_runs', {
      org_id: input.orgId,
      connection_id: input.connectionId,
      capability: 'inventory',
      status: 'QUEUED',
      trigger: input.trigger,
      requested_by: input.requestedBy,
      idempotency_key: input.idempotencyKey,
      planned_steps: input.plannedSteps,
      total_steps: input.plannedSteps.length,
    });
    return { run: row, created: true };
  } catch {
    // Lost the race against a concurrent create; the unique index did its job.
    // Re-read rather than surfacing a constraint error, so two tabs clicking
    // at once both end up watching the same run.
    const raced = await db.select<CollectionRunRow[]>('collection_runs', {
      select: '*',
      filters: {
        connection_id: `eq.${input.connectionId}`,
        status: 'in.(QUEUED,RUNNING,WAITING_RETRY,CANCEL_REQUESTED,PAUSING,PAUSED)',
      },
      limit: 1,
    });
    if (raced[0]) return { run: raced[0], created: false };
    throw new Error('Could not create or find a collection run for this connection.');
  }
}

/**
 * Claims runs a worker may advance: queued, or running with an expired lease
 * (their worker died), or due for retry.
 *
 * The claim is a conditional UPDATE, so two workers cannot hold the same run:
 * whichever writes first owns the lease, and the loser's update matches no row.
 */
export async function claimRun(db: Db, run: CollectionRunRow, leaseOwner: string, now: number = Date.now()): Promise<boolean> {
  const nextStatus: JobStatus = 'RUNNING';
  assertTransition(run.status, nextStatus);

  const leaseExpiry = new Date(now + LEASE_SECONDS * 1000).toISOString();
  const updated = await db.update<CollectionRunRow[]>(
    'collection_runs',
    {
      id: `eq.${run.id}`,
      // Only claim if nobody else has since taken it. Without this the two
      // workers would both believe they own the run.
      status: `eq.${run.status}`,
    },
    {
      status: nextStatus,
      lease_owner: leaseOwner,
      lease_expires_at: leaseExpiry,
      started_at: run.started_at ?? new Date(now).toISOString(),
      heartbeat_at: new Date(now).toISOString(),
      attempt: run.attempt + 1,
      updated_at: new Date(now).toISOString(),
    },
  );
  return updated.length > 0;
}

/** Extends the lease and advances the checkpoint after a slice. */
export async function checkpoint(
  db: Db,
  runId: string,
  patch: { stepCursor: number; completedSteps: number; failedSteps: number; degradedResourceTypes: string[] },
  now: number = Date.now(),
): Promise<void> {
  await db.update(
    'collection_runs',
    { id: `eq.${runId}` },
    {
      step_cursor: patch.stepCursor,
      completed_steps: patch.completedSteps,
      failed_steps: patch.failedSteps,
      degraded_resource_types: patch.degradedResourceTypes,
      heartbeat_at: new Date(now).toISOString(),
      lease_expires_at: new Date(now + LEASE_SECONDS * 1000).toISOString(),
      updated_at: new Date(now).toISOString(),
    },
    'return=minimal',
  );
}

/**
 * Closes a run using its COMMITTED step rows.
 *
 * Deliberately re-reads the steps rather than trusting counters carried in
 * memory: the counters are a convenience for progress display, while the step
 * rows are the evidence. This is the line that makes "succeeded with failed
 * steps" unreachable.
 */
export async function finalizeRun(db: Db, run: CollectionRunRow, opts: { canceled?: boolean } = {}, now: number = Date.now()): Promise<JobStatus> {
  const steps = await db.select<{ status: 'succeeded' | 'failed' | 'skipped' | 'info' }[]>('collection_run_steps', {
    select: 'status',
    filters: { run_id: `eq.${run.id}` },
    limit: 5000,
  });

  const status = terminalStatusFor(steps, opts);
  const failed = steps.filter((s) => s.status === 'failed').length;

  await db.update(
    'collection_runs',
    { id: `eq.${run.id}` },
    {
      status,
      finished_at: new Date(now).toISOString(),
      lease_owner: null,
      lease_expires_at: null,
      error_summary: failed > 0 ? `${failed} of ${steps.length} step(s) failed` : null,
      updated_at: new Date(now).toISOString(),
    },
    'return=minimal',
  );
  return status;
}

/** Public projection of a run. Never exposes lease internals or raw provider text. */
export function toRunResponse(run: CollectionRunRow) {
  return {
    id: run.id,
    connectionId: run.connection_id,
    capability: run.capability,
    status: run.status,
    trigger: run.trigger,
    progress: {
      totalSteps: run.total_steps,
      completedSteps: run.completed_steps,
      failedSteps: run.failed_steps,
      // Percent is derived, never stored, so it cannot drift from the counts.
      percent: run.total_steps > 0 ? Math.round((run.step_cursor / run.total_steps) * 100) : 0,
    },
    attempt: run.attempt,
    correlationId: run.correlation_id,
    queuedAt: run.queued_at,
    startedAt: run.started_at,
    heartbeatAt: run.heartbeat_at,
    finishedAt: run.finished_at,
    errorSummary: run.error_summary,
  };
}
