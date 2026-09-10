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


/**
 * How many times a run's failed steps may be retried.
 *
 * Two total attempts, not more. A step that failed after the AWS helper had
 * already exhausted its own per-call retries is usually failing for a
 * persistent reason -- a missing permission, a service the account has not
 * enabled -- and hammering it again adds load to an account that may already
 * be throttling. One retry after a real backoff catches the transient cases
 * without pretending a permission error is transient.
 */
export const MAX_RUN_ATTEMPTS = 2;

/** Base delay before the first retry. */
const RETRY_BASE_MS = 60_000;
/** Ceiling, so a long chain cannot push a retry beyond a useful horizon. */
const RETRY_MAX_MS = 15 * 60_000;

/**
 * Exponential backoff with full jitter, matching awsErrors.ts's policy shape.
 *
 * Jitter matters here for the same reason it does per-call: without it, a
 * regional AWS outage that fails every connection's scan at once would
 * schedule every retry for the same instant and reproduce the thundering
 * herd the backoff exists to prevent.
 */
export function retryDelayMs(attempt: number, random: () => number = Math.random): number {
  const ceiling = Math.min(RETRY_BASE_MS * 2 ** Math.max(0, attempt - 1), RETRY_MAX_MS);
  return Math.floor(random() * ceiling);
}

/**
 * Whether a finished run should have its failed steps retried.
 *
 * `attempt` is incremented by claimRun, so a run claimed once has attempt 1.
 * Retrying while attempt < MAX_RUN_ATTEMPTS therefore permits exactly one
 * follow-up run.
 */
export function shouldRetryRun(run: Pick<CollectionRunRow, 'attempt'>, failedStepIds: readonly string[]): boolean {
  return failedStepIds.length > 0 && run.attempt < MAX_RUN_ATTEMPTS;
}

/**
 * Queues a retry as a NEW run linked by `rerun_of`, rather than rewinding the
 * original.
 *
 * The schema already models it this way, and it is the honest shape: the
 * original run keeps its real outcome and its real step evidence instead of
 * having its progress counters rewound, and the retry carries only the steps
 * that actually failed. Rewinding `step_cursor` in place would make a run's
 * own history unreadable -- progress would move backwards and the committed
 * step rows would no longer correspond to the plan.
 *
 * Returns the new run id, or null when a retry was not queued (nothing
 * failed, attempts exhausted, or another run is already active on this
 * connection -- the partial unique index enforces that last one, and losing
 * the race is a normal outcome, not an error).
 */
export async function queueRetryRun(
  db: Db,
  run: CollectionRunRow,
  failedStepIds: readonly string[],
  now: number = Date.now(),
  random: () => number = Math.random,
): Promise<string | null> {
  if (!shouldRetryRun(run, failedStepIds)) return null;

  const nextAttemptAt = new Date(now + retryDelayMs(run.attempt, random)).toISOString();
  try {
    const [row] = await db.insert<{ id: string }[]>('collection_runs', {
      org_id: run.org_id,
      connection_id: run.connection_id,
      capability: run.capability,
      // WAITING_RETRY, not QUEUED: the worker must honour next_attempt_at
      // before claiming it, and the status is what makes the wait visible
      // rather than looking like a run that is merely slow to start.
      status: 'WAITING_RETRY',
      trigger: 'retry',
      requested_by: run.requested_by,
      idempotency_key: `${run.idempotency_key}:retry:${run.attempt}`,
      planned_steps: [...failedStepIds],
      total_steps: failedStepIds.length,
      // Carried so the chain terminates: claimRun increments it, so the
      // retry's own claim takes it to MAX_RUN_ATTEMPTS and shouldRetryRun
      // then refuses a third.
      attempt: run.attempt,
      next_attempt_at: nextAttemptAt,
      rerun_of: run.id,
      correlation_id: run.correlation_id,
    });
    return row?.id ?? null;
  } catch {
    // Another run is already active on this connection (the partial unique
    // index). That run will cover the same steps, so dropping this retry is
    // correct rather than an error worth surfacing.
    return null;
  }
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
