import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { MAX_RUN_ATTEMPTS, retryDelayMs, shouldRetryRun, queueRetryRun, type CollectionRunRow } from './collectionRuns';

/**
 * Phase B — retry between worker ticks.
 *
 * `next_attempt_at` and `WAITING_RETRY` were modelled in the schema and read
 * by the claim query, but NOTHING ever wrote them, so WAITING_RETRY was
 * unreachable and a failed step was simply recorded and forgotten.
 *
 * There were two halves to that bug, and fixing only the first would have
 * looked correct while doing nothing: the claim query also ignored
 * `next_attempt_at`, so a scheduled retry would have been claimed on the very
 * next tick and the backoff would have been decorative.
 */
function run(over: Partial<CollectionRunRow> = {}): CollectionRunRow {
  return {
    id: 'run-1', org_id: 'org-1', connection_id: 'conn-1', capability: 'inventory',
    status: 'RUNNING', trigger: 'user', requested_by: null, idempotency_key: 'key-1',
    planned_steps: ['regional:ec2:us-east-1', 'global:iam'], step_cursor: 2, total_steps: 2,
    completed_steps: 2, failed_steps: 1, lease_owner: null, lease_expires_at: null,
    attempt: 1, next_attempt_at: null, degraded_resource_types: [], error_summary: null,
    correlation_id: 'corr-1', queued_at: 'now', started_at: 'now', heartbeat_at: null, finished_at: null,
    ...over,
  } as CollectionRunRow;
}

describe('retry eligibility', () => {
  it('retries when steps failed and attempts remain', () => {
    expect(shouldRetryRun(run({ attempt: 1 }), ['global:iam'])).toBe(true);
  });

  it('does not retry when nothing failed', () => {
    expect(shouldRetryRun(run({ attempt: 1 }), [])).toBe(false);
  });

  it('stops after MAX_RUN_ATTEMPTS so a permanent failure cannot loop', () => {
    // A step failing for a missing permission will fail again. Retrying it
    // forever adds load to an account that may already be throttling.
    expect(shouldRetryRun(run({ attempt: MAX_RUN_ATTEMPTS }), ['global:iam'])).toBe(false);
    expect(shouldRetryRun(run({ attempt: MAX_RUN_ATTEMPTS + 5 }), ['global:iam'])).toBe(false);
  });
});

describe('backoff', () => {
  it('grows with the attempt number', () => {
    // random() pinned to 1 so the jittered value equals the ceiling.
    expect(retryDelayMs(1, () => 1)).toBeLessThan(retryDelayMs(2, () => 1));
    expect(retryDelayMs(2, () => 1)).toBeLessThan(retryDelayMs(3, () => 1));
  });

  it('is capped, so a long chain cannot schedule a retry hours away', () => {
    expect(retryDelayMs(50, () => 1)).toBeLessThanOrEqual(15 * 60_000);
  });

  it('applies full jitter', () => {
    /**
     * Without jitter, a regional AWS outage failing every connection's scan
     * at once would schedule every retry for the same instant, reproducing
     * the thundering herd the backoff exists to prevent.
     */
    expect(retryDelayMs(3, () => 0)).toBe(0);
    expect(retryDelayMs(3, () => 1)).toBeGreaterThan(0);
  });
});

describe('queueRetryRun', () => {
  function fakeDb(captured: Record<string, unknown>[], shouldThrow = false) {
    return {
      insert: async (_table: string, payload: Record<string, unknown>) => {
        if (shouldThrow) throw new Error('duplicate key value violates unique constraint');
        captured.push(payload);
        return [{ id: 'retry-run-1' }];
      },
    } as never;
  }

  it('queues a NEW run carrying only the failed steps', async () => {
    const captured: Record<string, unknown>[] = [];
    const id = await queueRetryRun(fakeDb(captured), run(), ['global:iam'], 1_000_000, () => 0.5);

    expect(id).toBe('retry-run-1');
    const payload = captured[0];
    expect(payload.planned_steps).toEqual(['global:iam']);
    expect(payload.total_steps).toBe(1);
    // WAITING_RETRY, not QUEUED: the wait must be visible rather than looking
    // like a run that is merely slow to start.
    expect(payload.status).toBe('WAITING_RETRY');
    expect(payload.trigger).toBe('retry');
    // Linked to the original rather than rewinding it, so the first run keeps
    // its real outcome and its real step evidence.
    expect(payload.rerun_of).toBe('run-1');
    expect(payload.next_attempt_at).toBeTruthy();
    expect(Date.parse(payload.next_attempt_at as string)).toBeGreaterThanOrEqual(1_000_000);
  });

  it('carries the attempt count forward so the chain terminates', async () => {
    const captured: Record<string, unknown>[] = [];
    await queueRetryRun(fakeDb(captured), run({ attempt: 1 }), ['global:iam'], 1_000_000, () => 0);
    // claimRun increments on claim, taking this to MAX_RUN_ATTEMPTS, after
    // which shouldRetryRun refuses a third.
    expect(captured[0].attempt).toBe(1);
    expect(shouldRetryRun(run({ attempt: 1 + 1 }), ['global:iam'])).toBe(false);
  });

  it('uses a distinct idempotency key so the retry is not deduped into the original', async () => {
    const captured: Record<string, unknown>[] = [];
    await queueRetryRun(fakeDb(captured), run({ idempotency_key: 'key-1' }), ['global:iam'], 0, () => 0);
    expect(captured[0].idempotency_key).toBe('key-1:retry:1');
    expect(captured[0].idempotency_key).not.toBe('key-1');
  });

  it('returns null rather than throwing when another run is already active', async () => {
    // The partial unique index refuses a second active run per connection.
    // That run covers the same steps, so losing the race is correct, not an
    // error worth surfacing.
    const id = await queueRetryRun(fakeDb([], true), run(), ['global:iam'], 0, () => 0);
    expect(id).toBeNull();
  });

  it('queues nothing when no step failed', async () => {
    const captured: Record<string, unknown>[] = [];
    expect(await queueRetryRun(fakeDb(captured), run(), [], 0, () => 0)).toBeNull();
    expect(captured).toHaveLength(0);
  });
});

describe('the worker actually honours the backoff', () => {
  /**
   * The half of the bug that would otherwise stay hidden. Writing
   * next_attempt_at is useless if the claim query does not filter on it.
   */
  const src = readFileSync(join(__dirname, '..', 'routes', 'collectionRuns.ts'), 'utf8');

  it('filters candidate runs on next_attempt_at', () => {
    expect(src).toContain('next_attempt_at.is.null');
    expect(src).toContain('next_attempt_at.lte.');
  });

  it('keeps non-retry runs claimable', () => {
    // Every non-retry run has a null next_attempt_at. Without the is.null
    // branch the filter would exclude all of them and collection would stop
    // entirely -- a far worse bug than the one being fixed.
    const orClause = /or: `\(next_attempt_at\.is\.null,next_attempt_at\.lte\.\$\{[^}]+\}\)`/;
    expect(src).toMatch(orClause);
  });

  it('queues the retry only after the original run is finalized', () => {
    // The partial unique index permits one active run per connection, so
    // queueing before finalize would always lose the race.
    const finalizeIdx = src.indexOf('const status = await finalizeRun(db, { ...run, completed_steps: completed');
    const retryIdx = src.indexOf('const retryRunId = await queueRetryRun(');
    expect(finalizeIdx).toBeGreaterThan(-1);
    expect(retryIdx).toBeGreaterThan(finalizeIdx);
  });
});
