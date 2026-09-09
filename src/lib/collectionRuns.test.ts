import { describe, it, expect, vi } from 'vitest';
import { isLeaseExpired, createOrGetActiveRun, claimRun, finalizeRun, toRunResponse, LEASE_SECONDS, STEPS_PER_SLICE, type CollectionRunRow } from './collectionRuns';
import type { Db } from '@horizonvigil/shared-lib';

/**
 * Phase 3 durability guarantees, stated as acceptance criteria in the build
 * prompt:
 *   "One manual sync creates one durable job despite repeated clicks or
 *    multiple tabs."
 *   "A killed worker resumes from the last durable checkpoint without
 *    duplicates."
 *   "A failed required step yields PARTIALLY_SUCCEEDED or FAILED, never
 *    SUCCEEDED."
 */
const NOW = Date.parse('2026-09-09T12:00:00Z');

function run(over: Partial<CollectionRunRow> = {}): CollectionRunRow {
  return {
    id: 'run-1', org_id: 'org-1', connection_id: 'conn-1', capability: 'inventory',
    status: 'QUEUED', trigger: 'user', requested_by: 'u1', idempotency_key: 'k1',
    planned_steps: ['a', 'b', 'c'], step_cursor: 0, total_steps: 3, completed_steps: 0, failed_steps: 0,
    lease_owner: null, lease_expires_at: null, attempt: 0, next_attempt_at: null,
    degraded_resource_types: [], error_summary: null, correlation_id: 'corr-1',
    queued_at: '2026-09-09T11:00:00Z', started_at: null, heartbeat_at: null, finished_at: null,
    ...over,
  };
}

describe('lease recovery — a killed worker must not strand a run', () => {
  it('treats a run with no lease as claimable', () => {
    expect(isLeaseExpired(run(), NOW)).toBe(true);
  });

  it('protects a run whose worker is alive', () => {
    const held = run({ lease_expires_at: new Date(NOW + 60_000).toISOString() });
    expect(isLeaseExpired(held, NOW)).toBe(false);
  });

  it('reclaims a run whose worker died', () => {
    const dead = run({ lease_expires_at: new Date(NOW - 1000).toISOString() });
    expect(isLeaseExpired(dead, NOW)).toBe(true);
  });

  it('treats an unparseable lease as expired rather than holding it forever', () => {
    expect(isLeaseExpired(run({ lease_expires_at: 'garbage' }), NOW)).toBe(true);
  });

  it('uses a lease shorter than Cloud Run\'s 60-minute request ceiling', () => {
    // A lease that could outlive the process holding it would let a dead
    // worker block its run past the point anyone could recover it.
    expect(LEASE_SECONDS).toBeLessThan(60 * 60);
  });

  it('slices small enough to finish inside a request budget', () => {
    expect(STEPS_PER_SLICE).toBeGreaterThan(0);
    expect(STEPS_PER_SLICE).toBeLessThanOrEqual(200);
  });
});

describe('one job per connection despite repeated clicks', () => {
  it('returns the existing run instead of creating a second', async () => {
    const existing = run({ id: 'already-running', status: 'RUNNING' });
    const insert = vi.fn();
    const db = { select: vi.fn().mockResolvedValue([existing]), insert } as unknown as Db;

    const out = await createOrGetActiveRun(db, {
      orgId: 'org-1', connectionId: 'conn-1', requestedBy: 'u1', trigger: 'user',
      plannedSteps: ['a'], idempotencyKey: 'k2',
    });

    expect(out.created).toBe(false);
    expect(out.run.id).toBe('already-running');
    expect(insert).not.toHaveBeenCalled();
  });

  it('creates one when nothing is in flight', async () => {
    const db = {
      select: vi.fn().mockResolvedValue([]),
      insert: vi.fn().mockResolvedValue([run({ id: 'new-run' })]),
    } as unknown as Db;

    const out = await createOrGetActiveRun(db, {
      orgId: 'org-1', connectionId: 'conn-1', requestedBy: 'u1', trigger: 'user',
      plannedSteps: ['a'], idempotencyKey: 'k1',
    });
    expect(out.created).toBe(true);
  });

  it('recovers by re-reading when it loses the insert race', async () => {
    // Two tabs clicking at once: the unique index rejects the loser, which
    // must then watch the winner's run rather than surfacing a constraint
    // error to the user.
    const select = vi.fn()
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([run({ id: 'winner', status: 'RUNNING' })]);
    const db = { select, insert: vi.fn().mockRejectedValue(new Error('duplicate key')) } as unknown as Db;

    const out = await createOrGetActiveRun(db, {
      orgId: 'org-1', connectionId: 'conn-1', requestedBy: 'u1', trigger: 'user',
      plannedSteps: ['a'], idempotencyKey: 'k1',
    });
    expect(out.created).toBe(false);
    expect(out.run.id).toBe('winner');
  });
});

describe('claim is conditional so two workers cannot hold one run', () => {
  it('claims when the status is unchanged', async () => {
    const db = { update: vi.fn().mockResolvedValue([run({ status: 'RUNNING' })]) } as unknown as Db;
    expect(await claimRun(db, run(), 'worker-a', NOW)).toBe(true);
  });

  it('fails the claim when another worker already moved it', async () => {
    // The conditional update matches no row, so the loser simply skips it.
    const db = { update: vi.fn().mockResolvedValue([]) } as unknown as Db;
    expect(await claimRun(db, run(), 'worker-b', NOW)).toBe(false);
  });
});

describe('terminal status comes from committed steps, not from counters', () => {
  it('is PARTIALLY_SUCCEEDED when any step failed', async () => {
    const db = {
      select: vi.fn().mockResolvedValue([{ status: 'succeeded' }, { status: 'failed' }]),
      update: vi.fn().mockResolvedValue([]),
    } as unknown as Db;
    expect(await finalizeRun(db, run({ status: 'RUNNING' }))).toBe('PARTIALLY_SUCCEEDED');
  });

  it('is SUCCEEDED only when nothing failed', async () => {
    const db = {
      select: vi.fn().mockResolvedValue([{ status: 'succeeded' }, { status: 'succeeded' }]),
      update: vi.fn().mockResolvedValue([]),
    } as unknown as Db;
    expect(await finalizeRun(db, run({ status: 'RUNNING' }))).toBe('SUCCEEDED');
  });

  it('ignores in-memory counters that disagree with the step rows', async () => {
    // The browser used to supply its own error list; evidence must win.
    const db = {
      select: vi.fn().mockResolvedValue([{ status: 'failed' }]),
      update: vi.fn().mockResolvedValue([]),
    } as unknown as Db;
    const optimistic = run({ status: 'RUNNING', failed_steps: 0, completed_steps: 99 });
    expect(await finalizeRun(db, optimistic)).toBe('FAILED');
  });
});

describe('run projection', () => {
  it('derives percent rather than storing it', () => {
    const r = toRunResponse(run({ step_cursor: 1, total_steps: 4 }));
    expect(r.progress.percent).toBe(25);
  });

  it('does not leak lease internals to the client', () => {
    const r = toRunResponse(run({ lease_owner: 'worker:secret' })) as Record<string, unknown>;
    expect(JSON.stringify(r)).not.toMatch(/lease|worker:secret/);
  });

  it('reports 0 percent for an empty plan rather than dividing by zero', () => {
    expect(toRunResponse(run({ total_steps: 0, step_cursor: 0 })).progress.percent).toBe(0);
  });
});
