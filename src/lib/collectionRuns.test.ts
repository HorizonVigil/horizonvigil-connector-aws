import { describe, it, expect, vi } from 'vitest';
import { isLeaseExpired, createOrGetActiveRun, claimRun, checkpoint, finalizeRun, toRunResponse, LEASE_SECONDS, STEPS_PER_SLICE, type CollectionRunRow } from './collectionRuns';
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

/**
 * AWS-06 / AWS-12 regression: the evidence read was silently truncated.
 *
 * `finalizeRun` asked for `limit: 5000`, but PostgREST caps a response at
 * 1,000 rows server-side before any app-level limit applies. A 1,628-step run
 * was therefore finalized from its first 1,000 steps.
 *
 * Production, 2026-09-15: the run stored `error_summary` = "12 of 1000
 * step(s) failed" when it had **17** failures across **1,628** steps.
 */
describe('finalize reads every committed step, not the first page', () => {
  /** A db whose select honours limit/offset and caps each page at 1,000, as PostgREST does. */
  const pagedDb = (statuses: ('succeeded' | 'failed' | 'skipped' | 'info')[]) => {
    const update = vi.fn().mockResolvedValue([]);
    const select = vi.fn(async (_table: string, opts: { limit?: number; offset?: number }) => {
      const offset = opts.offset ?? 0;
      const limit = Math.min(opts.limit ?? 1000, 1000); // the server-side cap
      return statuses.slice(offset, offset + limit).map((status) => ({ status }));
    });
    return { db: { select, update } as unknown as Db, select, update };
  };

  const run1628 = (failedIndices: number[]) => {
    const statuses = Array.from({ length: 1628 }, () => 'succeeded' as const);
    const out: ('succeeded' | 'failed')[] = [...statuses];
    for (const i of failedIndices) out[i] = 'failed';
    return out;
  };

  it('does not report SUCCEEDED when every failure sits beyond the first page', async () => {
    // The exact shape that made the guarantee unreachable: 17 failures, all
    // past row 1,000, so a truncated read sees a flawless run.
    const failed = Array.from({ length: 17 }, (_, i) => 1100 + i);
    const { db } = pagedDb(run1628(failed));

    expect(await finalizeRun(db, run({ status: 'RUNNING' }))).toBe('PARTIALLY_SUCCEEDED');
  });

  it('counts failures against the true total, not the page size', async () => {
    const failed = Array.from({ length: 17 }, (_, i) => 1100 + i);
    const { db, update } = pagedDb(run1628(failed));

    await finalizeRun(db, run({ status: 'RUNNING' }));

    const patch = update.mock.calls[0]?.[2] as { error_summary: string };
    expect(patch.error_summary).toBe('17 of 1628 step(s) failed');
    // The literal that gave the truncation away in production.
    expect(patch.error_summary).not.toContain('of 1000');
  });

  it('pages until the run is exhausted', async () => {
    const { db, select } = pagedDb(run1628([]));
    await finalizeRun(db, run({ status: 'RUNNING' }));

    // 1,628 rows over a 1,000-row cap is two pages; the second is short, so
    // no third request is needed to prove the end.
    expect(select).toHaveBeenCalledTimes(2);
    expect((select.mock.calls[1]?.[1] as { offset: number }).offset).toBe(1000);
  });

  it('orders the read so paging cannot repeat or skip a row', async () => {
    const { db, select } = pagedDb(run1628([]));
    await finalizeRun(db, run({ status: 'RUNNING' }));

    // Without an explicit order, PostgREST's row order is unspecified between
    // requests -- which is also why WHICH 1,000 rows came back was luck.
    expect((select.mock.calls[0]?.[1] as { order: string }).order).toBe('step_index.asc');
  });

  it('still succeeds a genuinely clean multi-page run', async () => {
    const { db } = pagedDb(run1628([]));
    expect(await finalizeRun(db, run({ status: 'RUNNING' }))).toBe('SUCCEEDED');
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

/**
 * AWS-06 — the lease must not outlive the slice that held it.
 *
 * `checkpoint` previously renewed the lease to now + 15 minutes on the way
 * OUT of a slice, when no worker was holding the run any more. A parked run
 * therefore stayed reserved against a worker that had already returned, and
 * the next tick could not claim it however often the scheduler fired.
 *
 * Measured on a real 1,628-step production run: 14 slices, attempt=14,
 * 03:35 -> 07:50 = 4h15m, roughly 18 minutes per slice against a 5-minute
 * scheduler. Inventory was up to four hours stale for no other reason.
 */
describe('lease lifetime', () => {
  it('releases the lease at the end of a slice instead of extending it', async () => {
    const update = vi.fn().mockResolvedValue([]);
    const db = { update } as unknown as Db;
    await checkpoint(db, 'run-1', { stepCursor: 120, completedSteps: 120, failedSteps: 0, degradedResourceTypes: [] }, NOW);

    const patch = update.mock.calls[0][2] as Record<string, unknown>;
    expect(patch.lease_owner).toBeNull();
    expect(patch.lease_expires_at).toBeNull();
    // The load-bearing negative: the pre-fix code wrote a future expiry here.
    expect(patch.lease_expires_at).not.toBe(new Date(NOW + LEASE_SECONDS * 1000).toISOString());
  });

  /**
   * Crash recovery is the only reason the lease has a timeout, so it must
   * survive this change: a worker that dies MID-slice never reaches
   * checkpoint, so nothing releases its lease and it expires on its own.
   */
  it('still treats a lease held into the future as live', () => {
    const held = run({ status: 'RUNNING', lease_expires_at: new Date(NOW + 60_000).toISOString() });
    expect(isLeaseExpired(held, NOW)).toBe(false);
  });

  it('treats a released lease as claimable immediately', () => {
    expect(isLeaseExpired(run({ status: 'RUNNING', lease_expires_at: null }), NOW)).toBe(true);
  });

  /**
   * Comparing `status` alone did not exclude a second worker on the recovery
   * path: reclaiming a RUNNING run transitions RUNNING -> RUNNING, so the
   * winner's write leaves `status` exactly as the loser's filter expects and
   * both updates match. The lease condition is what actually serialises them.
   */
  it('claims only when the lease is free, not merely when the status matches', async () => {
    const update = vi.fn().mockResolvedValue([run({ status: 'RUNNING' })]);
    const db = { update } as unknown as Db;
    await claimRun(db, run({ status: 'RUNNING' }), 'worker-a', NOW);

    const filters = update.mock.calls[0][1] as Record<string, string>;
    expect(filters.or).toBe(`(lease_owner.is.null,lease_expires_at.lt.${new Date(NOW).toISOString()})`);
    expect(filters.status).toBe('eq.RUNNING');
  });

  it('takes a lease that extends past the slice it is claimed for', async () => {
    const update = vi.fn().mockResolvedValue([run({ status: 'RUNNING' })]);
    const db = { update } as unknown as Db;
    await claimRun(db, run(), 'worker-a', NOW);
    const patch = update.mock.calls[0][2] as Record<string, unknown>;
    expect(patch.lease_expires_at).toBe(new Date(NOW + LEASE_SECONDS * 1000).toISOString());
    expect(patch.lease_owner).toBe('worker-a');
  });
});

/**
 * Blocker 2 boundary matrix. The cap is 1,000, so the interesting sizes are
 * the ones either side of it and the real 1,628-step run that exposed this.
 */
describe('finalize across page boundaries', () => {
  const pagedDb = (statuses: ('succeeded' | 'failed')[]) => {
    const update = vi.fn().mockResolvedValue([]);
    const select = vi.fn(async (_t: string, opts: { limit?: number; offset?: number }) => {
      const offset = opts.offset ?? 0;
      const limit = Math.min(opts.limit ?? 1000, 1000);
      return statuses.slice(offset, offset + limit).map((status) => ({ status }));
    });
    return { db: { select, update } as unknown as Db, update, select };
  };

  const withFailuresAt = (total: number, failedIndices: number[]) => {
    const out: ('succeeded' | 'failed')[] = Array.from({ length: total }, () => 'succeeded');
    for (const i of failedIndices) out[i] = 'failed';
    return out;
  };

  const summaryOf = (update: ReturnType<typeof vi.fn>) =>
    (update.mock.calls[0]?.[2] as { error_summary: string | null }).error_summary;

  for (const total of [0, 1, 999, 1000, 1001, 1628, 5000]) {
    it(`reads all ${total} steps`, async () => {
      const { db, update } = pagedDb(withFailuresAt(total, total > 0 ? [total - 1] : []));
      const status = await finalizeRun(db, run({ status: 'RUNNING' }));

      if (total === 0) {
        // A run that executed nothing has produced no trustworthy result.
        expect(status).toBe('FAILED');
        return;
      }
      if (total === 1) {
        // Its only step failed, so there is no success to partially credit.
        expect(status).toBe('FAILED');
        return;
      }
      expect(status).toBe('PARTIALLY_SUCCEEDED');
      expect(summaryOf(update)).toBe(`1 of ${total} step(s) failed`);
    });
  }

  it('sees a failure on the FIRST page', async () => {
    const { db, update } = pagedDb(withFailuresAt(1628, [0]));
    expect(await finalizeRun(db, run({ status: 'RUNNING' }))).toBe('PARTIALLY_SUCCEEDED');
    expect(summaryOf(update)).toBe('1 of 1628 step(s) failed');
  });

  it('sees a failure on the LAST page', async () => {
    // The case the old truncated read could not see at all.
    const { db, update } = pagedDb(withFailuresAt(1628, [1627]));
    expect(await finalizeRun(db, run({ status: 'RUNNING' }))).toBe('PARTIALLY_SUCCEEDED');
    expect(summaryOf(update)).toBe('1 of 1628 step(s) failed');
  });

  it('sees failures spread across every page', async () => {
    const { db, update } = pagedDb(withFailuresAt(5000, [10, 1500, 2500, 3500, 4999]));
    expect(await finalizeRun(db, run({ status: 'RUNNING' }))).toBe('PARTIALLY_SUCCEEDED');
    expect(summaryOf(update)).toBe('5 of 5000 step(s) failed');
  });

  it('writes no error summary when nothing failed', async () => {
    const { db, update } = pagedDb(withFailuresAt(1628, []));
    expect(await finalizeRun(db, run({ status: 'RUNNING' }))).toBe('SUCCEEDED');
    expect(summaryOf(update)).toBeNull();
  });

  it('is FAILED when every step failed, however many pages', async () => {
    const { db } = pagedDb(Array.from({ length: 1628 }, () => 'failed' as const));
    expect(await finalizeRun(db, run({ status: 'RUNNING' }))).toBe('FAILED');
  });

  /** A cancelled run is reported by what it actually produced. */
  it('reports a cancelled multi-page run by its committed work', async () => {
    const clean = pagedDb(withFailuresAt(1628, []));
    expect(await finalizeRun(clean.db, run({ status: 'CANCEL_REQUESTED' }), { canceled: true })).toBe('CANCELED');

    const dirty = pagedDb(withFailuresAt(1628, [1600]));
    expect(await finalizeRun(dirty.db, run({ status: 'CANCEL_REQUESTED' }), { canceled: true })).toBe('PARTIALLY_SUCCEEDED');
  });

  /** Finalizing twice must reach the same verdict, not drift. */
  it('is deterministic when finalized twice', async () => {
    const statuses = withFailuresAt(1628, [17, 1200, 1627]);
    const first = pagedDb(statuses);
    const second = pagedDb(statuses);

    expect(await finalizeRun(first.db, run({ status: 'RUNNING' })))
      .toBe(await finalizeRun(second.db, run({ status: 'RUNNING' })));
    expect(summaryOf(first.update)).toBe(summaryOf(second.update));
  });

  /** The production regression, stated exactly. */
  it('REGRESSION: 1,628 steps with 17 failures', async () => {
    const { db, update } = pagedDb(withFailuresAt(1628, Array.from({ length: 17 }, (_, i) => 1100 + i)));

    expect(await finalizeRun(db, run({ status: 'RUNNING' }))).toBe('PARTIALLY_SUCCEEDED');
    expect(summaryOf(update)).toBe('17 of 1628 step(s) failed');
    // What production actually stored on 2026-09-15.
    expect(summaryOf(update)).not.toBe('12 of 1000 step(s) failed');
  });
});
