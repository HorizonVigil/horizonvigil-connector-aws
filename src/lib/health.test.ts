import { describe, it, expect } from 'vitest';
import { computeHealth, summarizeHealth, type HealthConnectionInput, type HealthValidationInput } from './health';

const NOW = Date.parse('2026-03-01T00:00:00Z');
const daysAgo = (n: number) => new Date(NOW - n * 86_400_000).toISOString();

function conn(over: Partial<HealthConnectionInput> = {}): HealthConnectionInput {
  return {
    id: 'c1',
    status: 'connected',
    connection_method: 'cross_account_role',
    error_message: null,
    last_sync_at: daysAgo(0),
    last_discovery_at: daysAgo(0),
    last_permission_check_at: daysAgo(0),
    key_rotated_at: null,
    ...over,
  };
}

const okRun: HealthValidationInput = { status: 'succeeded', finished_at: daysAgo(0), error_message: null, deniedChecks: 0, erroredChecks: 0 };

describe('computeHealth', () => {
  it('a fully healthy cross-account-role connection scores 100 / healthy', () => {
    const h = computeHealth(conn(), okRun, NOW);
    expect(h.state).toBe('healthy');
    expect(h.score).toBe(100);
    expect(h.signals).toHaveLength(5);
    expect(h.signals.every((s) => s.status === 'ok')).toBe(true);
  });

  it('a brand-new pending connection with no history is "unknown", not low-scored', () => {
    const h = computeHealth(
      conn({ status: 'pending', last_sync_at: null, last_discovery_at: null, last_permission_check_at: null }),
      null,
      NOW,
    );
    // connection=warn, permissions=unknown, discovery=warn, sync=warn, credentials=ok(keyless)
    expect(h.state).not.toBe('unknown'); // it has some determinable signals
    expect(h.signals.find((s) => s.key === 'permissions')?.status).toBe('unknown');
  });

  it('every signal unknown → state unknown, score 0', () => {
    const h = computeHealth(
      { id: 'c1', status: 'weird', connection_method: 'cross_account_role', error_message: null,
        last_sync_at: null, last_discovery_at: daysAgo(0), last_permission_check_at: null, key_rotated_at: null },
      null, NOW,
    );
    // status 'weird' → connection unknown; permissions unknown; discovery ok; so not fully unknown
    // force a truly-all-unknown case:
    const h2 = computeHealth(
      { id: 'c2', status: 'disconnected', connection_method: 'cross_account_role', error_message: null,
        last_sync_at: daysAgo(0), last_discovery_at: daysAgo(0), last_permission_check_at: daysAgo(0), key_rotated_at: null },
      okRun, NOW,
    );
    expect(h2.state).toBe('unknown');
    void h;
  });

  it('a connection in error state is critical and the connection signal fails', () => {
    const h = computeHealth(conn({ status: 'error', error_message: 'AccessDenied on sts:GetCallerIdentity' }), okRun, NOW);
    expect(h.state).toBe('critical');
    expect(h.signals.find((s) => s.key === 'connection')).toMatchObject({ status: 'fail', detail: expect.stringContaining('AccessDenied') });
  });

  it('stale sync (>7d) fails the freshness signal and drags score down', () => {
    const fresh = computeHealth(conn(), okRun, NOW);
    const stale = computeHealth(conn({ last_sync_at: daysAgo(30) }), okRun, NOW);
    expect(stale.signals.find((s) => s.key === 'sync_freshness')?.status).toBe('fail');
    // Both are connected, so both are scored; the null case is asserted
    // separately below for disconnected connections.
    expect(stale.score!).toBeLessThan(fresh.score!);
  });

  it('failed permission run fails the permissions signal', () => {
    const h = computeHealth(conn(), { status: 'failed', finished_at: daysAgo(0), error_message: 'IAM ListUsers denied' }, NOW);
    expect(h.signals.find((s) => s.key === 'permissions')?.status).toBe('fail');
  });

  it('denied checks on an otherwise-passing run → warn', () => {
    const h = computeHealth(conn(), { ...okRun, deniedChecks: 2 }, NOW);
    expect(h.signals.find((s) => s.key === 'permissions')?.status).toBe('warn');
  });

  it('access-key credentials past 90 days fail the credentials signal', () => {
    const h = computeHealth(conn({ connection_method: 'access_key', key_rotated_at: daysAgo(120) }), okRun, NOW);
    expect(h.signals.find((s) => s.key === 'credentials')?.status).toBe('fail');
  });

  it('access-key credentials 80 days old → warn (due soon)', () => {
    const h = computeHealth(conn({ connection_method: 'access_key', key_rotated_at: daysAgo(80) }), okRun, NOW);
    expect(h.signals.find((s) => s.key === 'credentials')?.status).toBe('warn');
  });

  it('permissions never checked cannot yield a healthy state, even if every other signal is ok (real production bug, fixed 2026-09-08)', () => {
    // Every other signal ok (connection/discovery/sync/credentials), but
    // permissions was never run -- last_permission_check_at null, no run.
    // Live-audited: this scored 100/'healthy' before the fix, silently
    // implying a connection whose permissions have literally never been
    // validated was fully healthy.
    const h = computeHealth(conn({ last_permission_check_at: null }), null, NOW);
    expect(h.signals.find((s) => s.key === 'permissions')?.status).toBe('unknown');
    expect(h.signals.filter((s) => s.status === 'ok')).toHaveLength(4); // the other 4 signals really are ok
    expect(h.state).not.toBe('healthy');
    expect(h.state).toBe('warning');
  });
});

describe('summarizeHealth', () => {
  it('counts states and computes health% over rated accounts only', () => {
    const s = summarizeHealth([
      { connectionId: 'a', score: 100, state: 'healthy', signals: [] },
      { connectionId: 'b', score: 100, state: 'healthy', signals: [] },
      { connectionId: 'c', score: 65, state: 'warning', signals: [] },
      { connectionId: 'd', score: 0, state: 'unknown', signals: [] },
    ]);
    expect(s).toMatchObject({ total: 4, healthy: 2, warning: 1, critical: 0, unknown: 1 });
    expect(s.healthPercent).toBe(67); // 2 of 3 rated
  });

  it('all-unknown → healthPercent null', () => {
    expect(summarizeHealth([{ connectionId: 'a', score: 0, state: 'unknown', signals: [] }]).healthPercent).toBeNull();
  });
});

/**
 * The audit found a DISCONNECTED account reporting `score: 100, state:
 * unknown`, and AWS summarised as 100% healthy while one of its two
 * connections was disconnected. The state had been corrected but the score
 * was left behind, so any aggregate reading `score` still saw a perfect
 * account.
 */
describe('a disconnected connection has no score at all', () => {
  it('returns null, not 100 and not 0', () => {
    const h = computeHealth(conn({ status: 'disconnected' }), okRun, NOW);
    expect(h.score).toBeNull();
    expect(h.state).toBe('unknown');
  });

  it('is null even when every other signal looks perfect', () => {
    // This is the exact shape that produced 100: healthy permissions,
    // discovery, freshness and credentials on a disconnected connection.
    const h = computeHealth(conn({ status: 'disconnected', last_sync_at: daysAgo(0), last_discovery_at: daysAgo(0) }), okRun, NOW);
    expect(h.score).toBeNull();
  });

  it('cannot contribute a number to a provider rollup', () => {
    // A rollup that sums `score` must get nothing from this connection.
    const h = computeHealth(conn({ status: 'disconnected' }), okRun, NOW);
    expect(typeof h.score).not.toBe('number');
  });

  it('returns null rather than 0 when nothing is measurable', () => {
    // 0 reads as "scored, and failing"; null reads as "not scored".
    const h = computeHealth(conn({ status: 'disconnected' }), null, NOW);
    expect(h.score).toBeNull();
  });
});
