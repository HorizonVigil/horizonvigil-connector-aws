import { describe, it, expect, vi } from 'vitest';
import { capabilityState, stateForCheck, buildCapabilityStatuses, writeCapabilityStatuses, CAPABILITY_PROBES, type CapabilityStatusRow } from './capabilityStatus';
import type { PermissionCheckResult } from './permissionChecks';
import type { Db } from '@horizonvigil/shared-lib';

/**
 * §6.2: health must be capability-specific, and "unknown, not configured and
 * unsupported do not earn points". One blended score per connection cannot
 * say "inventory is fine but Cost Explorer is denied" -- the only form of
 * this a customer can act on.
 */
const check = (service: string, status: PermissionCheckResult['status']): PermissionCheckResult =>
  ({ service, label: service, status, detail: '', verified: true });

describe('stateForCheck', () => {
  it('maps a granted probe to available', () => {
    expect(stateForCheck(check('iam', 'granted')).state).toBe('available');
  });

  it('distinguishes DENIED from NOT ENABLED', () => {
    // Only one of these is fixed by editing an IAM policy. Reporting an
    // unenabled service as denied sends someone to fix a correct policy.
    expect(stateForCheck(check('config', 'denied')).state).toBe('permission_denied');
    expect(stateForCheck(check('organizations', 'not_applicable')).state).toBe('not_enabled');
  });

  it('treats a never-run probe as not_configured, not as healthy', () => {
    expect(stateForCheck(undefined).state).toBe('not_configured');
    expect(stateForCheck(undefined).reasonCode).toBe('never_evaluated');
  });

  it('treats a probe error as failed rather than assuming the worst about permissions', () => {
    expect(stateForCheck(check('eks', 'error')).state).toBe('failed');
  });
});

describe('capabilityState', () => {
  it('is available when every probe passed', () => {
    expect(capabilityState('identity', [check('iam', 'granted')]).state).toBe('available');
  });

  it('is permission_denied when its probe was denied', () => {
    const r = capabilityState('billing_cost_explorer', [check('cost_explorer', 'denied')]);
    expect(r.state).toBe('permission_denied');
    expect(r.reasonCode).toBe('cost_explorer_denied');
  });

  it('is not_configured when the probe never ran — never silently available', () => {
    expect(capabilityState('metrics', []).state).toBe('not_configured');
  });

  it('is partial when a multi-probe capability is only half proven', () => {
    // recommendations needs both compute_optimizer and trusted_advisor.
    const r = capabilityState('recommendations', [check('compute_optimizer', 'granted'), check('trusted_advisor', 'denied')]);
    expect(r.state).toBe('partial');
    expect(r).toMatchObject({ covered: 1, expected: 2 });
  });

  it('requires ALL probes for a multi-probe capability', () => {
    const r = capabilityState('recommendations', [check('compute_optimizer', 'granted'), check('trusted_advisor', 'granted')]);
    expect(r.state).toBe('available');
  });

  it('preserves a shared reason when every probe failed the same way', () => {
    const r = capabilityState('recommendations', [check('compute_optimizer', 'denied'), check('trusted_advisor', 'denied')]);
    expect(r.state).toBe('permission_denied');
  });

  it('reports unsupported for a capability with no probe rather than guessing', () => {
    expect(capabilityState('made_up_capability', []).state).toBe('unsupported');
  });
});

describe('buildCapabilityStatuses', () => {
  const base = { orgId: 'org-1', connectionId: 'conn-1', snapshotId: 'run-1' };

  it('emits one row per declared capability', () => {
    const rows = buildCapabilityStatuses({ ...base, checks: [], connectionStatus: 'connected' });
    expect(rows).toHaveLength(Object.keys(CAPABILITY_PROBES).length);
  });

  it('marks EVERY capability disconnected when the connection is', () => {
    // Saying "available" for a disconnected connection's capabilities is the
    // same false-health claim the audit found at the connection level.
    const rows = buildCapabilityStatuses({
      ...base,
      checks: [check('sts', 'granted'), check('iam', 'granted')],
      connectionStatus: 'disconnected',
    });
    expect(rows.every((r) => r.state === 'disconnected')).toBe(true);
    expect(rows.every((r) => r.last_success_at === null)).toBe(true);
  });

  it('records last_success_at only for capabilities that are actually available', () => {
    const rows = buildCapabilityStatuses({
      ...base,
      checks: [check('sts', 'granted'), check('cost_explorer', 'denied')],
      connectionStatus: 'connected',
    });
    const inventory = rows.find((r) => r.capability === 'inventory')!;
    const billing = rows.find((r) => r.capability === 'billing_cost_explorer')!;
    expect(inventory.state).toBe('available');
    expect(inventory.last_success_at).not.toBeNull();
    expect(billing.state).toBe('permission_denied');
    expect(billing.last_success_at).toBeNull();
  });

  it('links every row back to the snapshot that produced it', () => {
    const rows = buildCapabilityStatuses({ ...base, checks: [], connectionStatus: 'connected' });
    expect(rows.every((r) => r.permission_snapshot_id === 'run-1')).toBe(true);
  });
});

/**
 * AWS-P2 — the last-success timestamp must survive a failure.
 *
 * `last_success_at` was written as `state === 'available' ? at : null` on an
 * UPSERT, so the previous value was destroyed on every run where a capability
 * was not currently available. Measured in production 2026-09-22: 9 AWS
 * capability rows carry a null last_success_at, including
 * `billing_cost_explorer` on a connection where Cost Explorer demonstrably
 * used to answer -- so nothing can now say whether it ever did.
 *
 * "Available now" and "last worked on the 15th" are different facts. The
 * second is what tells a customer whether a capability is newly broken or was
 * never configured, and it is the field staleness evaluation reads.
 */
describe('last_success_at durability', () => {
  const NOW = Date.parse('2026-09-22T10:00:00Z');
  const PREVIOUS = '2026-09-15T12:43:04.794Z';

  const build = (checks: PermissionCheckResult[], previousSuccessAt?: Record<string, string | null>) =>
    buildCapabilityStatuses(
      { orgId: 'org-1', connectionId: 'conn-1', checks, snapshotId: 'snap-1', connectionStatus: 'connected', previousSuccessAt },
      NOW,
    );

  const row = (rows: ReturnType<typeof build>, capability: string) =>
    rows.find((r) => r.capability === capability)!;

  const granted = (service: string, label = service): PermissionCheckResult =>
    ({ service, label, status: 'granted', detail: 'ok', verified: true });

  const errored = (service: string, label = service): PermissionCheckResult =>
    ({ service, label, status: 'error', detail: 'HTTP 500', verified: true });

  it('advances the timestamp when the capability is available', () => {
    const rows = build([granted('sts'), granted('iam')]);
    const identity = row(rows, 'identity');
    expect(identity.state).toBe('available');
    expect(identity.last_success_at).toBe(new Date(NOW).toISOString());
  });

  it('CARRIES FORWARD the previous success when the capability is not available', () => {
    const rows = build([errored('iam')], { identity: PREVIOUS });
    const identity = row(rows, 'identity');

    expect(identity.state).not.toBe('available');
    expect(identity.last_success_at, 'the previous success was erased').toBe(PREVIOUS);
  });

  it('still records the attempt even while carrying the old success forward', () => {
    // Otherwise "we tried and it is still broken" is indistinguishable from
    // "nobody has looked since the 15th".
    const rows = build([errored('iam')], { identity: PREVIOUS });
    expect(row(rows, 'identity').last_attempt_at).toBe(new Date(NOW).toISOString());
  });

  it('is null only when the capability has genuinely never succeeded', () => {
    const rows = build([errored('iam')], {});
    expect(row(rows, 'identity').last_success_at).toBeNull();
  });

  it('does not resurrect a success for a disconnected connection', () => {
    // A disconnected connection collects nothing, but its history is still
    // history -- the previous success is preserved, the state is not.
    const rows = buildCapabilityStatuses(
      { orgId: 'o', connectionId: 'c', checks: [], snapshotId: null, connectionStatus: 'disconnected', previousSuccessAt: { identity: PREVIOUS } },
      NOW,
    );
    const identity = row(rows, 'identity');
    expect(identity.state).toBe('disconnected');
    expect(identity.last_success_at).toBe(PREVIOUS);
  });

  it('is wired at the call site, not merely supported by the builder', async () => {
    // A parameter nothing passes is the same as no parameter.
    const { readFileSync } = await import('node:fs');
    const source = readFileSync('src/routes/permissions.ts', 'utf8');

    expect(source).toContain('previousSuccessAt');
    expect(source).toMatch(/select: 'capability,last_success_at'/);
  });
});

/**
 * The conflict target, and the class of bug it represents.
 *
 * `writeCapabilityStatuses` upserted with `resolution=merge-duplicates` and no
 * `on_conflict`. PostgREST resolves against the PRIMARY KEY unless told
 * otherwise; this table's primary key is a surrogate `id`, while the
 * uniqueness that matters lives in a separate index on
 * `(connection_id, capability)`. So every row got a fresh id, found no
 * primary-key conflict, and was attempted as an INSERT that violated the
 * unique index.
 *
 * The catch turned that into one console line, so the table froze on
 * 2026-09-09 / 2026-09-15 and every capability state a customer saw was days
 * stale. Measured 2026-09-22: a validation finished at 18:50:47 and the logs
 * show `[capability-status] write failed` at 18:50:47.666 for both
 * connections.
 */
describe('writeCapabilityStatuses targets the right conflict', () => {
  const row = (capability: string): CapabilityStatusRow => ({
    org_id: 'org-1',
    connection_id: 'conn-1',
    capability,
    state: 'available',
    reason_code: null,
    source: 'permission_validation',
    expected_scope: 1,
    covered_scope: 1,
    last_attempt_at: '2026-09-22T18:50:47.000Z',
    last_success_at: '2026-09-22T18:50:47.000Z',
    permission_snapshot_id: null,
    updated_at: '2026-09-22T18:50:47.000Z',
  });

  function recordingDb() {
    const calls: { table: string; prefer?: string }[] = [];
    const db = {
      insert: async (table: string, _rows: unknown, prefer?: string) => {
        calls.push({ table, prefer });
        return [];
      },
    } as unknown as Db;
    return { db, calls };
  }

  it('names (connection_id, capability) as the conflict target', async () => {
    const { db, calls } = recordingDb();

    await writeCapabilityStatuses(db, [row('inventory')]);

    expect(calls[0].table).toContain('on_conflict=connection_id,capability');
  });

  it('still asks PostgREST to merge rather than insert', async () => {
    const { db, calls } = recordingDb();

    await writeCapabilityStatuses(db, [row('inventory')]);

    expect(calls[0].prefer).toContain('merge-duplicates');
  });

  it('writes nothing at all for an empty set', async () => {
    const { db, calls } = recordingDb();
    await writeCapabilityStatuses(db, []);
    expect(calls).toEqual([]);
  });

  /**
   * Still non-fatal: a telemetry row must never take down the validation that
   * produced it. But the line must say how much was lost, so a silent freeze
   * is at least countable.
   */
  it('a failed write does not fail the validation, and says how much was lost', async () => {
    const errors: string[] = [];
    const spy = vi.spyOn(console, 'error').mockImplementation((...args) => { errors.push(args.join(' ')); });
    const db = { insert: async () => { throw new Error('duplicate key value'); } } as unknown as Db;

    await expect(writeCapabilityStatuses(db, [row('inventory'), row('metrics')])).resolves.toBeUndefined();
    expect(errors.join(' ')).toMatch(/2 row\(s\)/);

    spy.mockRestore();
  });
});
