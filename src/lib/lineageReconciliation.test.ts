import { describe, it, expect } from 'vitest';
import { reconcileLineage, toReconciliationRow, MAX_DRIFT_SAMPLE, type BatchAccounting } from './lineageReconciliation';

const batch = (over: Partial<BatchAccounting> = {}): BatchAccounting => ({
  collector: 'ec2', observedCount: 10, acceptedCount: 10, quarantinedCount: 0, rejectedCount: 0, ...over,
});

describe('reconcileLineage', () => {
  it('passes when every accepted record became a live row', () => {
    const r = reconcileLineage([batch({ observedCount: 100, acceptedCount: 100 })], [{ resourceTypeKey: 'ec2_instance', liveRows: 100 }]);
    expect(r.status).toBe('PASSED');
    expect(r.drift).toEqual([]);
    expect(r.accepted).toBe(100);
    expect(r.persisted).toBe(100);
  });

  /**
   * The failure this module exists to catch, and the one nothing else in the
   * system can see: tombstoning cannot (the rows were never written), the
   * truncation guard cannot (the read succeeded), scan health cannot (every
   * step succeeded). The estate simply comes back smaller.
   */
  it('detects records that admission accepted and storage never received', () => {
    const r = reconcileLineage([batch({ observedCount: 100, acceptedCount: 100 })], [{ resourceTypeKey: 'ec2_instance', liveRows: 87 }]);
    expect(r.status).toBe('FAILED');
    const d = r.drift.find((x) => x.kind === 'ACCEPTED_NOT_PERSISTED')!;
    expect(d.count).toBe(13);
    expect(d.detail).toContain('accepted 100');
  });

  /**
   * More rows than this run accepted is NOT drift. The estate legitimately
   * carries resources from earlier runs that this one did not re-observe, and
   * flagging that would fail every incremental scan.
   */
  it('does not treat pre-existing rows as drift', () => {
    const r = reconcileLineage([batch({ observedCount: 5, acceptedCount: 5 })], [{ resourceTypeKey: 'ec2_instance', liveRows: 900 }]);
    expect(r.status).toBe('PASSED');
  });

  it('quarantined records are accounted for, not drift', () => {
    const r = reconcileLineage(
      [batch({ observedCount: 10, acceptedCount: 8, quarantinedCount: 2 })],
      [{ resourceTypeKey: 'ec2_instance', liveRows: 8 }],
    );
    expect(r.status).toBe('PASSED');
    expect(r.quarantined).toBe(2);
  });

  it('detects accounting that does not balance', () => {
    const r = reconcileLineage(
      [batch({ observedCount: 10, acceptedCount: 3, quarantinedCount: 1, rejectedCount: 0 })],
      [{ resourceTypeKey: 'ec2_instance', liveRows: 3 }],
    );
    const d = r.drift.find((x) => x.kind === 'UNBALANCED_BATCH')!;
    expect(d.count).toBe(6);
    expect(r.status).toBe('FAILED');
  });

  /**
   * Refusal before admission means no typed reason was ever assigned, so the
   * record cannot be explained to a customer. Reported separately from
   * quarantine, which always carries a reason.
   */
  it('reports pre-admission refusals separately from quarantine', () => {
    const r = reconcileLineage(
      [batch({ observedCount: 10, acceptedCount: 7, quarantinedCount: 0, rejectedCount: 3 })],
      [{ resourceTypeKey: 'ec2_instance', liveRows: 7 }],
    );
    expect(r.drift.some((d) => d.kind === 'REJECTED_BEFORE_ADMISSION')).toBe(true);
    expect(r.drift.some((d) => d.kind === 'UNBALANCED_BATCH')).toBe(false);
  });

  /**
   * A run that ingested nothing has not demonstrated that storage is sound —
   * it has demonstrated nothing. Passing it would be the false-clean pattern.
   */
  it('a run with no batches is not PASSED', () => {
    const r = reconcileLineage([], [{ resourceTypeKey: 'ec2_instance', liveRows: 5 }]);
    expect(r.status).toBe('FAILED');
    expect(r.reasonCode).toBe('no_batches');
    expect(r.drift).toEqual([]);
  });

  it('sums across collectors', () => {
    const r = reconcileLineage(
      [batch({ collector: 'ec2', observedCount: 10, acceptedCount: 10 }), batch({ collector: 'iam', observedCount: 5, acceptedCount: 5 })],
      [{ resourceTypeKey: 'a', liveRows: 15 }],
    );
    expect(r.observed).toBe(15);
    expect(r.accepted).toBe(15);
    expect(r.status).toBe('PASSED');
  });

  it('is idempotent', () => {
    const b = [batch()]; const p = [{ resourceTypeKey: 'x', liveRows: 10 }];
    expect(reconcileLineage(b, p)).toEqual(reconcileLineage(b, p));
  });
});

describe('toReconciliationRow', () => {
  const ctx = { orgId: 'o', connectionId: 'c', collectionRunId: 'r', accountId: '111111111111', evaluatedScopes: ['us-east-1'] };

  it('maps a clean result to a PASSED row', () => {
    const row = toReconciliationRow(
      reconcileLineage([batch({ observedCount: 10, acceptedCount: 10 })], [{ resourceTypeKey: 'x', liveRows: 10 }]),
      ctx,
    );
    expect(row.status).toBe('PASSED');
    expect(row.discovered_count).toBe(10);
    expect(row.persisted_count).toBe(10);
    expect(row.missing_local_count).toBe(0);
  });

  it('carries the write-loss count into missing_local_count', () => {
    const row = toReconciliationRow(
      reconcileLineage([batch({ observedCount: 100, acceptedCount: 100 })], [{ resourceTypeKey: 'x', liveRows: 87 }]),
      ctx,
    );
    expect(row.missing_local_count).toBe(13);
    expect(row.status).toBe('FAILED');
  });

  /** The status column defaults to BLOCKED, so a stored row must set it explicitly. */
  it('always sets a status the CHECK constraint permits', () => {
    for (const row of [
      toReconciliationRow(reconcileLineage([], []), ctx),
      toReconciliationRow(reconcileLineage([batch()], [{ resourceTypeKey: 'x', liveRows: 10 }]), ctx),
    ]) {
      expect(['PASSED', 'FAILED', 'BLOCKED']).toContain(row.status);
    }
  });

  it('bounds the stored sample while keeping counts authoritative', () => {
    const many = Array.from({ length: 40 }, (_, i) => batch({ collector: `c${i}`, observedCount: 10, acceptedCount: 1 }));
    const row = toReconciliationRow(reconcileLineage(many, [{ resourceTypeKey: 'x', liveRows: 40 }]), ctx);
    expect((row.drift_sample as unknown[]).length).toBe(MAX_DRIFT_SAMPLE);
    expect(row.discovered_count).toBe(400);
  });

  it('carries the evaluated scopes, without which a result is uninterpretable', () => {
    const row = toReconciliationRow(reconcileLineage([batch()], [{ resourceTypeKey: 'x', liveRows: 10 }]), ctx);
    expect(row.evaluated_scopes).toEqual(['us-east-1']);
    expect(row.collection_run_id).toBe('r');
  });
});
