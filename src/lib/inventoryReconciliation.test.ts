import { describe, it, expect } from 'vitest';
import { reconcileInventory, type ObservedResource, type PersistedResource } from './inventoryReconciliation';

const obs = (id: string, over: Partial<ObservedResource> = {}): ObservedResource =>
  ({ resourceTypeKey: 'ec2_instance', resourceId: id, region: 'us-east-1', accountId: '111111111111', ...over });

const per = (id: string, over: Partial<PersistedResource> = {}): PersistedResource =>
  ({ id: `row-${id}`, resourceTypeKey: 'ec2_instance', resourceId: id, region: 'us-east-1',
     accountId: '111111111111', lifecycleState: 'ACTIVE', generation: 1, ...over });

const SCOPES = new Set(['us-east-1', '__global__']);

describe('reconcileInventory — AWS-11', () => {
  it('a matching inventory reconciles clean', () => {
    const r = reconcileInventory([obs('i-1'), obs('i-2')], [per('i-1'), per('i-2')], SCOPES);
    expect(r.status).toBe('PASSED');
    expect(r.drift).toEqual([]);
    expect(r.matched).toBe(2);
  });

  it('detects a resource AWS has that we do not', () => {
    const r = reconcileInventory([obs('i-1'), obs('i-new')], [per('i-1')], SCOPES);
    expect(r.countsByKind.MISSING_LOCAL).toBe(1);
    expect(r.drift[0].resourceId).toBe('i-new');
    expect(r.status).toBe('FAILED');
  });

  it('detects a resource we hold ACTIVE that AWS did not return', () => {
    const r = reconcileInventory([obs('i-1')], [per('i-1'), per('i-gone')], SCOPES);
    expect(r.countsByKind.STALE_LOCAL).toBe(1);
  });

  /**
   * The load-bearing rule, and the same asymmetry AWS-12 enforces: absence
   * only counts inside a scope that was actually evaluated. A resource in a
   * region AWS was never asked about is not stale.
   */
  it('never calls a resource stale when its scope was not evaluated', () => {
    const r = reconcileInventory(
      [obs('i-1')],
      [per('i-1'), per('i-eu', { region: 'eu-west-1' })],
      new Set(['us-east-1']),
    );
    expect(r.countsByKind.STALE_LOCAL).toBe(0);
  });

  it('an empty evaluated scope set proves nothing absent', () => {
    const r = reconcileInventory([], [per('i-1'), per('i-2')], new Set());
    expect(r.countsByKind.STALE_LOCAL).toBe(0);
    expect(r.status).toBe('PASSED');
  });

  it('detects a changed configuration fingerprint', () => {
    const r = reconcileInventory(
      [obs('i-1', { configurationHash: 'aaa' })],
      [per('i-1', { configurationHash: 'bbb' })],
      SCOPES,
    );
    expect(r.countsByKind.CHANGED).toBe(1);
  });

  /**
   * A scanner that supplies no fingerprint must not make every one of its
   * resources look changed.
   */
  it('does not report CHANGED when either side has no fingerprint', () => {
    expect(reconcileInventory([obs('i-1')], [per('i-1', { configurationHash: 'bbb' })], SCOPES)
      .countsByKind.CHANGED).toBe(0);
    expect(reconcileInventory([obs('i-1', { configurationHash: 'aaa' })], [per('i-1')], SCOPES)
      .countsByKind.CHANGED).toBe(0);
  });

  it('detects duplicate ACTIVE rows for one identity', () => {
    const r = reconcileInventory([obs('i-1')], [per('i-1'), per('i-1', { id: 'row-dup', generation: 2 })], SCOPES);
    expect(r.countsByKind.DUPLICATE_LOCAL).toBe(1);
  });

  /** A duplicate must not mask a second, different problem on the same row. */
  it('reports a region mismatch even when the identity is also duplicated', () => {
    const r = reconcileInventory(
      [obs('i-1', { region: 'eu-west-1' })],
      [per('i-1'), per('i-1', { id: 'row-dup', generation: 2 })],
      new Set(['us-east-1', 'eu-west-1', '__global__']),
    );
    expect(r.countsByKind.DUPLICATE_LOCAL).toBe(1);
    expect(r.countsByKind.REGION_MISMATCH).toBe(1);
  });

  it('detects region and account mismatches', () => {
    expect(reconcileInventory([obs('i-1', { region: 'eu-west-1' })], [per('i-1')], SCOPES)
      .countsByKind.REGION_MISMATCH).toBe(1);
    expect(reconcileInventory([obs('i-1', { accountId: '999999999999' })], [per('i-1')], SCOPES)
      .countsByKind.ACCOUNT_MISMATCH).toBe(1);
  });

  /**
   * A DELETED generation is history. Comparing it against a live AWS
   * response would report every correctly tombstoned resource as missing.
   */
  it('ignores non-ACTIVE generations entirely', () => {
    const r = reconcileInventory([], [per('i-old', { lifecycleState: 'DELETED' })], SCOPES);
    expect(r.status).toBe('PASSED');
    expect(r.persisted).toBe(0);
  });

  it('matches on native id and type, not display name', () => {
    const r = reconcileInventory(
      [obs('i-1', { resourceTypeKey: 'ebs_volume' })],
      [per('i-1', { resourceTypeKey: 'ec2_instance' })],
      SCOPES,
    );
    // Same native string, different type: not the same resource.
    expect(r.countsByKind.MISSING_LOCAL).toBe(1);
    expect(r.countsByKind.STALE_LOCAL).toBe(1);
  });

  it('is idempotent — the same inputs give the same result', () => {
    const a = reconcileInventory([obs('i-1'), obs('i-2')], [per('i-1')], SCOPES);
    const b = reconcileInventory([obs('i-1'), obs('i-2')], [per('i-1')], SCOPES);
    expect(a).toEqual(b);
  });

  it('handles both sides empty', () => {
    const r = reconcileInventory([], [], SCOPES);
    expect(r.status).toBe('PASSED');
    expect(r.discovered).toBe(0);
    expect(r.persisted).toBe(0);
  });

  /**
   * No tolerance band, unlike cost. An inventory difference is a discrete
   * fact about a resource, not a rounding artifact, so "close enough" has no
   * meaning here.
   */
  it('fails on a single drift — there is no tolerance', () => {
    expect(reconcileInventory([obs('i-1'), obs('i-2')], [per('i-1')], SCOPES).status).toBe('FAILED');
  });
});
