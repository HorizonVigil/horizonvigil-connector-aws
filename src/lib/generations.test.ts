import { describe, it, expect } from 'vitest';
import {
  resolveGeneration,
  regionsEstablishingAbsence,
  inventoryCompleteness,
  type ExistingGeneration,
} from './generations';

const gen = (over: Partial<ExistingGeneration> = {}): ExistingGeneration => ({
  id: 'row-1',
  generation: 1,
  lifecycle_state: 'ACTIVE',
  immutable_identity: null,
  ...over,
});

describe('resolveGeneration — Phase 4 §2/§13/§14', () => {
  it('first sighting opens generation 1', () => {
    const d = resolveGeneration([]);
    expect(d.generation).toBe(1);
    expect(d.reason).toBe('first_sighting');
    expect(d.continuesRowId).toBeNull();
  });

  it('a live resource seen again stays in its generation', () => {
    const d = resolveGeneration([gen({ id: 'row-a' })]);
    expect(d.generation).toBe(1);
    expect(d.continuesRowId).toBe('row-a');
    expect(d.reason).toBe('continues_live_generation');
  });

  // §13: a rename must not fork identity. The name is not the identity, and
  // this function never sees the name -- which is the structural guarantee.
  it('a renamed resource does not open a new generation', () => {
    const d = resolveGeneration([gen({ id: 'row-a', lifecycle_state: 'ACTIVE' })]);
    expect(d.generation).toBe(1);
    expect(d.continuesRowId).toBe('row-a');
  });

  it('INACTIVE is not DELETED and does not open a generation', () => {
    const d = resolveGeneration([gen({ lifecycle_state: 'INACTIVE' })]);
    expect(d.generation).toBe(1);
    expect(d.reason).toBe('continues_live_generation');
  });

  // The headline case, and hard NO-GO condition 4.
  it('a reused native id after deletion opens a NEW generation', () => {
    const d = resolveGeneration([gen({ id: 'row-a', lifecycle_state: 'DELETED' })]);
    expect(d.generation).toBe(2);
    expect(d.reason).toBe('new_generation_after_delete');
    // Critically: it must NOT reuse the deleted row, or the new resource
    // inherits its cost facts, metrics and findings.
    expect(d.continuesRowId).toBeNull();
  });

  it('generations keep incrementing across repeated delete/recreate cycles', () => {
    const history = [
      gen({ id: 'row-a', generation: 1, lifecycle_state: 'DELETED' }),
      gen({ id: 'row-b', generation: 2, lifecycle_state: 'DELETED' }),
    ];
    expect(resolveGeneration(history).generation).toBe(3);
  });

  it('picks the latest generation regardless of array order', () => {
    const history = [
      gen({ id: 'row-b', generation: 2, lifecycle_state: 'DELETED' }),
      gen({ id: 'row-a', generation: 1, lifecycle_state: 'DELETED' }),
    ];
    expect(resolveGeneration(history).generation).toBe(3);
  });

  it('continuity IS accepted when a matching immutable identity proves it', () => {
    const d = resolveGeneration(
      [gen({ id: 'row-a', lifecycle_state: 'DELETED', immutable_identity: 'db-ABCDEF123' })],
      'db-ABCDEF123',
    );
    expect(d.generation).toBe(1);
    expect(d.continuesRowId).toBe('row-a');
    expect(d.reason).toBe('continuity_proven_by_immutable_identity');
  });

  it('a DIFFERENT immutable identity opens a new generation', () => {
    const d = resolveGeneration(
      [gen({ lifecycle_state: 'DELETED', immutable_identity: 'db-OLD' })],
      'db-NEW',
    );
    expect(d.generation).toBe(2);
  });

  // Two absences of evidence are not a match. If null === null were treated
  // as proof of continuity, every resource type that supplies no immutable
  // id -- which is most of them -- would silently merge histories again, and
  // the mechanism would be decorative.
  it('two NULL immutable identities are NOT treated as a match', () => {
    const d = resolveGeneration([gen({ lifecycle_state: 'DELETED', immutable_identity: null })], null);
    expect(d.generation).toBe(2);
    expect(d.reason).toBe('new_generation_after_delete');
  });

  it('an observed identity against a stored NULL does not prove continuity', () => {
    const d = resolveGeneration([gen({ lifecycle_state: 'DELETED', immutable_identity: null })], 'db-NEW');
    expect(d.generation).toBe(2);
  });
});

describe('regionsEstablishingAbsence — Phase 4 §9', () => {
  it('only regions evaluated WITHOUT failure can establish absence', () => {
    const s = regionsEstablishingAbsence({
      requested: ['us-east-1', 'eu-west-1', 'ap-south-1'],
      evaluated: ['us-east-1', 'eu-west-1'],
      failed: ['eu-west-1'],
    });
    expect([...s]).toEqual(['us-east-1']);
  });

  // The exact §9 invariant: region B failed, so a resource last seen in
  // region B must not be tombstoned.
  it('a failed region never establishes absence', () => {
    const s = regionsEstablishingAbsence({
      requested: ['us-east-1', 'eu-west-1'],
      evaluated: ['us-east-1', 'eu-west-1'],
      failed: ['eu-west-1'],
    });
    expect(s.has('eu-west-1')).toBe(false);
  });

  it('a requested region that was never attempted establishes nothing', () => {
    const s = regionsEstablishingAbsence({
      requested: ['us-east-1', 'ap-south-1'],
      evaluated: ['us-east-1'],
      failed: [],
    });
    expect(s.has('ap-south-1')).toBe(false);
  });

  it('a clean full scan establishes absence everywhere it looked', () => {
    const s = regionsEstablishingAbsence({
      requested: ['us-east-1', 'eu-west-1'],
      evaluated: ['us-east-1', 'eu-west-1'],
      failed: [],
    });
    expect([...s].sort()).toEqual(['eu-west-1', 'us-east-1']);
  });
});

describe('inventoryCompleteness — Phase 4 §9/§46', () => {
  it('COMPLETE only when every requested region was evaluated and none failed', () => {
    expect(
      inventoryCompleteness({
        requested: ['us-east-1', 'eu-west-1'],
        evaluated: ['us-east-1', 'eu-west-1'],
        failed: [],
      }),
    ).toBe('COMPLETE');
  });

  it('any failure makes it PARTIAL', () => {
    expect(
      inventoryCompleteness({
        requested: ['us-east-1', 'eu-west-1'],
        evaluated: ['us-east-1', 'eu-west-1'],
        failed: ['eu-west-1'],
      }),
    ).toBe('PARTIAL');
  });

  it('an unattempted region makes it PARTIAL even with zero failures', () => {
    expect(
      inventoryCompleteness({
        requested: ['us-east-1', 'eu-west-1'],
        evaluated: ['us-east-1'],
        failed: [],
      }),
    ).toBe('PARTIAL');
  });

  it('an empty requested scope is not silently COMPLETE by vacuous truth alone', () => {
    // every() on an empty array is true, so this documents the deliberate
    // outcome rather than leaving it to be discovered later: nothing was
    // asked for, nothing failed, so there is nothing partial about it.
    expect(inventoryCompleteness({ requested: [], evaluated: [], failed: [] })).toBe('COMPLETE');
  });
});
