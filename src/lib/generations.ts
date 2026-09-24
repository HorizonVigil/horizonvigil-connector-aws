/**
 * Phase 4 §2/§13/§14 — resource generations.
 *
 * A provider-native id is not permanently stable. AWS reuses them: an EC2
 * instance id, an EBS volume id or a security-group id can be released and
 * handed to something else entirely. The pre-existing unique constraint on
 * (connection_id, resource_type_key, resource_id) meant the recreated
 * resource upserted straight into the deleted one's row -- inheriting its
 * first_seen_at, its lifecycle events, and every cost fact, metric and
 * security finding that pointed at that row id.
 *
 * That is hard NO-GO condition 4 ("delete/recreate incorrectly shares one
 * generation") and 12 ("security findings migrate to a recreated resource
 * without evidence"). It is also silent: nothing errors, and the UI shows one
 * resource with a continuous history that never happened.
 *
 * The rule here is deliberately asymmetric. Opening a new generation when the
 * resource was really the same one costs a split history that a human can see
 * and reconcile. Merging two different resources into one generation produces
 * a confident, wrong history that nobody can see. So continuity must be
 * PROVEN; it is never assumed.
 */

/** Lifecycle vocabulary, matching cloud_resources.lifecycle_state. */
export type LifecycleState = 'ACTIVE' | 'INACTIVE' | 'DELETED' | 'UNKNOWN';

export interface ExistingGeneration {
  id: string;
  generation: number;
  lifecycle_state: LifecycleState;
  /**
   * An identifier the provider guarantees is unique for the lifetime of the
   * underlying resource and is NOT reused -- an RDS `DbiResourceId`
   * (db-ABCDEF…), an EC2 volume's snapshot lineage, a Lambda version ARN.
   *
   * Null for the majority of resource types, and null is not a weakness: it
   * is the accurate statement that this type gives us nothing that can prove
   * continuity across a deletion.
   */
  immutable_identity: string | null;
}

export interface GenerationDecision {
  generation: number;
  lifecycle_state: LifecycleState;
  /** The row to upsert into, when continuing an existing generation. */
  continuesRowId: string | null;
  reason:
    | 'first_sighting'
    | 'continues_live_generation'
    | 'new_generation_after_delete'
    | 'continuity_proven_by_immutable_identity';
}

/**
 * Decides which generation an observed resource belongs to.
 *
 * `observedImmutableIdentity` is the caller's evidence of continuity. Pass it
 * only when the provider actually supplied an identifier it guarantees is
 * never reused. Passing the native id here would defeat the entire mechanism,
 * because the native id being reused is the case this exists to catch.
 */
export function resolveGeneration(
  existing: readonly ExistingGeneration[],
  observedImmutableIdentity: string | null = null,
): GenerationDecision {
  if (existing.length === 0) {
    return {
      generation: 1,
      lifecycle_state: 'ACTIVE',
      continuesRowId: null,
      reason: 'first_sighting',
    };
  }

  const latest = [...existing].sort((a, b) => b.generation - a.generation)[0];

  // The common case by a wide margin: the resource is simply still there.
  // A changed display name does NOT open a generation (§13) -- identity is
  // what matters, and the name is not identity.
  if (latest.lifecycle_state !== 'DELETED') {
    return {
      generation: latest.generation,
      lifecycle_state: 'ACTIVE',
      continuesRowId: latest.id,
      reason: 'continues_live_generation',
    };
  }

  // The latest generation was proven deleted and the native id is back.
  //
  // Continuity is only accepted against a non-empty immutable identity that
  // matches. Two nulls matching is not evidence of anything -- it is two
  // absences of evidence -- and treating it as a match would reopen exactly
  // the hole this module closes for every resource type that supplies no
  // immutable id, which is most of them.
  if (
    observedImmutableIdentity !== null &&
    latest.immutable_identity !== null &&
    observedImmutableIdentity === latest.immutable_identity
  ) {
    return {
      generation: latest.generation,
      lifecycle_state: 'ACTIVE',
      continuesRowId: latest.id,
      reason: 'continuity_proven_by_immutable_identity',
    };
  }

  return {
    generation: latest.generation + 1,
    lifecycle_state: 'ACTIVE',
    continuesRowId: null,
    reason: 'new_generation_after_delete',
  };
}

/**
 * §9 partial-scan safety, at region granularity.
 *
 * The existing finalize logic (discoveryFinalize.ts) already refuses to
 * tombstone a resource type whose scanner reported any failure this run. That
 * closes the type-level hole but not the region-level one: a run that scanned
 * fifteen regions successfully and failed two would still mark every resource
 * in the two failed regions as vanished, because the resource TYPE was
 * covered somewhere.
 *
 * Absence can only be established inside a scope that was actually evaluated.
 * A region that failed, was never attempted, or is not in the requested scope
 * proves nothing at all about what lives there.
 */
export interface RegionCoverage {
  requested: readonly string[];
  evaluated: readonly string[];
  failed: readonly string[];
}

export function regionsEstablishingAbsence(coverage: RegionCoverage): Set<string> {
  const failed = new Set(coverage.failed);
  // Evaluated minus failed. Requested-but-never-attempted regions are absent
  // from `evaluated` and so are excluded without needing a separate rule.
  return new Set(coverage.evaluated.filter((r) => !failed.has(r)));
}

/**
 * Whether the inventory produced by a run may be described as complete.
 *
 * Complete means every requested region was evaluated and none failed.
 * Anything else is PARTIAL, and §46 forbids presenting a partial inventory's
 * count as the account's total.
 */
export function inventoryCompleteness(coverage: RegionCoverage): 'COMPLETE' | 'PARTIAL' {
  if (coverage.failed.length > 0) return 'PARTIAL';
  const evaluated = new Set(coverage.evaluated);
  return coverage.requested.every((r) => evaluated.has(r)) ? 'COMPLETE' : 'PARTIAL';
}
