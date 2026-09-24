/**
 * AWS-11 — inventory reconciliation.
 *
 * Answers one question: **does what AWS says exists match what HorizonVigil
 * believes exists?**
 *
 * WHY THIS IS NOT THE SAME AS DISCOVERY
 *
 * Discovery upserts what it finds. If discovery were perfect, reconciliation
 * would always report zero drift — and that is exactly why it is worth
 * running. Drift is not an expected outcome to be tolerated; it is a signal
 * that discovery, admission, generation resolution or tombstoning has a bug.
 * A reconciliation that quietly "fixes" differences would hide the defect it
 * exists to surface, so this classifies and reports rather than repairs.
 *
 * WHAT IT DELIBERATELY DOES NOT DO
 *
 * It does not delete. Absence from one comparison is not proof a resource is
 * gone — that is the same asymmetry AWS-12 enforces for tombstoning, and the
 * cost of being wrong is identical: a stale row is corrected next cycle, a
 * wrongly deleted one destroys history and cost attribution.
 */

/** A resource as AWS reported it during this collection. */
export interface ObservedResource {
  resourceTypeKey: string;
  /** AWS-native id. Never a display name. */
  resourceId: string;
  region: string | null;
  accountId: string | null;
  /** Fingerprint of the configuration AWS returned, when the scanner supplies one. */
  configurationHash?: string | null;
}

/** A resource as HorizonVigil currently stores it. */
export interface PersistedResource {
  id: string;
  resourceTypeKey: string;
  resourceId: string;
  region: string | null;
  accountId: string | null;
  configurationHash?: string | null;
  lifecycleState: string;
  generation: number;
}

export type DriftKind =
  /** AWS has it; we do not. Discovery missed it or admission rejected it. */
  | 'MISSING_LOCAL'
  /** We have it ACTIVE; AWS did not return it in an evaluated scope. */
  | 'STALE_LOCAL'
  /** Both have it, but the configuration fingerprint differs. */
  | 'CHANGED'
  /** More than one ACTIVE local row for one native identity. */
  | 'DUPLICATE_LOCAL'
  /** Same identity, different region in AWS than we stored. */
  | 'REGION_MISMATCH'
  /** Same identity, different owning account. */
  | 'ACCOUNT_MISMATCH';

export interface Drift {
  kind: DriftKind;
  resourceTypeKey: string;
  resourceId: string;
  detail: string;
}

export interface ReconciliationResult {
  discovered: number;
  persisted: number;
  matched: number;
  drift: Drift[];
  countsByKind: Record<DriftKind, number>;
  /**
   * PASSED only when no drift at all. There is no tolerance band here, unlike
   * cost: an inventory difference is a discrete fact about a resource, not a
   * rounding artifact, so "close enough" has no meaning.
   */
  status: 'PASSED' | 'FAILED';
}

/** Identity key. Type + native id — never the display name. */
const identity = (r: { resourceTypeKey: string; resourceId: string }) => `${r.resourceTypeKey}:${r.resourceId}`;

/**
 * Compares one evaluated scope.
 *
 * `evaluatedScopes` is required and load-bearing. A resource whose region was
 * NOT evaluated this run cannot be called stale — AWS was never asked about
 * it. Passing an empty set therefore yields no STALE_LOCAL at all, which is
 * correct rather than a degenerate case: nothing was evaluated, so nothing
 * can be proven absent.
 */
export function reconcileInventory(
  observed: readonly ObservedResource[],
  persisted: readonly PersistedResource[],
  evaluatedScopes: ReadonlySet<string>,
): ReconciliationResult {
  const drift: Drift[] = [];

  const observedByIdentity = new Map<string, ObservedResource>();
  for (const o of observed) observedByIdentity.set(identity(o), o);

  // Only ACTIVE rows participate. A DELETED generation is history, and
  // comparing it against a live AWS response would report every correctly
  // tombstoned resource as missing.
  const activePersisted = persisted.filter((p) => p.lifecycleState === 'ACTIVE');

  const persistedByIdentity = new Map<string, PersistedResource[]>();
  for (const p of activePersisted) {
    const k = identity(p);
    persistedByIdentity.set(k, [...(persistedByIdentity.get(k) ?? []), p]);
  }

  let matched = 0;

  for (const [key, o] of observedByIdentity) {
    const rows = persistedByIdentity.get(key) ?? [];

    if (rows.length === 0) {
      drift.push({
        kind: 'MISSING_LOCAL', resourceTypeKey: o.resourceTypeKey, resourceId: o.resourceId,
        detail: `AWS returned it in ${o.region ?? 'global'}; no ACTIVE local row exists`,
      });
      continue;
    }

    if (rows.length > 1) {
      drift.push({
        kind: 'DUPLICATE_LOCAL', resourceTypeKey: o.resourceTypeKey, resourceId: o.resourceId,
        detail: `${rows.length} ACTIVE local rows share this identity (generations ${rows.map((r) => r.generation).join(', ')})`,
      });
      // Still compared below against the first row, so a duplicate does not
      // also mask a region or configuration difference.
    }

    const p = rows[0];
    let differed = false;

    if ((o.region ?? null) !== (p.region ?? null)) {
      drift.push({
        kind: 'REGION_MISMATCH', resourceTypeKey: o.resourceTypeKey, resourceId: o.resourceId,
        detail: `AWS says ${o.region ?? 'global'}, stored as ${p.region ?? 'global'}`,
      });
      differed = true;
    }

    if (o.accountId && p.accountId && o.accountId !== p.accountId) {
      drift.push({
        kind: 'ACCOUNT_MISMATCH', resourceTypeKey: o.resourceTypeKey, resourceId: o.resourceId,
        detail: `AWS says account ${o.accountId}, stored under ${p.accountId}`,
      });
      differed = true;
    }

    // Only compared when BOTH sides carry a hash. A scanner that supplies no
    // fingerprint must not make every one of its resources look changed.
    if (o.configurationHash && p.configurationHash && o.configurationHash !== p.configurationHash) {
      drift.push({
        kind: 'CHANGED', resourceTypeKey: o.resourceTypeKey, resourceId: o.resourceId,
        detail: 'configuration fingerprint differs from the stored value',
      });
      differed = true;
    }

    if (!differed && rows.length === 1) matched++;
  }

  for (const p of activePersisted) {
    const key = identity(p);
    if (observedByIdentity.has(key)) continue;

    // The AWS-12 rule again: absence only counts inside a scope that was
    // actually evaluated.
    const scope = p.region && p.region.trim() !== '' ? p.region : '__global__';
    if (!evaluatedScopes.has(scope)) continue;

    drift.push({
      kind: 'STALE_LOCAL', resourceTypeKey: p.resourceTypeKey, resourceId: p.resourceId,
      detail: `stored ACTIVE in ${p.region ?? 'global'}, which was evaluated, but AWS did not return it`,
    });
  }

  const countsByKind = {
    MISSING_LOCAL: 0, STALE_LOCAL: 0, CHANGED: 0,
    DUPLICATE_LOCAL: 0, REGION_MISMATCH: 0, ACCOUNT_MISMATCH: 0,
  } as Record<DriftKind, number>;
  for (const d of drift) countsByKind[d.kind]++;

  return {
    discovered: observed.length,
    persisted: activePersisted.length,
    matched,
    drift,
    countsByKind,
    status: drift.length === 0 ? 'PASSED' : 'FAILED',
  };
}
