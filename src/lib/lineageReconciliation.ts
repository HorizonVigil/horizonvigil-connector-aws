/**
 * AWS-11 — reconciling what was collected against what was stored.
 *
 * `inventory_reconciliations` has existed, empty, since it was created:
 * `reconcileInventory()` is pure, tested, and nothing ever called it. The
 * reason is that its inputs are hard to obtain honestly. Comparing the rows a
 * run wrote against the rows a run wrote is a tautology, and re-reading the
 * whole estate from AWS purely to compare costs a second full scan.
 *
 * THE COMPARISON THAT IS BOTH CHEAP AND REAL
 *
 * Every collection step already records an `ingestion_batches` row:
 *
 *   observed_count     records the scanner produced
 *   accepted_count     records admission admitted
 *   quarantined_count  records admission rejected, with a typed reason
 *   rejected_count     records refused before admission
 *
 * That accounting is checked internally — observed must equal the sum of the
 * other three, and a constraint enforces it. What NOTHING checked is the next
 * hop: whether the records admission ACCEPTED actually became rows in
 * `cloud_resources`.
 *
 * That hop is where a silent write loss would live, and it is invisible to
 * every other control in the system. Tombstoning cannot see it (the rows were
 * never written, so there is nothing to age out). The truncation guard cannot
 * see it (the read succeeded). Scan health cannot see it (every step
 * succeeded). The estate simply comes back smaller than AWS reported, and
 * nothing says so.
 */

/** One collection step's admission accounting, as stored. */
export interface BatchAccounting {
  collector: string;
  observedCount: number;
  acceptedCount: number;
  quarantinedCount: number;
  rejectedCount: number;
}

/** Rows actually present for a resource type after the run. */
export interface PersistedCount {
  resourceTypeKey: string;
  liveRows: number;
}

export type LineageDriftKind =
  /** observed ≠ accepted + quarantined + rejected. The accounting itself is wrong. */
  | 'UNBALANCED_BATCH'
  /** Admission accepted records that are not present as live rows. */
  | 'ACCEPTED_NOT_PERSISTED'
  /** Records were refused before admission could classify them. */
  | 'REJECTED_BEFORE_ADMISSION';

export interface LineageDrift {
  kind: LineageDriftKind;
  collector: string;
  detail: string;
  /** How many records the discrepancy covers. */
  count: number;
}

export interface LineageReconciliationResult {
  observed: number;
  accepted: number;
  quarantined: number;
  rejected: number;
  /** Live rows across the types these batches wrote. */
  persisted: number;
  drift: LineageDrift[];
  /**
   * PASSED only at zero drift. There is no tolerance band: a record that was
   * accepted and did not become a row is a discrete fact about a resource, not
   * a rounding artifact.
   */
  status: 'PASSED' | 'FAILED';
  /**
   * Why a comparison could not be made, when it could not. Distinct from
   * PASSED — a run with no batches has not been shown to be clean.
   */
  reasonCode: 'no_batches' | null;
}

/**
 * Reconciles one run's admission accounting against stored rows.
 *
 * `persisted` is compared in AGGREGATE, not per collector, and that is a
 * deliberate limit rather than an oversight: several collectors write the same
 * resource type, and a per-collector split would need a provenance column that
 * `cloud_resources` does not carry. Aggregate still catches the failure that
 * matters — records accepted and never stored — without inventing attribution
 * the data cannot support.
 */
export function reconcileLineage(
  batches: readonly BatchAccounting[],
  persisted: readonly PersistedCount[],
): LineageReconciliationResult {
  const drift: LineageDrift[] = [];

  let observed = 0, accepted = 0, quarantined = 0, rejected = 0;
  for (const b of batches) {
    observed += b.observedCount;
    accepted += b.acceptedCount;
    quarantined += b.quarantinedCount;
    rejected += b.rejectedCount;

    const sum = b.acceptedCount + b.quarantinedCount + b.rejectedCount;
    if (sum !== b.observedCount) {
      drift.push({
        kind: 'UNBALANCED_BATCH',
        collector: b.collector,
        detail: `observed ${b.observedCount}, accounted ${sum} (accepted ${b.acceptedCount}, quarantined ${b.quarantinedCount}, rejected ${b.rejectedCount})`,
        count: Math.abs(b.observedCount - sum),
      });
    }

    // Refusal before admission means no typed reason was ever assigned, so the
    // record cannot be explained to a customer. Reported separately from
    // quarantine for exactly that reason.
    if (b.rejectedCount > 0) {
      drift.push({
        kind: 'REJECTED_BEFORE_ADMISSION',
        collector: b.collector,
        detail: `${b.rejectedCount} record(s) refused before admission could classify them`,
        count: b.rejectedCount,
      });
    }
  }

  const persistedTotal = persisted.reduce((a, p) => a + p.liveRows, 0);

  if (batches.length === 0) {
    return {
      observed: 0, accepted: 0, quarantined: 0, rejected: 0,
      persisted: persistedTotal,
      drift: [],
      // NOT passed. A run that ingested nothing has not demonstrated that
      // storage is sound; it has demonstrated nothing.
      status: 'FAILED',
      reasonCode: 'no_batches',
    };
  }

  /**
   * The load-bearing check.
   *
   * Fewer live rows than admission accepted means records were admitted and
   * never stored. MORE live rows is not drift: the estate legitimately carries
   * resources from earlier runs that this run did not re-observe, and calling
   * that an error would flag every incremental scan.
   */
  if (persistedTotal < accepted) {
    drift.push({
      kind: 'ACCEPTED_NOT_PERSISTED',
      collector: '(aggregate)',
      detail: `admission accepted ${accepted} record(s) but only ${persistedTotal} live row(s) exist for the types written`,
      count: accepted - persistedTotal,
    });
  }

  return {
    observed, accepted, quarantined, rejected,
    persisted: persistedTotal,
    drift,
    status: drift.length === 0 ? 'PASSED' : 'FAILED',
    reasonCode: null,
  };
}

/** Bounded sample for storage. The counts remain authoritative. */
export const MAX_DRIFT_SAMPLE = 20;

export function toReconciliationRow(
  result: LineageReconciliationResult,
  ctx: { orgId: string; connectionId: string; collectionRunId: string; accountId: string | null; evaluatedScopes: readonly string[] },
): Record<string, unknown> {
  const count = (k: LineageDriftKind) =>
    result.drift.filter((d) => d.kind === k).reduce((a, d) => a + d.count, 0);

  return {
    org_id: ctx.orgId,
    connection_id: ctx.connectionId,
    collection_run_id: ctx.collectionRunId,
    account_id: ctx.accountId,
    evaluated_scopes: [...ctx.evaluatedScopes],
    discovered_count: result.observed,
    persisted_count: result.persisted,
    matched_count: result.accepted,
    // Accepted-but-absent is exactly "AWS had it, we do not".
    missing_local_count: count('ACCEPTED_NOT_PERSISTED'),
    // Accounting that does not balance is a duplicate/miscount class.
    duplicate_local_count: count('UNBALANCED_BATCH'),
    changed_count: 0,
    stale_local_count: 0,
    region_mismatch_count: 0,
    account_mismatch_count: count('REJECTED_BEFORE_ADMISSION'),
    drift_sample: result.drift.slice(0, MAX_DRIFT_SAMPLE),
    status: result.status,
    reason_code: result.reasonCode,
    completed_at: new Date().toISOString(),
  };
}
