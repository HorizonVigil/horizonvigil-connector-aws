/**
 * Pure "vanished resource" computation for discovery/finalize, extracted
 * from routes/discovery.ts so it's unit-testable without a database. This
 * is the exact logic behind a real bug (fixed 2026-07-31): finalize used
 * to consider every resource on a connection eligible to be marked
 * deleted, regardless of whether any currently-implemented scanner
 * actually checked its resource type this run — running discovery (EC2
 * only, at the time) against a real account with 349 resources from an
 * older, broader scanner would have wrongly mass-deleted everything
 * outside EC2/EBS/VPC. See discovery_finalize.test.ts.
 */
export interface FinalizeCandidateResource {
  id: string;
  resource_type_key: string;
  category: string;
  last_seen_at: string;
  deleted_at: string | null;
}

export interface FinalizeResult {
  vanishedIds: string[];
  activeCategoryCounts: Record<string, number>;
  activeCount: number;
}

/**
 * A resource is "vanished" (should be marked deleted) only if: it isn't
 * already deleted, it wasn't touched by this run (last_seen_at predates
 * runStartedAt), a scanner that ran this cycle actually covers its resource
 * type, AND that scanner's coverage this run was not degraded.
 *
 * The third condition was the original 2026-07-31 fix. The fourth closes a
 * strictly worse hole found on 2026-09-08.
 *
 * "Absent from the scan" was being treated as proof of "deleted in AWS", but
 * a scanner reports absence for two very different reasons: the resource is
 * genuinely gone, or the API call that would have listed it failed. Scanners
 * swallow a failed sub-call and return an empty body ("continuing without
 * it"), so a single throttled `DescribeInstances` made every EC2 instance on
 * the connection look vanished — and this function would soft-delete the
 * customer's entire live EC2 inventory, while the connection still reported
 * `connected` and the run still reported `succeeded` (sub-call failures never
 * became step errors, so the >10% broken-connection ratio never saw them).
 *
 * Retry (awsErrors.ts) removes the most common trigger. This removes the
 * consequence: a resource type whose scanner reported ANY failure this run is
 * not eligible for deletion at all. The cost of being wrong here is
 * asymmetric — leaving a genuinely-deleted resource listed for one more cycle
 * is a stale row that the next clean run corrects, while deleting a live one
 * destroys history, breaks cost attribution, and silently understates the
 * customer's estate.
 */
export function computeFinalizeResult(
  existing: FinalizeCandidateResource[],
  coveredResourceTypes: readonly string[],
  runStartedAt: string,
  degradedResourceTypes: readonly string[] = [],
): FinalizeResult {
  const degraded = new Set(degradedResourceTypes);
  const vanishedIds = existing
    .filter(
      (r) =>
        !r.deleted_at &&
        r.last_seen_at < runStartedAt &&
        coveredResourceTypes.includes(r.resource_type_key) &&
        !degraded.has(r.resource_type_key),
    )
    .map((r) => r.id);

  const vanishedSet = new Set(vanishedIds);
  const active = existing.filter((r) => !r.deleted_at && !vanishedSet.has(r.id));

  const activeCategoryCounts: Record<string, number> = {};
  for (const r of active) activeCategoryCounts[r.category] = (activeCategoryCounts[r.category] ?? 0) + 1;

  return { vanishedIds, activeCategoryCounts, activeCount: active.length };
}
