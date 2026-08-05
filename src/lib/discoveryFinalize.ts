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
 * runStartedAt), AND a scanner that ran this cycle actually covers its
 * resource type. The third condition is the one the original bug missed.
 */
export function computeFinalizeResult(
  existing: FinalizeCandidateResource[],
  coveredResourceTypes: readonly string[],
  runStartedAt: string,
): FinalizeResult {
  const vanishedIds = existing
    .filter((r) => !r.deleted_at && r.last_seen_at < runStartedAt && coveredResourceTypes.includes(r.resource_type_key))
    .map((r) => r.id);

  const vanishedSet = new Set(vanishedIds);
  const active = existing.filter((r) => !r.deleted_at && !vanishedSet.has(r.id));

  const activeCategoryCounts: Record<string, number> = {};
  for (const r of active) activeCategoryCounts[r.category] = (activeCategoryCounts[r.category] ?? 0) + 1;

  return { vanishedIds, activeCategoryCounts, activeCount: active.length };
}
