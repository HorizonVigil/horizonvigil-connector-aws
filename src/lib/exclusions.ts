/**
 * A currently-excluded recommendation is `excluded_at is not null AND
 * (excluded_until is null OR excluded_until > now())` — permanent when
 * excluded_until is null, lapsed (and therefore open again) once
 * excluded_until has passed, computed here at read time rather than as a
 * stored status so a lapsed exclusion re-surfaces with no background job.
 * Mirrors cost-optimization-api's lib/exclusions.ts (that service owns the
 * exclude/unexclude write routes; this is the same read-side filter kept
 * local per this codebase's existing per-service duplication convention for
 * cost_recommendations queries — see routes/dashboard.ts and
 * routes/recommendations.ts, which already each keep their own copy of the
 * `status: 'eq.open'` filter rather than importing cost-optimization-api's).
 */
export function notCurrentlyExcludedFilter(): string {
  return `(excluded_at.is.null,excluded_until.lte.${new Date().toISOString()})`;
}
