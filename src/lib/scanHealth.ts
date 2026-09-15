/**
 * Scan health — the completeness picture behind a resource count.
 *
 * WHY THIS EXISTS
 *
 * `cloud_connections.resource_summary.totalResources` is a bare number, and
 * the UI rendered it as a bare number. Nothing on the page could tell the
 * difference between:
 *
 *   430 resources, every scanner read the whole estate
 *   430 resources, EC2 failed in all 17 regions and those rows are stale
 *
 * Both happened on the same account on 2026-09-15. The second is what the
 * customer was shown, with `errors: 0` beside it, because `runFinalize` is
 * called with an empty stepErrors array by the durable worker — the failures
 * live on `collection_run_steps`, which nothing surfaced.
 *
 * A count without its coverage is a claim the data does not support. This
 * derives the coverage so the UI can qualify the count instead of asserting
 * it.
 */

/** One collection-run step as stored. */
export interface StepRow {
  step_id: string;
  status: 'succeeded' | 'failed' | 'skipped' | 'info';
  normalized_code?: string | null;
  error_message?: string | null;
}

export interface ScannerFailure {
  /** Scanner id, e.g. `ec2`. */
  scanner: string;
  /** Scopes it failed in — regions, or `global`. */
  scopes: string[];
  /** Normalized cause, when every failure shares one. Mixed causes report null. */
  normalizedCode: string | null;
  /** First human-readable detail, already redacted upstream. */
  detail: string | null;
}

export type ScanCompleteness =
  /** Every planned step committed and succeeded. */
  | 'COMPLETE'
  /** Some steps failed; the rows collected are real, the estate view is not whole. */
  | 'PARTIAL'
  /** The run failed outright. */
  | 'FAILED'
  /** A run is in flight. */
  | 'RUNNING'
  /** No run has ever finished for this connection. */
  | 'NEVER_RUN';

export interface ScanHealth {
  completeness: ScanCompleteness;
  /**
   * Whether the resource count may be presented as a fact about the estate.
   *
   * False for anything but COMPLETE. A PARTIAL scan's count is a floor, not a
   * total, and rendering it unqualified is the defect this module removes.
   */
  countIsAuthoritative: boolean;
  /** Short sentence a UI can show verbatim. Never contains provider detail. */
  summary: string;
  totalSteps: number;
  succeededSteps: number;
  failedSteps: number;
  /** Distinct scanners that failed at least once, with the scopes they failed in. */
  failures: ScannerFailure[];
  /** Resource types finalize refused to tombstone because coverage was degraded. */
  degradedResourceTypes: string[];
}

/** `regional:ec2:us-east-1` -> { scanner: 'ec2', scope: 'us-east-1' } */
export function parseStepId(stepId: string): { kind: string; scanner: string; scope: string } {
  const [kind = '', scanner = '', ...rest] = stepId.split(':');
  return { kind, scanner, scope: rest.join(':') || 'global' };
}

/**
 * Groups failed steps by scanner.
 *
 * Grouping matters for comprehension: seventeen rows reading
 * `regional:ec2:<region> failed` is noise, while "ec2 failed in 17 regions"
 * is the actual finding. A scanner failing everywhere is a different problem
 * from one failing in a single region, and a flat list hides which it is.
 */
export function groupFailures(steps: readonly StepRow[]): ScannerFailure[] {
  const byScanner = new Map<string, { scopes: string[]; codes: Set<string>; detail: string | null }>();

  for (const step of steps) {
    if (step.status !== 'failed') continue;
    const { scanner, scope } = parseStepId(step.step_id);
    const entry = byScanner.get(scanner) ?? { scopes: [], codes: new Set<string>(), detail: null };
    entry.scopes.push(scope);
    if (step.normalized_code) entry.codes.add(step.normalized_code);
    if (!entry.detail && step.error_message) entry.detail = step.error_message;
    byScanner.set(scanner, entry);
  }

  return [...byScanner.entries()]
    .map(([scanner, e]) => ({
      scanner,
      scopes: [...new Set(e.scopes)].sort(),
      // One shared cause is actionable; several is not, and claiming one of
      // them would send someone to fix the wrong thing.
      normalizedCode: e.codes.size === 1 ? [...e.codes][0] : null,
      detail: e.detail,
    }))
    .sort((a, b) => b.scopes.length - a.scopes.length || a.scanner.localeCompare(b.scanner));
}

export interface RunFacts {
  status: string | null;
  totalSteps: number;
  completedSteps: number;
  failedSteps: number;
  degradedResourceTypes: readonly string[];
}

export function buildScanHealth(run: RunFacts | null, steps: readonly StepRow[]): ScanHealth {
  const failures = groupFailures(steps);
  const degradedResourceTypes = [...(run?.degradedResourceTypes ?? [])].sort();
  const succeeded = steps.filter((s) => s.status === 'succeeded').length;
  const failed = steps.filter((s) => s.status === 'failed').length;

  if (!run || run.status === null) {
    return {
      completeness: 'NEVER_RUN',
      countIsAuthoritative: false,
      summary: 'No collection run has finished for this account yet, so its inventory has not been established.',
      totalSteps: 0, succeededSteps: 0, failedSteps: 0, failures: [], degradedResourceTypes: [],
    };
  }

  const base = {
    totalSteps: run.totalSteps,
    succeededSteps: succeeded,
    failedSteps: failed,
    failures,
    degradedResourceTypes,
  };

  if (['QUEUED', 'RUNNING', 'WAITING_RETRY', 'PAUSED', 'PAUSING', 'CANCEL_REQUESTED'].includes(run.status)) {
    return {
      ...base,
      completeness: 'RUNNING',
      countIsAuthoritative: false,
      summary: `Collection is in progress (${run.completedSteps} of ${run.totalSteps} steps). Counts below are from the previous run.`,
    };
  }

  if (run.status === 'FAILED' || run.status === 'CANCELED') {
    return {
      ...base,
      completeness: 'FAILED',
      countIsAuthoritative: false,
      summary: 'The last collection run did not complete, so this inventory is stale rather than current.',
    };
  }

  if (run.status === 'PARTIALLY_SUCCEEDED' || failed > 0) {
    const worst = failures[0];
    const where = worst
      ? `${worst.scanner} failed in ${worst.scopes.length} ${worst.scopes.length === 1 ? 'region' : 'regions'}`
      : `${failed} step(s) failed`;
    return {
      ...base,
      completeness: 'PARTIAL',
      // The load-bearing line. A partial scan's count is a FLOOR.
      countIsAuthoritative: false,
      summary: `Inventory is incomplete — ${where}. The resources shown are real, but this is not the whole estate.`,
    };
  }

  return {
    ...base,
    completeness: 'COMPLETE',
    countIsAuthoritative: true,
    summary: `All ${run.totalSteps} collection steps succeeded.`,
  };
}
