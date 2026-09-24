/**
 * Which security-finding sources a run is entitled to call ABSENT.
 *
 * finalize marks an open finding RESOLVED when the run did not see it again.
 * That sentence is only true if the scanner producing it actually ran, in
 * every region, and read everything it tried to read. Before this, the source
 * list was a hardcoded literal inside finalize applied on every run, so:
 *
 *   * a run whose GuardDuty step was never reached (slice budget, cancel)
 *   * a step denied by IAM
 *   * a step throttled halfway through
 *   * a scanner that failed outright
 *
 * all produced the same database write as a clean, complete read: every open
 * finding from that source closed, with `resolved_at` stamped. "We could not
 * look" was recorded as "the customer is clean" -- silently, irreversibly, and
 * on security findings specifically.
 *
 * Extracted here rather than left inline in the worker so the rule is
 * unit-testable on its own, the same reason discoveryFinalize.ts exists.
 */

export interface FindingCoverageInput {
  /** Finding scanner names, e.g. ['guardduty', 'inspector']. */
  scanners: readonly string[];
  /** Regions this connection scans. A scanner must succeed in ALL of them. */
  regions: readonly string[];
  /** Every step this run planned. */
  plannedSteps: readonly string[];
  /** Step ids committed with status 'succeeded' -- NOT merely committed. */
  succeededStepIds: ReadonlySet<string>;
  /** Scanner name -> the finding_source values it writes. */
  sourcesByScanner: Readonly<Record<string, readonly string[]>>;
}

/**
 * Returns the finding_source values this run proved absence for.
 *
 * Every condition is a conjunction, and each one has cost a real product
 * somewhere a real incident:
 *  - the step was PLANNED (a run that never intended to read GuardDuty proves
 *    nothing about GuardDuty),
 *  - in EVERY region (one denied region is enough to hide a finding),
 *  - and committed 'succeeded' -- excluding 'info', which runFindingStep
 *    commits when a call inside the step failed. A step that read part of the
 *    picture cannot prove the rest is gone.
 *
 * An empty result is the correct, safe answer whenever anything is unknown: a
 * finding that stays open one cycle too long is visible and self-correcting;
 * one closed because nobody looked is neither.
 */
export function provenFindingSources(input: FindingCoverageInput): string[] {
  const planned = new Set(input.plannedSteps);
  // A connection with no regions has no region in which anything was read.
  if (input.regions.length === 0) return [];

  const out: string[] = [];
  for (const scanner of input.scanners) {
    const provenEverywhere = input.regions.every((region) => {
      const stepId = `finding:${scanner}:${region}`;
      return planned.has(stepId) && input.succeededStepIds.has(stepId);
    });
    if (!provenEverywhere) continue;
    // An unmapped scanner contributes nothing rather than defaulting to its
    // own name: guessing a finding_source would resolve either the wrong rows
    // or none, and the wrong rows are security findings.
    out.push(...(input.sourcesByScanner[scanner] ?? []));
  }
  return [...new Set(out)];
}
