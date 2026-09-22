import type { AwsCallFailure } from './awsApi';

/**
 * AWS-P3 — why a scanner call failed, and whether that means the inventory is
 * incomplete.
 *
 * THE DEFECT THIS EXISTS TO FIX
 *
 * Discovery fans every regional scanner out over all 17 scan regions. Most AWS
 * services are not offered in all 17. When a scanner calls a service that has
 * no endpoint in a region, the call fails — and `onCallFailure` marked every
 * resource type that scanner owns as DEGRADED.
 *
 * Measured in production, 2026-09-22: **41 resource types degraded on every
 * single run**, including `s3_bucket` and `lambda_function`. Extracted from the
 * run logs, `apprunner:ListServices` fails in twelve regions:
 *
 *   ap-northeast-1 RESOURCE_NOT_FOUND   ap-northeast-2 NETWORK_ERROR
 *   ap-northeast-3 NETWORK_ERROR        ap-south-1     RESOURCE_NOT_FOUND
 *   ap-southeast-1 RESOURCE_NOT_FOUND   ap-southeast-2 RESOURCE_NOT_FOUND
 *   ca-central-1   NETWORK_ERROR        eu-central-1   RESOURCE_NOT_FOUND
 *   eu-north-1     NETWORK_ERROR        eu-west-1      RESOURCE_NOT_FOUND
 *   eu-west-2      RESOURCE_NOT_FOUND   eu-west-3      RESOURCE_NOT_FOUND
 *
 * The SAME region answering RESOURCE_NOT_FOUND on one run and NETWORK_ERROR on
 * another is the signature of an endpoint that does not exist: sometimes DNS
 * fails outright, sometimes a catch-all answers 404. It is not an intermittent
 * fault.
 *
 * FOUR CONSEQUENCES, ALL BAD
 *
 *   1. Every run reported 41 degraded types, so inventory was never
 *      authoritative and the account total was permanently a lower bound.
 *   2. Degraded types are protected from deletion (correctly — that is
 *      AWS-12). Permanently degraded types are therefore permanently
 *      un-reconcilable, so genuinely deleted resources are never cleaned up.
 *   3. The run was still stored SUCCEEDED, which contradicts the 41.
 *   4. Roughly 17 regions x ~25 absent services x 4 retries of wasted calls
 *      on every run, against an account that is also being rate-limited.
 *
 * WHAT THIS MODULE DECIDES
 *
 * A failure is only DEGRADING if it means "there may be resources here that we
 * did not read". A service with no endpoint in a region has no resources in
 * that region by construction — that is a coverage FACT, not a coverage gap,
 * and recording it as a gap is what made every run look incomplete.
 */

/** What a terminal call failure means for inventory completeness. */
export type FailureMeaning =
  /**
   * The service is not offered in this region. There is nothing to read here
   * and nothing is missing. Recorded as coverage, never as degradation.
   */
  | 'service_absent_in_region'
  /** IAM refused. Resources may exist and were not read — genuinely degrading. */
  | 'permission_denied'
  /** AWS asked us to slow down. Degrading, and retryable. */
  | 'throttled'
  /** AWS was unwell, or the request was malformed. Degrading. */
  | 'collection_failed'
  /** The call succeeded but did not read everything AWS offered. Degrading. */
  | 'incomplete_read';

export interface FailureClassification {
  meaning: FailureMeaning;
  /** Does this failure mean the scanner's resource types may be under-read? */
  degrades: boolean;
  /** One sentence naming the cause, stored alongside the affected types. */
  reason: string;
}

/**
 * Failures that mean "no endpoint here".
 *
 * `RESOURCE_NOT_FOUND` on a service-level LIST is the clearest signal: a list
 * operation over an empty account returns an empty list, not a not-found — so
 * not-found means the API itself is not there.
 *
 * `NETWORK_ERROR` is included for the same reason, and it is the judgement
 * call in this module: it genuinely can mean a transient network fault. It is
 * treated as absence ONLY when paired with the service being absent elsewhere
 * in the same run (see `classifyFailure`'s `absentElsewhere` argument), so a
 * real outage in one region is not silently reclassified.
 */
const ENDPOINT_ABSENT_CODES = new Set(['RESOURCE_NOT_FOUND']);

/** Ambiguous: absence or a genuine transport fault. Resolved with corroboration. */
const AMBIGUOUS_CODES = new Set(['NETWORK_ERROR', 'TIMEOUT']);

const THROTTLE_CODES = new Set(['THROTTLED', 'RATE_LIMITED']);

/**
 * @param failure          The terminal call failure.
 * @param absentElsewhere  True when this same service already answered with an
 *                         endpoint-absent code in ANOTHER region this run.
 *                         Corroboration, so an ambiguous NETWORK_ERROR is only
 *                         read as absence when the service is demonstrably
 *                         absent rather than momentarily unreachable.
 */
export function classifyFailure(failure: AwsCallFailure, absentElsewhere = false): FailureClassification {
  const code = failure.normalizedCode as string;

  if (code === 'PAGINATION_TRUNCATED') {
    return {
      meaning: 'incomplete_read',
      degrades: true,
      reason: `${failure.service}:${failure.action} in ${failure.region} returned more results than were read, so this type is under-counted.`,
    };
  }

  if (code === 'PERMISSION_DENIED' || code === 'AUTHENTICATION_FAILED') {
    return {
      meaning: 'permission_denied',
      degrades: true,
      reason: `${failure.service}:${failure.action} was denied in ${failure.region}. Resources of this type may exist and were not read.`,
    };
  }

  if (THROTTLE_CODES.has(code)) {
    return {
      meaning: 'throttled',
      degrades: true,
      reason: `${failure.service}:${failure.action} was throttled in ${failure.region} after ${failure.attempts} attempt(s), so this region was not fully read.`,
    };
  }

  if (ENDPOINT_ABSENT_CODES.has(code)) {
    return {
      meaning: 'service_absent_in_region',
      degrades: false,
      reason: `${failure.service} is not available in ${failure.region}, so there is nothing of this type to read there.`,
    };
  }

  if (AMBIGUOUS_CODES.has(code) && absentElsewhere) {
    return {
      meaning: 'service_absent_in_region',
      degrades: false,
      reason: `${failure.service} is not available in ${failure.region} (its endpoint did not resolve, and the service is absent in other scanned regions too).`,
    };
  }

  /*
   * Everything else degrades, INCLUDING an uncorroborated NETWORK_ERROR. The
   * safe default when a failure cannot be explained is to assume resources
   * were missed, because the cost of being wrong the other way is deleting
   * inventory that still exists.
   */
  return {
    meaning: 'collection_failed',
    degrades: true,
    reason: `${failure.service}:${failure.action} failed in ${failure.region} (${code}) after ${failure.attempts} attempt(s).`,
  };
}

/**
 * Accumulates a run's call failures and answers which resource types are
 * genuinely degraded, with the reason for each.
 *
 * Two-pass on purpose: an ambiguous NETWORK_ERROR in one region can only be
 * judged once the whole run is known, because the corroborating evidence is
 * the same service failing as absent somewhere else.
 */
export class RegionCoverageLedger {
  private readonly failures: { failure: AwsCallFailure; types: readonly string[] }[] = [];

  /** Services observed absent, by definite endpoint-absent codes only. */
  private readonly definitelyAbsent = new Set<string>();

  record(failure: AwsCallFailure, ownedTypes: readonly string[]): void {
    this.failures.push({ failure, types: ownedTypes });
    if (ENDPOINT_ABSENT_CODES.has(failure.normalizedCode as string)) {
      this.definitelyAbsent.add(failure.service);
    }
  }

  /** Resource types that may be under-read, mapped to why. */
  degradedTypes(): Map<string, string> {
    const out = new Map<string, string>();
    for (const { failure, types } of this.failures) {
      const c = classifyFailure(failure, this.definitelyAbsent.has(failure.service));
      if (!c.degrades) continue;
      // First reason wins; a type degraded twice is degraded for the first
      // cause a reader would act on.
      for (const t of types) if (!out.has(t)) out.set(t, c.reason);
    }
    return out;
  }

  /** Service/region pairs proven to have no endpoint. Coverage, not failure. */
  absentRegions(): { service: string; region: string; reason: string }[] {
    const seen = new Set<string>();
    const out: { service: string; region: string; reason: string }[] = [];
    for (const { failure } of this.failures) {
      const c = classifyFailure(failure, this.definitelyAbsent.has(failure.service));
      if (c.meaning !== 'service_absent_in_region') continue;
      const key = `${failure.service}|${failure.region}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ service: failure.service, region: failure.region, reason: c.reason });
    }
    return out;
  }

  /** Every failure, classified — for the per-scanner record AWS-P3 requires. */
  summary(): { meaning: FailureMeaning; count: number }[] {
    const counts = new Map<FailureMeaning, number>();
    for (const { failure } of this.failures) {
      const c = classifyFailure(failure, this.definitelyAbsent.has(failure.service));
      counts.set(c.meaning, (counts.get(c.meaning) ?? 0) + 1);
    }
    return [...counts.entries()].map(([meaning, count]) => ({ meaning, count }));
  }
}
