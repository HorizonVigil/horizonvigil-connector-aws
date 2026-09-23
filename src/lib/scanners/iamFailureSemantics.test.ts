import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * IAM failure semantics.
 *
 * Source-level, like the other guards in this repo, because the properties
 * being pinned are about HOW the scanner reacts to AWS — reachable only by
 * driving a real IAM endpoint through many failure shapes, which no unit test
 * here can do.
 *
 * Three things went wrong at once in the version this replaces, and each is
 * asserted separately below:
 *
 *  1. `call` threw after exhausting its own retries. One failed List* took the
 *     whole IAM scan down, discarding every call that had already succeeded.
 *     EC2 had the identical defect and it fired in production on 2026-09-15:
 *     AWS retired Elastic Graphics, `DescribeElasticGpus` began answering
 *     UNSUPPORTED_CAPABILITY, and EC2 collection failed in **all 17 regions**.
 *
 *  2. It carried a hand-rolled retry loop, duplicating `withRetry` inside
 *     `callQueryApi`. Two layers meant up to 4 x 4 = 16 attempts against a
 *     throttled endpoint — making throttling worse, not better.
 *
 *  3. `listPages` threw when AWS reported IsTruncated with no usable marker,
 *     throwing away the pages already collected.
 */
const SOURCE = readFileSync(join(__dirname, 'iam.ts'), 'utf8');

describe('IAM failure semantics', () => {
  /**
   * The one throw that MUST survive. If ListUsers is denied and the scanner
   * returned '', it would parse zero users and report success — publishing
   * "0 IAM users" for an account whose IAM we were simply not permitted to
   * read. Failing the step visibly is the only honest outcome.
   */
  it('still fails loudly when a REQUIRED call is denied', () => {
    expect(SOURCE).toMatch(/if \(options\.required !== false && !retired\) \{/);
    expect(SOURCE).toMatch(/throw new Error\(`IAM \$\{action\} failed: \$\{code\}`\)/);
  });

  /**
   * A retired or not-enabled capability is a settled answer, not a denial —
   * there is nothing to have been denied. `awsApi.ts` already excludes
   * UNSUPPORTED_CAPABILITY from degraded coverage centrally, for the same
   * reason: it must not freeze cleanup for a service the customer never uses.
   */
  it('never throws on a retired or not-enabled capability', () => {
    expect(SOURCE).toContain("const retired = code === 'UNSUPPORTED_CAPABILITY'");
    expect(SOURCE).toContain("status: retired ? 'not_supported' : 'failed'");
  });

  /** The load-bearing negative for defect 2. */
  it('carries no hand-rolled retry loop', () => {
    expect(SOURCE).not.toMatch(/for \(let attempt = 1; attempt <= maxAttempts/);
    expect(SOURCE).not.toMatch(/const sleep = /);
    expect(SOURCE).not.toMatch(/const isRetryable = /);
    expect(SOURCE).not.toMatch(/maxAttempts/);
    // Retry lives in exactly one place.
    expect(SOURCE).toContain("import { callQueryApi } from '../awsApi'");
  });

  /** The load-bearing negative for defect 3. */
  it('stops rather than throwing when truncation has no usable marker', () => {
    expect(SOURCE).not.toContain('reported IsTruncated=true without a usable continuation marker`)');
    expect(SOURCE).toContain("termination = 'malformed'");
  });

  /**
   * Stopping is only safe because the stop is REPORTED. An incomplete walk
   * that stayed silent would let finalize read the pages we never fetched as
   * deletions — the exact data-destruction path the truncation guard exists
   * to close.
   */
  it('routes every incomplete walk into the degraded-coverage sink', () => {
    expect(SOURCE).toContain('incompleteSink(ctx.creds)');
    const reports = SOURCE.match(/onIncomplete\('PAGINATION_TRUNCATED'/g) ?? [];
    expect(reports.length, 'every incomplete termination must report').toBeGreaterThanOrEqual(2);
  });

  /**
   * An incomplete walk must never be recorded as `success`, or the operation
   * telemetry would assert completeness the data does not have.
   */
  it('records a partial walk as partial, not success', () => {
    expect(SOURCE).toContain("status: termination === 'complete' ? 'success' : 'partial'");
    expect(SOURCE).toMatch(/status: 'success' \| 'partial' \| 'failed' \| 'not_supported'/);
  });

  /** A page cap must bound the walk, not spin inside one worker slice. */
  it('bounds the walk with the shared page cap', () => {
    expect(SOURCE).toContain('DEFAULT_MAX_PAGES');
    expect(SOURCE).toContain("termination = 'page_cap'");
  });

  /**
   * The credential report is ASYNCHRONOUS: GenerateCredentialReport answers
   * STARTED and the report is unreadable for a few seconds.
   *
   * This used to work BY ACCIDENT -- the hand-rolled retry loop's backoff was
   * long enough for the report to become ready. Removing that loop (correct;
   * it duplicated withRetry) removed the accidental poll, and acquisition
   * silently started failing: identities were still written, just without
   * mfaActive, accessKeys or passwordEnabled, and mfa_enabled went NULL for
   * every human in the estate. Measured in production 2026-09-16.
   *
   * Pinned so the poll cannot be removed again as "redundant retry logic".
   */
  it('polls explicitly for the credential report rather than relying on retry backoff', () => {
    expect(SOURCE).toContain('REPORT_POLL_DELAYS_MS');
    expect(SOURCE).toMatch(/for \(const delay of REPORT_POLL_DELAYS_MS\)/);
    // Bounded, and the first attempt is immediate so a ready report costs nothing.
    expect(SOURCE).toMatch(/REPORT_POLL_DELAYS_MS = \[0,/);
    // Exhausting the poll must report not_ready, never an empty-but-fine report.
    expect(SOURCE).toContain("credentialReportStatus = 'not_ready'");
  });

  /**
   * Only values the shared union actually declares. The first version of this
   * work invented 'incomplete' and 'stuck_token', and 'PAGINATION_INCOMPLETE'
   * — none of which exist. tsc caught all four, but pinning them here keeps
   * the vocabularies from drifting apart again.
   */
  it('uses only declared termination and error-code values', () => {
    const TERMINATIONS = ['complete', 'page_cap', 'repeated_token', 'failed', 'malformed'];
    for (const m of SOURCE.matchAll(/termination = '([a-z_]+)'/g)) {
      expect(TERMINATIONS, `termination '${m[1]}' is not in PaginationTermination`).toContain(m[1]);
    }
    for (const m of SOURCE.matchAll(/onIncomplete\('([A-Z_]+)'/g)) {
      expect(m[1], 'must be a declared NormalizedErrorCode').toBe('PAGINATION_TRUNCATED');
    }
  });
});