import { describe, it, expect } from 'vitest';
import {
  classifyAwsError,
  isRetryable,
  backoffDelayMs,
  retryAfterMs,
  describeNormalizedError,
  DEFAULT_RETRY_POLICY,
} from './awsErrors';

/**
 * Section 16/17 of the connector spec: normalized errors, retry, backoff,
 * jitter. Before this module, connector-aws had none of them — every AWS call
 * was single-shot, and a throttle was absorbed as an empty result.
 */
describe('classifyAwsError', () => {
  it('recognises throttling under every name AWS actually uses', () => {
    // The whole point: these differ per service, not per protocol. Matching
    // one of them is equivalent to matching none.
    for (const code of [
      'Throttling',
      'ThrottlingException',
      'RequestLimitExceeded',
      'TooManyRequestsException',
      'SlowDown',
      'ProvisionedThroughputExceededException',
      'RequestThrottled',
    ]) {
      expect(classifyAwsError({ status: 400, errorCode: code }), code).toBe('THROTTLED');
    }
  });

  it('classifies a throttle by its CODE even when AWS returns HTTP 400', () => {
    // Query-protocol services return 400 for throttling. Classifying by
    // status first would make a retryable throttle look permanent.
    expect(classifyAwsError({ status: 400, errorCode: 'RequestLimitExceeded' })).toBe('THROTTLED');
    expect(isRetryable(classifyAwsError({ status: 400, errorCode: 'RequestLimitExceeded' }))).toBe(true);
  });

  it('separates authentication from authorization', () => {
    expect(classifyAwsError({ status: 403, errorCode: 'ExpiredToken' })).toBe('AUTHENTICATION_FAILED');
    expect(classifyAwsError({ status: 403, errorCode: 'AccessDenied' })).toBe('PERMISSION_DENIED');
  });

  it('separates "capability not enabled" from "permission denied"', () => {
    // These need different words in front of a customer: only one of them is
    // fixed by editing an IAM policy.
    expect(classifyAwsError({ status: 400, errorCode: 'OptInRequired' })).toBe('UNSUPPORTED_CAPABILITY');
    expect(classifyAwsError({ status: 400, errorCode: 'AWSOrganizationsNotInUseException' })).toBe('UNSUPPORTED_CAPABILITY');
    expect(classifyAwsError({ status: 403, errorCode: 'UnauthorizedOperation' })).toBe('PERMISSION_DENIED');
  });

  it('maps transport failures, including safeFetch\'s synthesized 599', () => {
    expect(classifyAwsError({ status: 0, errorMessage: 'fetch failed' })).toBe('NETWORK_ERROR');
    expect(classifyAwsError({ status: 599, errorMessage: 'fetch failed' })).toBe('NETWORK_ERROR');
    expect(classifyAwsError({ status: 599, errorMessage: 'Request timed out' })).toBe('TIMEOUT');
  });

  it('maps status codes when no error code is present', () => {
    expect(classifyAwsError({ status: 429 })).toBe('RATE_LIMITED');
    expect(classifyAwsError({ status: 503 })).toBe('AWS_SERVICE_UNAVAILABLE');
    expect(classifyAwsError({ status: 404 })).toBe('RESOURCE_NOT_FOUND');
    expect(classifyAwsError({ status: 400 })).toBe('INVALID_REQUEST');
  });
});

describe('isRetryable', () => {
  it('retries only what a retry can fix', () => {
    for (const c of ['THROTTLED', 'RATE_LIMITED', 'AWS_SERVICE_UNAVAILABLE', 'NETWORK_ERROR', 'TIMEOUT'] as const) {
      expect(isRetryable(c), c).toBe(true);
    }
  });

  it('never retries a permission or validation error', () => {
    // Retrying these cannot succeed, and multiplies the API pressure that
    // caused the throttling in the first place.
    for (const c of ['PERMISSION_DENIED', 'AUTHENTICATION_FAILED', 'INVALID_REQUEST', 'UNSUPPORTED_CAPABILITY', 'RESOURCE_NOT_FOUND'] as const) {
      expect(isRetryable(c), c).toBe(false);
    }
  });
});

describe('backoffDelayMs', () => {
  it('grows exponentially and is capped', () => {
    const max = (attempt: number) => backoffDelayMs(attempt, DEFAULT_RETRY_POLICY, () => 0.999999);
    expect(max(0)).toBeLessThanOrEqual(200);
    expect(max(1)).toBeLessThanOrEqual(400);
    expect(max(2)).toBeLessThanOrEqual(800);
    expect(max(10)).toBeLessThanOrEqual(DEFAULT_RETRY_POLICY.maxDelayMs);
  });

  it('uses FULL jitter, so simultaneous callers do not re-collide', () => {
    // Every region of a scan starts at the same instant. Identical backoffs
    // would re-throttle the account in lockstep on every attempt; spreading
    // uniformly across the whole window is what de-syncs them.
    expect(backoffDelayMs(3, DEFAULT_RETRY_POLICY, () => 0)).toBe(0);
    expect(backoffDelayMs(3, DEFAULT_RETRY_POLICY, () => 0.5)).toBeGreaterThan(0);
    expect(backoffDelayMs(3, DEFAULT_RETRY_POLICY, () => 0.5)).toBeLessThan(backoffDelayMs(3, DEFAULT_RETRY_POLICY, () => 0.99));
  });
});

describe('retryAfterMs', () => {
  it('honours AWS delay-seconds', () => {
    expect(retryAfterMs('2')).toBe(2000);
  });

  it('honours the HTTP-date form', () => {
    const now = Date.parse('2026-09-08T12:00:00Z');
    expect(retryAfterMs('Tue, 08 Sep 2026 12:00:03 GMT', now)).toBe(3000);
  });

  it('never waits absurdly long, and ignores junk', () => {
    expect(retryAfterMs('99999')).toBe(60_000);
    expect(retryAfterMs('soon')).toBeNull();
    expect(retryAfterMs(null)).toBeNull();
  });

  it('treats a past date as "retry now" rather than a negative wait', () => {
    const now = Date.parse('2026-09-08T12:00:00Z');
    expect(retryAfterMs('Tue, 08 Sep 2026 11:59:00 GMT', now)).toBe(0);
  });
});

describe('describeNormalizedError', () => {
  it('never leaks raw AWS detail (ARNs, account ids) into customer-facing text', () => {
    for (const c of ['PERMISSION_DENIED', 'THROTTLED', 'AUTHENTICATION_FAILED', 'UNSUPPORTED_CAPABILITY'] as const) {
      const text = describeNormalizedError(c);
      expect(text).not.toMatch(/arn:|\d{12}/);
      expect(text.length).toBeGreaterThan(10);
    }
  });
});
