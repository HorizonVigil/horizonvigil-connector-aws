/**
 * AWS error normalization and retry policy.
 *
 * Until this existed, connector-aws had NO retry, backoff, jitter, rate
 * limiting or request timeout anywhere -- verified by grep across all 14.8k
 * lines: the only "retry" strings in the repo were comments, and
 * `enforceRateLimit` is HorizonVigil's INBOUND API limiter, not an outbound
 * AWS one. Every AWS call was single-shot.
 *
 * That is not a throughput problem, it is a correctness problem, because of
 * how the failure is absorbed downstream. A scanner's inner call helper logs
 * and returns an empty body on `!ok` ("continuing without it"), the scanner
 * therefore reports zero resources for that service, and discovery's finalize
 * step marks every previously-known resource of a covered type as deleted
 * because it "wasn't seen this run". So a single throttled
 * `DescribeInstances` could soft-delete a customer's entire live EC2
 * inventory while the connection still reported `connected` and the sync
 * still reported `succeeded`.
 *
 * Throttling is the dominant transient cause of exactly that, so retrying it
 * correctly here removes most of the risk for all ~120 scanners at once,
 * without touching any of them. The finalize guard in discoveryFinalize.ts is
 * the safety net for what retry cannot fix.
 */

/** Section 16 of the connector spec: the normalized error vocabulary HorizonVigil sees, instead of raw AWS codes. */
export type NormalizedErrorCode =
  | 'AUTHENTICATION_FAILED'
  | 'PERMISSION_DENIED'
  | 'RESOURCE_NOT_FOUND'
  | 'THROTTLED'
  | 'RATE_LIMITED'
  | 'NETWORK_ERROR'
  | 'TIMEOUT'
  | 'AWS_SERVICE_UNAVAILABLE'
  | 'INVALID_REQUEST'
  | 'UNSUPPORTED_CAPABILITY'
  | 'UNKNOWN';

/**
 * AWS signals throttling under a genuinely surprising number of names, and
 * they differ per service rather than per protocol -- EC2 uses
 * `RequestLimitExceeded`, most JSON services use `ThrottlingException`, S3
 * uses `SlowDown`, DynamoDB uses `ProvisionedThroughputExceededException`.
 * Matching only one of them is the same as matching none.
 */
const THROTTLE_CODES = new Set([
  'Throttling',
  'ThrottlingException',
  'ThrottledException',
  'RequestThrottled',
  'RequestThrottledException',
  'RequestLimitExceeded',
  'TooManyRequestsException',
  'ProvisionedThroughputExceededException',
  'TransactionInProgressException',
  'SlowDown',
  'EC2ThrottledException',
  'RequestTimeout',
  'PriorRequestNotComplete',
]);

const AUTH_CODES = new Set([
  'InvalidClientTokenId',
  'UnrecognizedClientException',
  'InvalidAccessKeyId',
  'SignatureDoesNotMatch',
  'ExpiredToken',
  'ExpiredTokenException',
  'InvalidSecurityToken',
  'InvalidSecurityTokenException',
  'AuthFailure',
  'MissingAuthenticationToken',
  'IncompleteSignature',
]);

const DENIED_CODES = new Set([
  'AccessDenied',
  'AccessDeniedException',
  'UnauthorizedOperation',
  'AuthorizationError',
  'NotAuthorized',
  'Forbidden',
]);

const NOT_FOUND_CODES = new Set([
  'NoSuchEntity',
  'ResourceNotFoundException',
  'NoSuchBucket',
  'NotFoundException',
  'NoSuchEntityException',
  'InvalidInstanceID.NotFound',
  'ResourceNotFound',
]);

/**
 * A capability the account genuinely does not have turned on, or that AWS
 * does not offer in this region. Distinct from PERMISSION_DENIED on purpose:
 * "you have not enabled Security Hub" and "your role may not read Security
 * Hub" need different words in front of a customer, and only one of them is
 * fixed by editing an IAM policy.
 */
const UNSUPPORTED_CODES = new Set([
  'OptInRequired',
  'SubscriptionRequiredException',
  'UnsupportedOperation',
  'InvalidAction',
  'AWSOrganizationsNotInUseException',
  'ResourceNotFoundException:SecurityHub',
  'InvalidClientException',
  'DataUnavailableException',
  'UnsupportedCommandException',
]);

export interface ClassifyInput {
  /** HTTP status; 0 for a transport-level failure, 599 for safeFetch's synthesized failure response. */
  status: number;
  errorCode?: string;
  errorMessage?: string;
}

/**
 * Maps an AWS failure onto the normalized vocabulary. Ordering matters: the
 * error CODE is checked before the HTTP status, because AWS routinely returns
 * 400 for throttling on Query-protocol services -- classifying by status
 * first would treat a retryable throttle as a permanent INVALID_REQUEST.
 */
export function classifyAwsError(input: ClassifyInput): NormalizedErrorCode {
  const code = input.errorCode ?? '';
  const message = input.errorMessage ?? '';

  if (THROTTLE_CODES.has(code)) return 'THROTTLED';
  if (AUTH_CODES.has(code)) return 'AUTHENTICATION_FAILED';
  if (DENIED_CODES.has(code)) return 'PERMISSION_DENIED';
  if (NOT_FOUND_CODES.has(code)) return 'RESOURCE_NOT_FOUND';
  if (UNSUPPORTED_CODES.has(code)) return 'UNSUPPORTED_CAPABILITY';

  // safeFetch synthesizes 599 for a transport failure; callJson/QueryApi use 0.
  if (input.status === 0 || input.status === 599) {
    return /timed?\s*out|timeout|aborted/i.test(message) ? 'TIMEOUT' : 'NETWORK_ERROR';
  }
  if (input.status === 429) return 'RATE_LIMITED';
  if (input.status === 401) return 'AUTHENTICATION_FAILED';
  if (input.status === 403) return 'PERMISSION_DENIED';
  if (input.status === 404) return 'RESOURCE_NOT_FOUND';
  if (input.status === 408) return 'TIMEOUT';
  if (input.status === 503 || input.status === 502 || input.status === 504) return 'AWS_SERVICE_UNAVAILABLE';
  if (input.status >= 500) return 'AWS_SERVICE_UNAVAILABLE';
  if (input.status >= 400) return 'INVALID_REQUEST';
  return 'UNKNOWN';
}

/**
 * Retry only what a retry can actually fix.
 *
 * PERMISSION_DENIED and INVALID_REQUEST are deliberately excluded: retrying
 * them cannot succeed, and doing so multiplies the API pressure that caused
 * the throttling in the first place. UNSUPPORTED_CAPABILITY is a settled
 * answer, not a failure.
 */
export function isRetryable(code: NormalizedErrorCode): boolean {
  return code === 'THROTTLED' || code === 'RATE_LIMITED' || code === 'AWS_SERVICE_UNAVAILABLE' || code === 'NETWORK_ERROR' || code === 'TIMEOUT';
}

export interface RetryPolicy {
  /** Total attempts including the first. 1 disables retrying. */
  maxAttempts: number;
  /** First backoff step in ms; doubles per attempt before jitter. */
  baseDelayMs: number;
  /** Upper bound on a single backoff, before jitter. */
  maxDelayMs: number;
}

export const DEFAULT_RETRY_POLICY: RetryPolicy = { maxAttempts: 4, baseDelayMs: 200, maxDelayMs: 5_000 };

/**
 * Full-jitter exponential backoff (`random(0, min(cap, base * 2^attempt))`).
 *
 * Full jitter rather than fixed or equal jitter because every region of a
 * scan starts its calls at the same instant: identical backoffs would
 * re-collide on every attempt and re-throttle the account in lockstep.
 * Spreading uniformly across the whole window is what actually de-syncs them.
 *
 * `attempt` is 0-based for the first retry. `random` is injectable so the
 * tests can assert the window bounds deterministically instead of sampling.
 */
export function backoffDelayMs(attempt: number, policy: RetryPolicy = DEFAULT_RETRY_POLICY, random: () => number = Math.random): number {
  const ceiling = Math.min(policy.maxDelayMs, policy.baseDelayMs * Math.pow(2, attempt));
  return Math.floor(random() * ceiling);
}

/**
 * AWS may state exactly how long to wait. Honour it over our own backoff when
 * it is present and sane -- guessing shorter just earns another throttle.
 * Supports both the delay-seconds and HTTP-date forms of `Retry-After`.
 */
export function retryAfterMs(headerValue: string | null, now: number = Date.now()): number | null {
  if (!headerValue) return null;
  const seconds = Number(headerValue);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, 60_000);
  const asDate = Date.parse(headerValue);
  if (Number.isFinite(asDate)) {
    const delta = asDate - now;
    return delta > 0 ? Math.min(delta, 60_000) : 0;
  }
  return null;
}

/** Human-facing sentence for a normalized code. Never includes raw AWS text, which can carry ARNs and account identifiers. */
export function describeNormalizedError(code: NormalizedErrorCode): string {
  switch (code) {
    case 'AUTHENTICATION_FAILED':
      return 'AWS rejected the stored credentials for this connection.';
    case 'PERMISSION_DENIED':
      return 'The connected AWS role is missing a permission this operation requires.';
    case 'RESOURCE_NOT_FOUND':
      return 'AWS reported that the requested resource no longer exists.';
    case 'THROTTLED':
    case 'RATE_LIMITED':
      return 'AWS is rate limiting this account; the request was retried and still throttled.';
    case 'NETWORK_ERROR':
      return 'The request to AWS could not be completed.';
    case 'TIMEOUT':
      return 'The request to AWS timed out.';
    case 'AWS_SERVICE_UNAVAILABLE':
      return 'AWS reported the service as unavailable.';
    case 'INVALID_REQUEST':
      return 'AWS rejected the request as invalid.';
    case 'UNSUPPORTED_CAPABILITY':
      return 'This AWS capability is not enabled or not available in this region.';
    default:
      return 'An unrecognized AWS error occurred.';
  }
}
