import { safeFetch } from '../awsApi';
import type { ScannerContext } from './types';

/**
 * Small shared helpers for the hand-rolled REST scanners (S3, S3 Control,
 * CloudTrail, EC2). Everything here exists to protect one invariant:
 *
 *   A resource type whose listing did not complete must be REPORTED as
 *   degraded, never returned as an empty list -- because finalize reads
 *   absence as deletion and tombstones live infrastructure.
 */

type CallFailureSink = NonNullable<ScannerContext['creds']['onCallFailure']>;
export type CallFailure = Parameters<CallFailureSink>[0];

/**
 * Code used for a listing failure that is NOT a permission error (5xx,
 * transport error, a prerequisite call that failed).
 *
 * ACTION FOR MAINTAINERS: if awsErrors.ts uses a different word for a
 * generic service/transport failure, change it HERE -- this is the only
 * place it is spelled.
 */
export const GENERIC_FAILURE_CODE = 'SERVICE_ERROR';

/**
 * Reports a listing call that did not complete, so the resource types it
 * feeds are excluded from tombstoning for this run.
 *
 * Safe to call even when the provider layer also reported the same failure:
 * a duplicate degraded signal is harmless, a missing one deletes inventory.
 */
export function reportListingFailure(
  ctx: ScannerContext,
  failure: { service: string; action: string; region: string; httpStatus?: number; truncated?: boolean },
): void {
  const normalizedCode = failure.truncated
    ? 'PAGINATION_TRUNCATED'
    : failure.httpStatus === 401 || failure.httpStatus === 403
      ? 'PERMISSION_DENIED'
      : GENERIC_FAILURE_CODE;
  try {
    ctx.creds.onCallFailure?.({
      service: failure.service,
      action: failure.action,
      region: failure.region,
      normalizedCode,
      attempts: 1,
    } as CallFailure);
  } catch (err) {
    // A throwing sink must never take the scan down with it.
    console.error(`onCallFailure sink threw for ${failure.service}:${failure.action}: ${errorMessage(err)}`);
  }
}

export interface FetchTextResult {
  ok: boolean;
  /** 0 when the request never produced an HTTP response (DNS, TLS, reset). */
  status: number;
  headers: Headers;
  text: string;
  error?: string;
}

/**
 * safeFetch + body read that never throws.
 *
 * Scanners previously awaited safeFetch directly; a transport-level rejection
 * then escaped the scanner and discarded every resource already collected.
 */
export async function fetchText(
  client: Parameters<typeof safeFetch>[0],
  url: string,
  init: RequestInit,
): Promise<FetchTextResult> {
  try {
    const res = await safeFetch(client, url, init);
    const text = await res.text();
    return { ok: res.ok, status: res.status, headers: res.headers, text };
  } catch (err) {
    return { ok: false, status: 0, headers: new Headers(), text: '', error: errorMessage(err) };
  }
}

/**
 * Promise.all with a concurrency ceiling, preserving input order.
 *
 * Unbounded fan-out bursts through the AWS per-account API rate buckets
 * (turning into retries and throttling) and, on Workers, past the
 * simultaneous-connection limit.
 */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  };
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker);
  await Promise.all(workers);
  return results;
}

export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : 'unknown error';
}

/** Log-safe snippet of an AWS error body (never the whole body). */
export function snippet(text: string, max = 200): string {
  return text.replace(/\s+/g, ' ').slice(0, max);
}