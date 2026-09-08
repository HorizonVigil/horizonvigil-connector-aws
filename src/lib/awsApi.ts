import { AwsClient } from 'aws4fetch';
import {
  classifyAwsError,
  isRetryable,
  backoffDelayMs,
  retryAfterMs,
  DEFAULT_RETRY_POLICY,
  type NormalizedErrorCode,
  type RetryPolicy,
} from './awsErrors';

/** One AWS call that exhausted its retries. Reported to `AwsCreds.onCallFailure`. */
export interface AwsCallFailure {
  service: string;
  /** API action for Query/JSON protocols, or the request URL's path for raw fetches. */
  action: string;
  region: string;
  normalizedCode: NormalizedErrorCode;
  attempts: number;
}

export interface AwsCreds {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  /**
   * Per-run sink for calls that failed after retrying.
   *
   * This lives on the credentials rather than on ScannerContext because the
   * creds object is the one thing EVERY scanner already threads into EVERY
   * AWS call — all 111 scanner files, whichever helper they happen to use.
   * Hanging the sink here means a scan reports its degraded coverage without
   * any scanner being edited, and a scanner added tomorrow is covered the day
   * it is written rather than the day someone remembers to wire it.
   *
   * Optional, so every existing caller and test keeps working unchanged.
   */
  onCallFailure?: (failure: AwsCallFailure) => void;
}

export interface AwsCallResult {
  ok: boolean;
  status: number;
  /** Parsed JSON body (JSON-protocol services) or raw XML text (Query-protocol services). */
  body: unknown;
  errorCode?: string;
  errorMessage?: string;
  /** Normalized vocabulary (see awsErrors.ts) — set on every failure. */
  normalizedCode?: NormalizedErrorCode;
  /** How many attempts were made, including the first. >1 means a retry happened. */
  attempts?: number;
}

/** Hard ceiling on a single AWS request. Without it a hung connection blocks a scan step until the platform's own timeout kills the whole run. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 20_000;

export interface AwsCallOptions {
  retry?: RetryPolicy;
  timeoutMs?: number;
  /** Injectable for tests, so retry behaviour is asserted without real sleeping. */
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
}

const realSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Runs `attempt` under the retry policy, backing off with full jitter between
 * tries and honouring AWS's own `Retry-After` when it sends one.
 *
 * Only failures `isRetryable()` accepts are retried — a permission error is
 * returned immediately rather than hammered three more times, which would add
 * load to an account that may already be throttling.
 */
async function withRetry(
  attempt: (signal: AbortSignal) => Promise<{ result: AwsCallResult; retryAfter: string | null }>,
  opts: AwsCallOptions,
  report?: { creds: AwsCreds; service: string; region: string; action: string },
): Promise<AwsCallResult> {
  const policy = opts.retry ?? DEFAULT_RETRY_POLICY;
  const sleep = opts.sleep ?? realSleep;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  let last: AwsCallResult | null = null;

  for (let tries = 0; tries < Math.max(1, policy.maxAttempts); tries++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let outcome: { result: AwsCallResult; retryAfter: string | null };
    try {
      outcome = await attempt(controller.signal);
    } finally {
      clearTimeout(timer);
    }

    const result = { ...outcome.result, attempts: tries + 1 };
    if (result.ok) return result;

    result.normalizedCode = classifyAwsError({ status: result.status, errorCode: result.errorCode, errorMessage: result.errorMessage });
    last = result;

    const isLastAttempt = tries === Math.max(1, policy.maxAttempts) - 1;
    if (!isRetryable(result.normalizedCode) || isLastAttempt) {
      // Terminal: retries are exhausted or the error is not retryable. This
      // is the moment the scanner is about to receive an empty body and carry
      // on, so it is the moment the run has to record degraded coverage.
      // UNSUPPORTED_CAPABILITY is excluded deliberately -- "this account has
      // not enabled Macie" is a settled answer, not incomplete coverage, and
      // treating it as degraded would permanently freeze cleanup for every
      // service the customer does not use.
      if (report && result.normalizedCode !== 'UNSUPPORTED_CAPABILITY') {
        report.creds.onCallFailure?.({
          service: report.service,
          action: report.action,
          region: report.region,
          normalizedCode: result.normalizedCode,
          attempts: result.attempts ?? tries + 1,
        });
      }
      return result;
    }

    const advised = retryAfterMs(outcome.retryAfter);
    await sleep(advised ?? backoffDelayMs(tries, policy, opts.random));
  }

  return last!;
}

/**
 * Query-protocol call (STS, IAM, CloudWatch classic API) — form-encoded
 * request, XML response. No XML DOM parser is used here (this project's own
 * history — see docs/about-project.md §7 — found `@xmldom/xmldom` +
 * `DOMParser` polyfills add real bundle/CPU cost in Workers); these checks
 * only ever need 1-2 known field names out of a response we otherwise
 * discard, so a small regex extractor is enough and avoids that entirely.
 */
export async function callQueryApi(
  creds: AwsCreds,
  opts: { service: string; region: string; host: string; action: string; version: string; params?: Record<string, string> },
  callOpts: AwsCallOptions = {},
): Promise<AwsCallResult> {
  const client = new AwsClient({ accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, sessionToken: creds.sessionToken, service: opts.service, region: opts.region });
  const body = new URLSearchParams({ Action: opts.action, Version: opts.version, ...(opts.params ?? {}) }).toString();

  return withRetry(async (signal) => {
    let res: Response;
    try {
      res = await client.fetch(`https://${opts.host}/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
        signal,
      });
    } catch (err) {
      // Same transport-level failure mode as callJsonApi below (see its
      // comment) — a service without an endpoint in this region throws here
      // instead of returning a response, and every caller already has a
      // graceful !result.ok path that this reuses instead of letting the
      // exception propagate as an uncaught step error. An abort from the
      // timeout above also lands here and classifies as TIMEOUT.
      const message = err instanceof Error ? err.message : 'Network request failed';
      return { result: { ok: false, status: 0, body: '', errorCode: 'FETCH_FAILED', errorMessage: signal.aborted ? 'Request timed out' : message }, retryAfter: null };
    }
    const text = await res.text();
    if (!res.ok) {
      return {
        result: {
          ok: false,
          status: res.status,
          body: text,
          errorCode: extractXmlField(text, 'Code') ?? undefined,
          errorMessage: extractXmlField(text, 'Message') ?? undefined,
        },
        retryAfter: res.headers.get('retry-after'),
      };
    }
    return { result: { ok: true, status: res.status, body: text }, retryAfter: null };
  }, callOpts, { creds, service: opts.service, region: opts.region, action: opts.action });
}

/** JSON-protocol call (Organizations, CloudTrail, Cost Explorer, Resource Groups Tagging API). */
export async function callJsonApi(
  creds: AwsCreds,
  opts: { service: string; region: string; host: string; target: string; body: Record<string, unknown> },
  callOpts: AwsCallOptions = {},
): Promise<AwsCallResult> {
  const client = new AwsClient({ accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, sessionToken: creds.sessionToken, service: opts.service, region: opts.region });
  return withRetry(async (signal) => {
  let res: Response;
  try {
    res = await client.fetch(`https://${opts.host}/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': opts.target },
      body: JSON.stringify(opts.body),
      signal,
    });
  } catch (err) {
    // A handful of services (Timestream is the known case — its
    // endpoint-discovery host is only real in the subset of regions that
    // actually support the service) don't resolve at all in every region a
    // connection might scan, which throws here instead of returning an HTTP
    // response to check .ok on. Every caller already has a graceful
    // "service not available/enabled in this region" path keyed off
    // `!result.ok` — converting a transport-level failure into that same
    // shape (rather than letting it propagate as an uncaught step error)
    // lets that existing handling cover this case too, instead of every
    // caller needing its own try/catch around the same failure mode.
    const message = err instanceof Error ? err.message : 'Network request failed';
    return { result: { ok: false, status: 0, body: {}, errorCode: 'FETCH_FAILED', errorMessage: signal.aborted ? 'Request timed out' : message }, retryAfter: null };
  }
  const text = await res.text();
  const parsed = text ? safeJsonParse(text) : {};
  if (!res.ok) {
    const errObj = safeJsonParse(text) as { __type?: string; message?: string; Message?: string } | null;
    return {
      result: {
        ok: false,
        status: res.status,
        body: parsed,
        errorCode: errObj?.__type?.split('#').pop(),
        errorMessage: errObj?.message ?? errObj?.Message,
      },
      retryAfter: res.headers.get('retry-after'),
    };
  }
  return { result: { ok: true, status: res.status, body: parsed }, retryAfter: null };
  }, callOpts, { creds, service: opts.service, region: opts.region, action: opts.target.split('.').pop() ?? opts.target });
}

/**
 * Raw signed client for calls that don't fit the Query/JSON request shapes
 * above (e.g. S3 object GETs, where the response body is a stream, not
 * XML/JSON to buffer).
 *
 * The reporting context is attached to the returned client so `safeFetch` can
 * report failures the same way the Query/JSON helpers do. 38 scanner files
 * build their client here and then call safeFetch with it; carrying the
 * context on the client is what lets those scanners report degraded coverage
 * without any of them being edited.
 */
export type ReportingAwsClient = AwsClient & { __hvReport?: { creds: AwsCreds; service: string; region: string } };

export function createAwsClient(creds: AwsCreds, service: string, region: string): ReportingAwsClient {
  const client = new AwsClient({ accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, sessionToken: creds.sessionToken, service, region }) as ReportingAwsClient;
  // Non-enumerable so it never lands in a JSON.stringify of the client, which
  // would put credentials into a log line.
  Object.defineProperty(client, '__hvReport', { value: { creds, service, region }, enumerable: false, writable: false });
  return client;
}

/**
 * Wraps a raw `client.fetch()` call for scanners that talk to
 * `createAwsClient` directly instead of through `callJsonApi`/`callQueryApi`
 * above — a service with no endpoint in the region being scanned (confirmed
 * gaps: Detective/Resilience Hub/Well-Architected/Control Tower/RAM in
 * ap-northeast-3, CodeArtifact/Timestream in us-west-1, and more likely
 * exist in other small regions) makes `client.fetch()` throw a raw network
 * exception instead of returning a `Response` to check `.ok` on. Every one
 * of these scanners already has a graceful `if (!res.ok) { ...; return []
 * }` path for a real HTTP error — this had been independently rediscovered
 * and patched once already, per-scanner, in codeartifact.ts alone, instead
 * of fixed centrally here; every other scanner making a raw `client.fetch()`
 * call was still one unavailable region away from an uncaught step failure
 * with no fix.
 *
 * Also buffers the body (by default) inside this same try/catch — confirmed
 * live (2026-08-25, a real S3 scan on a real account) that guarding only the
 * initial `client.fetch()` call wasn't enough: `fetch()`'s promise resolves
 * once headers arrive, the body streams in separately, and every caller
 * immediately calls `.text()` on the result — a connection dropped mid-body
 * throws there too (same underlying "fetch failed" error, just from a
 * different line), completely unguarded by only wrapping the initial call.
 * Buffering here means the caller's later `.text()`/`.json()` call can
 * never throw a second time — it's just reading an in-memory buffer.
 * `bufferBody: false` opts out for the one real exception: curIngest.ts's
 * CUR file download, which deliberately streams a potentially large gzip
 * file via `res.body` rather than holding it entirely in memory — buffering
 * would defeat that, and CUR files are the one caller not reading `.text()`
 * immediately anyway.
 */
export async function safeFetch(
  client: ReportingAwsClient,
  url: string,
  init?: RequestInit,
  opts: { bufferBody?: boolean } & AwsCallOptions = {},
): Promise<Response> {
  const bufferBody = opts.bufferBody ?? true;
  const policy = opts.retry ?? DEFAULT_RETRY_POLICY;
  const sleep = opts.sleep ?? realSleep;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;

  /**
   * Retries here as well as in callJson/QueryApi, because a large share of
   * scanners talk to `createAwsClient` directly and would otherwise keep the
   * original single-shot behaviour — the throttle-to-empty-result-to-mass-
   * delete path is identical whichever helper the scanner happens to use.
   *
   * A non-buffered call (the CUR download) is deliberately NOT retried: its
   * body is a stream the caller consumes itself, so a retry could hand back a
   * second response while the first is still being read.
   */
  let last: Response | null = null;
  const attempts = bufferBody ? Math.max(1, policy.maxAttempts) : 1;

  for (let tries = 0; tries < attempts; tries++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await client.fetch(url, { ...(init ?? {}), signal: controller.signal });
      if (!bufferBody) return res;
      const buf = await res.arrayBuffer();
      const buffered = new Response(buf, { status: res.status, statusText: res.statusText, headers: res.headers });
      if (res.ok) return buffered;
      last = buffered;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Network request failed';
      last = new Response(JSON.stringify({ message: controller.signal.aborted ? 'Request timed out' : message }), { status: 599, statusText: 'Fetch Failed' });
    } finally {
      clearTimeout(timer);
    }

    const code = classifyAwsError({ status: last.status, errorMessage: await peekMessage(last) });
    const isLastAttempt = tries === attempts - 1;
    if (!isRetryable(code) || isLastAttempt) {
      // Same terminal-failure reporting as the Query/JSON helpers -- see
      // withRetry. UNSUPPORTED_CAPABILITY is likewise not degraded coverage.
      const rep = client.__hvReport;
      if (rep && code !== 'UNSUPPORTED_CAPABILITY') {
        rep.creds.onCallFailure?.({
          service: rep.service,
          action: safePathOf(url),
          region: rep.region,
          normalizedCode: code,
          attempts: tries + 1,
        });
      }
      return last;
    }
    await sleep(retryAfterMs(last.headers.get('retry-after')) ?? backoffDelayMs(tries, policy, opts.random));
  }

  return last!;
}

/** Reads a failed response's message without consuming it — the body is already an in-memory buffer here, so cloning is cheap. */
async function peekMessage(res: Response): Promise<string | undefined> {
  try {
    const text = await res.clone().text();
    return extractXmlField(text, 'Message') ?? (safeJsonParse(text) as { message?: string } | null)?.message ?? text.slice(0, 200);
  } catch {
    return undefined;
  }
}

/** AWS Query-protocol list parameter encoding: listParams('Owner', ['self']) -> { 'Owner.1': 'self' }. */
export function listParams(prefix: string, values: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  values.forEach((v, i) => { out[`${prefix}.${i + 1}`] = v; });
  return out;
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export function extractXmlField(xml: string, tag: string): string | null {
  const match = new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(xml);
  return match ? match[1] : null;
}

/** The URL's path only — a raw AWS URL can carry bucket names and object keys, which do not belong in a failure record. */
function safePathOf(url: string): string {
  try {
    return new URL(url).pathname || '/';
  } catch {
    return 'unknown';
  }
}
