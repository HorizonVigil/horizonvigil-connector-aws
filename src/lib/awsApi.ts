import { AwsClient } from 'aws4fetch';

export interface AwsCreds {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface AwsCallResult {
  ok: boolean;
  status: number;
  /** Parsed JSON body (JSON-protocol services) or raw XML text (Query-protocol services). */
  body: unknown;
  errorCode?: string;
  errorMessage?: string;
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
): Promise<AwsCallResult> {
  const client = new AwsClient({ accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, sessionToken: creds.sessionToken, service: opts.service, region: opts.region });
  const body = new URLSearchParams({ Action: opts.action, Version: opts.version, ...(opts.params ?? {}) }).toString();
  let res: Response;
  try {
    res = await client.fetch(`https://${opts.host}/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
  } catch (err) {
    // Same transport-level failure mode as callJsonApi above (see its
    // comment) — a service without an endpoint in this region throws here
    // instead of returning a response, and every caller already has a
    // graceful !result.ok path that this reuses instead of letting the
    // exception propagate as an uncaught step error.
    return { ok: false, status: 0, body: '', errorCode: 'FETCH_FAILED', errorMessage: err instanceof Error ? err.message : 'Network request failed' };
  }
  const text = await res.text();
  if (!res.ok) {
    return {
      ok: false,
      status: res.status,
      body: text,
      errorCode: extractXmlField(text, 'Code') ?? undefined,
      errorMessage: extractXmlField(text, 'Message') ?? undefined,
    };
  }
  return { ok: true, status: res.status, body: text };
}

/** JSON-protocol call (Organizations, CloudTrail, Cost Explorer, Resource Groups Tagging API). */
export async function callJsonApi(
  creds: AwsCreds,
  opts: { service: string; region: string; host: string; target: string; body: Record<string, unknown> },
): Promise<AwsCallResult> {
  const client = new AwsClient({ accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, sessionToken: creds.sessionToken, service: opts.service, region: opts.region });
  let res: Response;
  try {
    res = await client.fetch(`https://${opts.host}/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': opts.target },
      body: JSON.stringify(opts.body),
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
    return { ok: false, status: 0, body: {}, errorCode: 'FETCH_FAILED', errorMessage: err instanceof Error ? err.message : 'Network request failed' };
  }
  const text = await res.text();
  const parsed = text ? safeJsonParse(text) : {};
  if (!res.ok) {
    const errObj = safeJsonParse(text) as { __type?: string; message?: string; Message?: string } | null;
    return {
      ok: false,
      status: res.status,
      body: parsed,
      errorCode: errObj?.__type?.split('#').pop(),
      errorMessage: errObj?.message ?? errObj?.Message,
    };
  }
  return { ok: true, status: res.status, body: parsed };
}

/** Raw signed client for calls that don't fit the Query/JSON request shapes above (e.g. S3 object GETs, where the response body is a stream, not XML/JSON to buffer). */
export function createAwsClient(creds: AwsCreds, service: string, region: string): AwsClient {
  return new AwsClient({ accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, sessionToken: creds.sessionToken, service, region });
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
export async function safeFetch(client: AwsClient, url: string, init?: RequestInit, opts: { bufferBody?: boolean } = {}): Promise<Response> {
  const bufferBody = opts.bufferBody ?? true;
  try {
    const res = await client.fetch(url, init);
    if (!bufferBody) return res;
    const buf = await res.arrayBuffer();
    return new Response(buf, { status: res.status, statusText: res.statusText, headers: res.headers });
  } catch (err) {
    return new Response(JSON.stringify({ message: err instanceof Error ? err.message : 'Network request failed' }), { status: 599, statusText: 'Fetch Failed' });
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
