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
  const res = await client.fetch(`https://${opts.host}/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
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
  const res = await client.fetch(`https://${opts.host}/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': opts.target },
    body: JSON.stringify(opts.body),
  });
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
