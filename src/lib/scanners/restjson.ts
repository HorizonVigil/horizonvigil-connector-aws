import { callJsonApi } from '../awsApi';
import { fetchText, reportListingFailure, snippet } from './scannerSupport';
import type { ScannerContext } from './types';

/**
 * Shared plumbing for the REST-JSON (path-based) and JSON-RPC (X-Amz-Target)
 * scanners: Access Analyzer, API Gateway, App Mesh, AppSync, Backup, Batch,
 * App Runner, Athena, ACM PCA, Budgets, Cost Explorer.
 *
 * Every one of those scanners had the same three defects, so they are fixed
 * once here rather than sixteen times:
 *
 *  1. NO PAGINATION. Each read page one and stopped. Anything past the first
 *     page looked deleted to finalize.
 *  2. UNREPORTED FAILURES. A failed list call logged and returned [] -- which
 *     finalize also reads as "everything was deleted".
 *  3. UNGUARDED JSON.parse. A truncated or HTML error body threw out of the
 *     scanner and discarded everything it had already collected.
 */

export interface JsonResult {
  ok: boolean;
  /** 0 when no HTTP response was received. */
  status: number;
  body: Record<string, unknown> | null;
  error?: string;
}

type Client = Parameters<typeof fetchText>[0];

/** GET/POST a REST-JSON endpoint. Never throws. */
export async function fetchJson(client: Client, url: string, init: RequestInit = { method: 'GET' }): Promise<JsonResult> {
  const headers = { Accept: 'application/json', ...(init.headers as Record<string, string> | undefined) };
  const res = await fetchText(client, url, { ...init, headers });
  if (!res.ok) {
    return { ok: false, status: res.status, body: null, error: res.error ?? `HTTP ${res.status} ${snippet(res.text)}` };
  }
  if (!res.text.trim()) return { ok: true, status: res.status, body: {} };
  try {
    const parsed = JSON.parse(res.text) as unknown;
    return parsed && typeof parsed === 'object'
      ? { ok: true, status: res.status, body: parsed as Record<string, unknown> }
      : { ok: false, status: res.status, body: null, error: 'response was not a JSON object' };
  } catch {
    return { ok: false, status: res.status, body: null, error: `unparseable JSON: ${snippet(res.text)}` };
  }
}

export function postJson(client: Client, url: string, body: unknown): Promise<JsonResult> {
  return fetchJson(client, url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

export interface PageWalk<T> {
  items: T[];
  pages: number;
  /** true only when the API stopped handing out a continuation token. */
  complete: boolean;
  /** true when the first page failed, i.e. nothing at all was read. */
  firstPageFailed: boolean;
  status?: number;
  error?: string;
}

export const DEFAULT_PAGE_CAP = 50;

/** Generic token walk. Stops on failure, repeated token, or the page cap. Never throws. */
export async function walkPages<T>(
  fetchPage: (token: string | undefined) => Promise<JsonResult>,
  itemsOf: (body: Record<string, unknown>) => unknown,
  nextOf: (body: Record<string, unknown>) => unknown,
  maxPages = DEFAULT_PAGE_CAP,
): Promise<PageWalk<T>> {
  const items: T[] = [];
  const seen = new Set<string>();
  let token: string | undefined;

  for (let page = 0; page < maxPages; page++) {
    const res = await fetchPage(token);
    if (!res.ok || !res.body) {
      return { items, pages: page, complete: false, firstPageFailed: page === 0, status: res.status, error: res.error };
    }
    const pageItems = itemsOf(res.body);
    if (Array.isArray(pageItems)) items.push(...(pageItems as T[]));
    const next = nextOf(res.body);
    if (typeof next !== 'string' || next === '') return { items, pages: page + 1, complete: true, firstPageFailed: false };
    if (seen.has(next)) return { items, pages: page + 1, complete: false, firstPageFailed: false, error: 'repeated continuation token' };
    seen.add(next);
    token = next;
  }
  return { items, pages: maxPages, complete: false, firstPageFailed: false, error: `page cap ${maxPages} reached` };
}

/** Every page of a JSON-RPC (X-Amz-Target) list call via callJsonApi. */
export function walkJsonRpc<T>(
  ctx: ScannerContext,
  req: { service: string; host: string; target: string; body?: Record<string, unknown>; region?: string },
  itemsKey: string,
  opts: { tokenIn?: string; tokenOut?: string; maxPages?: number } = {},
): Promise<PageWalk<T>> {
  const tokenIn = opts.tokenIn ?? 'NextToken';
  const tokenOut = opts.tokenOut ?? 'NextToken';
  const region = req.region ?? ctx.region;
  return walkPages<T>(
    async (token) => {
      const r = await callJsonApi(ctx.creds, {
        service: req.service, region, host: req.host, target: req.target,
        body: { ...(req.body ?? {}), ...(token ? { [tokenIn]: token } : {}) },
      });
      return r.ok
        ? { ok: true, status: r.status, body: (r.body ?? {}) as Record<string, unknown> }
        : { ok: false, status: r.status, body: null, error: r.errorMessage ?? r.errorCode ?? `status ${r.status}` };
    },
    (b) => b[itemsKey],
    (b) => b[tokenOut],
    opts.maxPages,
  );
}

/**
 * Reports an incomplete walk so the types it feeds are excluded from
 * tombstoning, and logs it. Returns true when the walk was complete.
 *
 * Safe even where the provider layer also reported the failure: a duplicate
 * degraded signal is harmless, a missing one deletes inventory.
 */
export function reportWalk(ctx: ScannerContext, walk: PageWalk<unknown>, service: string, action: string, region = ctx.region): boolean {
  if (walk.complete) return true;
  const what = walk.firstPageFailed ? 'failed' : 'was incomplete';
  console.error(`${service} ${action} ${what} in ${region} after ${walk.pages} page(s) (continuing with what was read): ${walk.error ?? ''}`);
  reportListingFailure(ctx, walk.firstPageFailed
    ? { service, action, region, httpStatus: walk.status }
    : { service, action, region, truncated: true });
  return false;
}

/** Epoch seconds (JSON 1.1 protocol) or ISO string → ISO string; anything else → null. */
export function toIso(value: unknown): string | null {
  if (typeof value === 'number') return Number.isFinite(value) ? new Date(value * 1000).toISOString() : null;
  if (typeof value === 'string' && value.trim() !== '') return value;
  return null;
}

/** A string field that may arrive under either wire casing (e.g. apiId / ApiId). */
export function pick<T = string>(obj: Record<string, unknown> | undefined | null, ...keys: string[]): T | undefined {
  if (!obj) return undefined;
  for (const k of keys) if (obj[k] !== undefined && obj[k] !== null) return obj[k] as T;
  return undefined;
}