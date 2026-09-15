/**
 * Shared AWS pagination.
 *
 * WHY THIS EXISTS, AND WHY IT IS ONE MODULE
 *
 * Before this, pagination was per-scanner and mostly absent. A grep across the
 * 160 scanner files found exactly 22 that mentioned any pagination token at
 * all; the rest issued a single list call and returned whatever page 1 held.
 * Every one of those APIs is paginated on the AWS side (EC2 `NextToken`, RDS
 * `Marker`, SNS `NextToken`, ACM `NextToken`, IAM `IsTruncated`/`Marker`, ...),
 * so an account with more instances than one page silently reported fewer —
 * with a 200 and no error.
 *
 * That is not a display bug. `runFinalize` establishes absence from "the
 * scanner that covers this type did not return it", so a truncated page 1
 * makes every resource beyond it look deleted, and the next scan soft-deletes
 * live infrastructure. The failure has no error to attach to, so the
 * degraded-coverage sink never fired. This module, plus the truncation guard in
 * awsApi.ts, is what closes it.
 *
 * ONE module rather than a copy per scanner, because the walk itself is
 * protocol-shaped, not service-shaped: pass the token back under the field name
 * AWS returned it in, stop when it stops, and refuse to loop forever if AWS
 * repeats a token. The only genuinely per-service parts are the response
 * section holding the list and the tag naming each member — both are parameters
 * here.
 *
 * The critical implementation detail is that items are accumulated PER PAGE.
 * A tempting shortcut is to concatenate the page bodies and slice the list out
 * once, but `extractSection` (xmlList.ts) returns only the FIRST matching
 * section, so that silently discards every page after the first while still
 * making the calls for them. That exact bug was written and caught here.
 */
import { callQueryApi, callJsonApi, type AwsCallOptions, type AwsCreds } from './awsApi';
import { extractSection, extractListItems } from './xmlList';
import type { NormalizedErrorCode } from './awsErrors';
import { detectQueryTruncation, type TruncationSignal } from './paginationSignals';

/**
 * The truncation detectors live in paginationSignals.ts, because awsApi.ts needs
 * them too and importing them from here would be a cycle. Re-exported so a
 * scanner migrating onto the walker needs one import.
 */
export { detectQueryTruncation, detectJsonTruncation, type TruncationSignal } from './paginationSignals';

/** How a page walk ended. Every value other than `complete` means coverage is incomplete. */
export type PaginationTermination =
  /** AWS said there is nothing more to read. The only value that proves completeness. */
  | 'complete'
  /** maxPages reached with a token still outstanding. */
  | 'page_cap'
  /** AWS returned a token this walk had already followed. */
  | 'repeated_token'
  /** A page request failed after retries; whatever was collected before it stands. */
  | 'failed'
  /** AWS reported truncation but supplied no token to continue with. */
  | 'malformed';

export interface PageWalk<T> {
  /** Items from every page read, in order. Never just the first page. */
  items: T[];
  /** Pages actually fetched. 1 means the answer was not paginated. */
  pages: number;
  termination: PaginationTermination;
  /** Human-readable cause, set whenever termination !== 'complete'. */
  detail?: string;
}

/**
 * Default ceiling on pages per walk.
 *
 * A cap has to exist: a repeated or lagging token from AWS would otherwise spin
 * until the platform kills the run. 200 pages is comfortably past any real
 * account at AWS's page sizes (EC2 lists 1,000 per page, IAM 100), so reaching
 * it means something is wrong rather than that the account is large — which is
 * why hitting it is reported, not swallowed.
 */
export const DEFAULT_MAX_PAGES = 200;

/**
 * Items out of one Query-protocol page.
 *
 * `section` is the wrapper element (`volumeSet`, `Users`, ...) and `itemTag`
 * the repeated member tag inside it (`item` for EC2, `member` for IAM, a
 * type-named tag for RDS). Extraction is per page by construction: this takes
 * ONE page body.
 */
export function queryPageItems(xml: string, section: string, itemTag = 'item'): string[] {
  return extractListItems(extractSection(xml, section), itemTag);
}

/**
 * Items out of one JSON-protocol page.
 *
 * Returns [] rather than throwing when the key is absent: an absent list key is
 * a legitimate empty page, and a caller should not have to distinguish "no
 * queues" from "no queues".
 */
export function jsonPageItems<T>(body: unknown, key: string): T[] {
  if (body === null || typeof body !== 'object') return [];
  const value = (body as Record<string, unknown>)[key];
  return Array.isArray(value) ? (value as T[]) : [];
}

export interface PageWalkOptions extends AwsCallOptions {
  /** Defaults to DEFAULT_MAX_PAGES. */
  maxPages?: number;
  /**
   * Sink for incompleteness that AWS did NOT report as an error — the page cap,
   * the repeated token, and truncation with no token. A FAILED page needs no
   * call here: it already went through awsApi's terminal-failure path, which
   * reports on its own.
   */
  onIncomplete?: (code: NormalizedErrorCode, detail: string) => void;
}

/**
 * The walk itself, parameterised over how one page is fetched and read.
 *
 * Kept protocol-agnostic and pure-ish so the termination rules — cap, repeated
 * token, malformed truncation — are asserted in one place instead of being
 * re-derived (differently) in every scanner that follows a token.
 */
async function walkPages<TPage, TItem>(
  fetchPage: (tokenParam: string | null, token: string | null) => Promise<{ ok: boolean; page: TPage; error?: string }>,
  readItems: (page: TPage) => TItem[],
  detect: (page: TPage) => TruncationSignal,
  options: PageWalkOptions,
): Promise<PageWalk<TItem>> {
  const maxPages = Math.max(1, options.maxPages ?? DEFAULT_MAX_PAGES);
  const items: TItem[] = [];
  const seenTokens = new Set<string>();

  let token: string | null = null;
  let tokenParam: string | null = null;
  let pages = 0;

  const incomplete = (termination: PaginationTermination, detail: string): PageWalk<TItem> => {
    options.onIncomplete?.('PAGINATION_TRUNCATED', detail);
    return { items, pages, termination, detail };
  };

  for (;;) {
    const response = await fetchPage(tokenParam, token);
    if (!response.ok) {
      // The failure has already been classified and reported by awsApi (so the
      // scanner's resource types are degraded and finalize will not tombstone).
      // What is added here is the honest statement that this walk is partial.
      return {
        items, pages,
        termination: 'failed',
        detail: response.error ?? 'a page request failed',
      };
    }

    pages += 1;
    items.push(...readItems(response.page));

    const signal = detect(response.page);
    if (!signal.truncated) return { items, pages, termination: 'complete' };

    if (signal.nextToken === null || signal.tokenParam === null) {
      return incomplete(
        'malformed',
        `page ${pages} reported truncation with no continuation token; the remainder was not read`,
      );
    }

    if (seenTokens.has(signal.nextToken)) {
      // AWS repeating a token would otherwise loop until the platform kills the
      // run, and every iteration would burn API quota re-reading the same page.
      return incomplete(
        'repeated_token',
        `page ${pages} returned a continuation token already followed; stopped rather than looping`,
      );
    }

    if (pages >= maxPages) {
      return incomplete(
        'page_cap',
        `stopped at the ${maxPages}-page cap with more results outstanding; the remainder was not read`,
      );
    }

    seenTokens.add(signal.nextToken);
    token = signal.nextToken;
    tokenParam = signal.tokenParam;
  }
}

/**
 * Walks every page of an AWS Query-protocol list operation.
 *
 * `readItems` and `detect` each receive ONE page's XML; use `queryPageItems` /
 * `detectQueryTruncation`, or a custom pair when a page carries several lists.
 */
export async function paginateQueryApi<TPage, TItem>(
  creds: AwsCreds,
  opts: { service: string; region: string; host: string; action: string; version: string; params?: Record<string, string> },
  readItems: (page: TPage) => TItem[],
  detect: (page: TPage) => TruncationSignal,
  walkOpts: PageWalkOptions = {},
): Promise<PageWalk<TItem>> {
  return walkPages<TPage, TItem>(
    async (tokenParam, token) => {
      const params = tokenParam && token ? { ...(opts.params ?? {}), [tokenParam]: token } : opts.params;
      const result = await callQueryApi(
        creds,
        { ...opts, params },
        // 'follow' opts this call out of awsApi's truncation guard: this walk is
        // the thing reading the pages, and it reports its own incompleteness.
        { ...walkOpts, pagination: 'follow' },
      );
      if (!result.ok) {
        return { ok: false, page: '' as unknown as TPage, error: result.normalizedCode ?? result.errorCode ?? `HTTP ${result.status}` };
      }
      return { ok: true, page: result.body as TPage };
    },
    readItems,
    detect,
    walkOpts,
  );
}

/** Walks every page of an AWS JSON-protocol list operation. */
export async function paginateJsonApi<TPage, TItem>(
  creds: AwsCreds,
  opts: { service: string; region: string; host: string; target: string; body: Record<string, unknown> },
  readItems: (page: TPage) => TItem[],
  detect: (page: TPage) => TruncationSignal,
  walkOpts: PageWalkOptions = {},
): Promise<PageWalk<TItem>> {
  return walkPages<TPage, TItem>(
    async (tokenParam, token) => {
      const body = tokenParam && token ? { ...opts.body, [tokenParam]: token } : opts.body;
      const result = await callJsonApi(
        creds,
        { ...opts, body },
        { ...walkOpts, pagination: 'follow' },
      );
      if (!result.ok) {
        return { ok: false, page: null as unknown as TPage, error: result.normalizedCode ?? result.errorCode ?? `HTTP ${result.status}` };
      }
      return { ok: true, page: result.body as TPage };
    },
    readItems,
    detect,
    walkOpts,
  );
}

/**
 * Query-protocol list walk with the overwhelmingly common shape: one section,
 * one repeated member tag. This is the form almost every scanner should use.
 */
export async function paginateQueryList(
  creds: AwsCreds,
  opts: { service: string; region: string; host: string; action: string; version: string; params?: Record<string, string> },
  section: string,
  itemTag = 'item',
  walkOpts: PageWalkOptions = {},
): Promise<PageWalk<string>> {
  return paginateQueryApi<string, string>(
    creds, opts,
    (xml) => queryPageItems(xml, section, itemTag),
    (xml) => detectQueryTruncation(xml),
    walkOpts,
  );
}

/**
 * The sink a scanner should hand to a walk so an incomplete walk degrades its
 * own resource types.
 *
 * Without this, a page cap or a repeated token would be reported nowhere:
 * `onCallFailure` only fires for calls that FAILED, and these are calls that
 * succeeded. Wiring it is one line per scanner and is the difference between
 * "coverage was partial and we said so" and another silent shortfall.
 *
 * `service` is 'pagination' and `action` carries the reason, which is what the
 * operator sees in the flow log line discovery.ts already emits per degraded
 * call. No credential, ARN or account id is included.
 */
export function incompleteSink(creds: AwsCreds): (code: NormalizedErrorCode, detail: string) => void {
  return (code, detail) => {
    creds.onCallFailure?.({
      service: 'pagination',
      action: detail,
      region: 'unknown',
      normalizedCode: code,
      attempts: 1,
    });
  };
}

/** True when a walk's result proves the type was fully enumerated. */
export function isComplete(walk: PageWalk<unknown>): boolean {
  return walk.termination === 'complete';
}