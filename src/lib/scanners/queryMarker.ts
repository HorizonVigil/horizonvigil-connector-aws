import { callQueryApi } from '../awsApi';
import { DEFAULT_MAX_PAGES, incompleteSink, type PaginationTermination } from '../pagination';
import { extractSection, extractListItems, field } from '../xmlList';
import type { ScannerContext } from './types';

/**
 * Generic page walker for Query-protocol (XML) APIs whose continuation token
 * has a service-specific name -- the shape rdsQuery.ts handles for RDS, for
 * everything else:
 *
 *   ElastiCache       Marker     → <Marker>      (MaxRecords ≤ 100)
 *   ELB / ELBv2       Marker     → <NextMarker>  (PageSize ≤ 400)
 *   Elastic Beanstalk NextToken  → <NextToken>   (MaxRecords ≤ 1000)
 *
 * A failed page ends the walk as 'failed' and keeps what was read
 * (callQueryApi's terminal-failure path reports it). A page cap or repeated
 * token is reported through the shared incomplete sink. Never throws.
 */
export interface QueryWalk {
  items: string[];
  pages: number;
  termination: PaginationTermination;
  detail?: string;
}

export interface QueryWalkRequest {
  service: string;
  host: string;
  version: string;
  action: string;
  params?: Record<string, string>;
  listSection: string;
  itemTag: string;
  tokenIn?: string;
  tokenOut?: string;
  pageSizeParam?: string;
  pageSize?: string;
  maxPages?: number;
}

export async function describeAllQuery(ctx: ScannerContext, req: QueryWalkRequest): Promise<QueryWalk> {
  const tokenIn = req.tokenIn ?? 'Marker';
  const tokenOut = req.tokenOut ?? 'Marker';
  const maxPages = req.maxPages ?? DEFAULT_MAX_PAGES;
  const onIncomplete = incompleteSink(ctx.creds);
  const items: string[] = [];
  const seen = new Set<string>();
  let token: string | null = null;
  let pages = 0;

  for (;;) {
    if (pages >= maxPages) {
      const detail = `${req.service} ${req.action} hit the ${maxPages}-page cap in ${ctx.region}`;
      console.error(detail);
      onIncomplete('PAGINATION_TRUNCATED', detail);
      return { items, pages, termination: 'page_cap', detail };
    }
    const params: Record<string, string> = {
      ...(req.params ?? {}),
      ...(req.pageSizeParam && req.pageSize ? { [req.pageSizeParam]: req.pageSize } : {}),
      ...(token ? { [tokenIn]: token } : {}),
    };
    const result = await callQueryApi(ctx.creds, { service: req.service, region: ctx.region, host: req.host, action: req.action, version: req.version, params });
    if (!result.ok) {
      const detail = `${req.service} ${req.action} failed in ${ctx.region} after ${pages} page(s): ${result.errorMessage ?? result.errorCode ?? result.status}`;
      console.error(`${detail} (continuing with what was read)`);
      return { items, pages, termination: 'failed', detail };
    }
    pages += 1;
    const xml = result.body as string;
    items.push(...extractListItems(extractSection(xml, req.listSection), req.itemTag));

    // The continuation token is a result-level element; list items never carry one.
    const next = field(xml, tokenOut);
    if (!next) return { items, pages, termination: 'complete' };
    if (seen.has(next)) {
      const detail = `${req.service} ${req.action} returned a repeated ${tokenOut} in ${ctx.region}`;
      console.error(detail);
      onIncomplete('PAGINATION_TRUNCATED', detail);
      return { items, pages, termination: 'repeated_token', detail };
    }
    seen.add(next);
    token = next;
  }
}

/** `<Attributes><member><Key>k</Key><Value>v</Value></member>…` → map (ELBv2 attributes). */
export function keyValueMembers(xml: string | null, section = 'Attributes'): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of extractListItems(extractSection(xml ?? '', section), 'member')) {
    const k = field(m, 'Key');
    if (k) out[k] = field(m, 'Value') ?? '';
  }
  return out;
}
