import { createAwsClient } from '../awsApi';
import { summarizePolicy } from './policyEvidence';
import { fetchJson, pick, reportWalk, walkPages } from './restJson';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const APIGATEWAY_RESOURCE_TYPES = ['apigateway_rest_api', 'apigateway_http_api', 'apigateway_websocket_api'] as const;

/** Per-API follow-ups (stages, routes), bounded for the Workers subrequest budget. */
const MAX_API_ENRICHMENT = 25;
const ENRICHMENT_CONCURRENCY = 4;

type Json = Record<string, unknown>;

/**
 * One REST API stage as evidence. The methodSettings entry keyed "all
 * resources, all methods" is the stage-wide default API Gateway applies to
 * every method.
 */
export function restStageEvidence(stage: Json) {
  const all = ((stage.methodSettings as Json | undefined)?.['*/*'] ?? {}) as Json;
  return {
    stageName: (stage.stageName as string) ?? null,
    webAclArn: (stage.webAclArn as string) ?? null,
    tracingEnabled: (stage.tracingEnabled as boolean) ?? false,
    clientCertificateId: (stage.clientCertificateId as string) ?? null,
    cacheClusterEnabled: (stage.cacheClusterEnabled as boolean) ?? false,
    cacheDataEncrypted: (all.cacheDataEncrypted as boolean) ?? null,
    loggingLevel: (all.loggingLevel as string) ?? 'OFF',
    // Full request/response logging can write secrets into CloudWatch.
    dataTraceEnabled: (all.dataTraceEnabled as boolean) ?? false,
    accessLogDestination: ((stage.accessLogSettings as Json | undefined)?.destinationArn as string) ?? null,
  };
}

/** One HTTP/WebSocket API stage as evidence (v2 wire format is camelCase). */
export function v2StageEvidence(stage: Json) {
  const defaults = (pick<Json>(stage, 'defaultRouteSettings', 'DefaultRouteSettings') ?? {}) as Json;
  const access = (pick<Json>(stage, 'accessLogSettings', 'AccessLogSettings') ?? {}) as Json;
  return {
    stageName: pick(stage, 'stageName', 'StageName') ?? null,
    accessLogDestination: pick(access, 'destinationArn', 'DestinationArn') ?? null,
    loggingLevel: pick(defaults, 'loggingLevel', 'LoggingLevel') ?? null,
    dataTraceEnabled: pick<boolean>(defaults, 'dataTraceEnabled', 'DataTraceEnabled') ?? false,
    detailedMetricsEnabled: pick<boolean>(defaults, 'detailedMetricsEnabled', 'DetailedMetricsEnabled') ?? false,
    autoDeploy: pick<boolean>(stage, 'autoDeploy', 'AutoDeploy') ?? false,
  };
}

/**
 * API Gateway — REST APIs (v1, /restapis) and HTTP/WebSocket APIs (v2,
 * /v2/apis) from the same regional host.
 *
 * What changed, and why:
 *
 *  - HTTP and WebSocket APIs had NO identity. The v2 REST wire format is
 *    camelCase (`apiId`, `protocolType`, `name`); the previous version read
 *    `ApiId`/`ProtocolType`/`Name` (the SDK's casing), so every v2 API got an
 *    undefined resourceId and every WebSocket API was typed as HTTP. Both
 *    casings are now accepted.
 *
 *  - Both lists paginate (v1 `position`, v2 `nextToken`); failures are
 *    reported so finalize does not read them as deletions; `Accept:
 *    application/json` is sent so v1 never answers in HAL form (whose items
 *    live under `_embedded`, which is also accepted).
 *
 *  - API security evidence: endpoint type (PRIVATE vs public), resource
 *    policy (anonymous/cross-account), whether the default execute-api
 *    endpoint is disabled, and per-stage WAF, logging, tracing, client
 *    certificates and cache encryption; for v2, CORS and routes with NO
 *    authorization.
 */
export async function scanApiGateway(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'apigateway', ctx.region);
  const base = `https://apigateway.${ctx.region}.amazonaws.com`;
  const itemsOfV1 = (b: Json) => b.item ?? (b._embedded as Json | undefined)?.item;

  const [restWalk, v2Walk] = await Promise.all([
    walkPages<Json>(
      (token) => fetchJson(client, `${base}/restapis?limit=500${token ? `&position=${encodeURIComponent(token)}` : ''}`),
      itemsOfV1,
      (b) => b.position,
    ),
    walkPages<Json>(
      (token) => fetchJson(client, `${base}/v2/apis?maxResults=500${token ? `&nextToken=${encodeURIComponent(token)}` : ''}`),
      (b) => b.items ?? b.Items,
      (b) => b.nextToken ?? b.NextToken,
    ),
  ]);
  reportWalk(ctx, restWalk, 'apigateway', 'GetRestApis');
  reportWalk(ctx, v2Walk, 'apigateway', 'GetApis');

  const out: ScannedResource[] = [];

  // ── REST APIs (v1) ────────────────────────────────────────────────────────
  const restApis = restWalk.items.filter((a) => typeof a?.id === 'string' && a.id !== '');
  const restStages = new Map<string, ReturnType<typeof restStageEvidence>[] | null>();
  await mapWithConcurrency(restApis.slice(0, MAX_API_ENRICHMENT), ENRICHMENT_CONCURRENCY, async (api) => {
    const res = await fetchJson(client, `${base}/restapis/${encodeURIComponent(api.id as string)}/stages`);
    const list = res.ok ? itemsOfV1(res.body ?? {}) : null;
    restStages.set(api.id as string, Array.isArray(list) ? (list as Json[]).map(restStageEvidence) : null);
  });

  for (const api of restApis) {
    const id = api.id as string;
    const endpointTypes = ((api.endpointConfiguration as Json | undefined)?.types as string[] | undefined) ?? [];
    const stages = restStages.get(id);
    out.push({
      resourceTypeKey: 'apigateway_rest_api', resourceId: id, region: ctx.region, resourceName: api.name as string | undefined,
      tags: api.tags as Record<string, string> | undefined,
      metadata: {
        description: api.description, createdAt: api.createdDate, endpointTypes,
        isPrivate: endpointTypes.includes('PRIVATE'),
        disableExecuteApiEndpoint: (api.disableExecuteApiEndpoint as boolean) ?? false,
        apiKeySource: api.apiKeySource ?? null,
        // Resource policy: who may invoke. Owning account is not known here, so
        // externalAccountIds lists every account the policy names.
        resourcePolicy: summarizePolicy(api.policy as string | undefined, null),
        stagesCollected: stages !== undefined && stages !== null,
        stages: stages ?? [],
      },
      relationships: { vpcEndpointIds: ((api.endpointConfiguration as Json | undefined)?.vpcEndpointIds as string[] | undefined) ?? [] },
    });
  }

  // ── HTTP / WebSocket APIs (v2) ────────────────────────────────────────────
  const v2Apis = v2Walk.items.filter((a) => !!pick(a, 'apiId', 'ApiId'));
  const v2Enrichment = new Map<string, { stages: ReturnType<typeof v2StageEvidence>[] | null; routes: { total: number; unauthenticated: number; unauthenticatedRouteKeys: string[] } | null }>();
  await mapWithConcurrency(v2Apis.slice(0, MAX_API_ENRICHMENT), ENRICHMENT_CONCURRENCY, async (api) => {
    const id = pick(api, 'apiId', 'ApiId') as string;
    const [stagesRes, routesRes] = await Promise.all([
      fetchJson(client, `${base}/v2/apis/${encodeURIComponent(id)}/stages?maxResults=500`),
      fetchJson(client, `${base}/v2/apis/${encodeURIComponent(id)}/routes?maxResults=500`),
    ]);
    const stageItems = stagesRes.ok ? (stagesRes.body?.items ?? stagesRes.body?.Items) : null;
    const routeItems = routesRes.ok ? (routesRes.body?.items ?? routesRes.body?.Items) : null;
    const routes = Array.isArray(routeItems) ? (routeItems as Json[]) : null;
    const open = routes?.filter((r) => (pick(r, 'authorizationType', 'AuthorizationType') ?? 'NONE') === 'NONE') ?? [];
    v2Enrichment.set(id, {
      stages: Array.isArray(stageItems) ? (stageItems as Json[]).map(v2StageEvidence) : null,
      routes: routes ? {
        total: routes.length,
        unauthenticated: open.length,
        unauthenticatedRouteKeys: open.map((r) => pick(r, 'routeKey', 'RouteKey') ?? '').filter(Boolean).slice(0, 50),
      } : null,
    });
  });

  for (const api of v2Apis) {
    const id = pick(api, 'apiId', 'ApiId') as string;
    const protocol = pick(api, 'protocolType', 'ProtocolType');
    const cors = pick<Json>(api, 'corsConfiguration', 'CorsConfiguration');
    const allowOrigins = (cors ? pick<string[]>(cors, 'allowOrigins', 'AllowOrigins') : undefined) ?? [];
    const enrichment = v2Enrichment.get(id);
    out.push({
      resourceTypeKey: protocol === 'WEBSOCKET' ? 'apigateway_websocket_api' : 'apigateway_http_api',
      resourceId: id, region: ctx.region, resourceName: pick(api, 'name', 'Name'),
      tags: pick<Record<string, string>>(api, 'tags', 'Tags'),
      metadata: {
        createdAt: pick(api, 'createdDate', 'CreatedDate'),
        endpoint: pick(api, 'apiEndpoint', 'ApiEndpoint'),
        protocolType: protocol ?? null,
        disableExecuteApiEndpoint: pick<boolean>(api, 'disableExecuteApiEndpoint', 'DisableExecuteApiEndpoint') ?? false,
        corsAllowOrigins: allowOrigins,
        corsAllowsAnyOrigin: allowOrigins.includes('*'),
        corsAllowCredentials: (cors ? pick<boolean>(cors, 'allowCredentials', 'AllowCredentials') : undefined) ?? false,
        stagesCollected: !!enrichment?.stages,
        stages: enrichment?.stages ?? [],
        routesCollected: !!enrichment?.routes,
        routeCount: enrichment?.routes?.total ?? null,
        unauthenticatedRouteCount: enrichment?.routes?.unauthenticated ?? null,
        unauthenticatedRouteKeys: enrichment?.routes?.unauthenticatedRouteKeys ?? [],
      },
    });
  }

  if (restApis.length + v2Apis.length > MAX_API_ENRICHMENT * 2) {
    console.error(`API Gateway ${ctx.region}: stage/route evidence read for the first ${MAX_API_ENRICHMENT} APIs of each kind; the rest are marked not collected.`);
  }
  return out;
}