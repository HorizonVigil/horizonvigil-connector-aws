import { createAwsClient } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const APIGATEWAY_RESOURCE_TYPES = ['apigateway_rest_api', 'apigateway_http_api', 'apigateway_websocket_api'] as const;

interface RestApi {
  id: string; name?: string; description?: string; createdDate?: string;
  endpointConfiguration?: { types?: string[] };
}
interface V2Api {
  ApiId: string; Name?: string; ProtocolType?: string; CreatedDate?: string; ApiEndpoint?: string;
}

/**
 * REST-JSON like Lambda — createAwsClient's raw signed fetch. REST APIs
 * (v1, /restapis) and HTTP/WebSocket APIs (v2, /v2/apis) are both served
 * from the same apigateway.{region}.amazonaws.com host despite the version
 * split; v2's ProtocolType field ("HTTP" vs "WEBSOCKET") is what
 * distinguishes the two catalog entries this call also has to produce.
 */
export async function scanApiGateway(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'apigateway', ctx.region);
  const base = `https://apigateway.${ctx.region}.amazonaws.com`;
  const getJson = async (path: string): Promise<Record<string, unknown> | null> => {
    const res = await client.fetch(`${base}${path}`, { method: 'GET' });
    const text = await res.text();
    if (!res.ok) {
      console.error(`API Gateway GET ${path} failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };

  const out: ScannedResource[] = [];

  const restBody = await getJson('/restapis?limit=500');
  for (const api of (restBody?.item as RestApi[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'apigateway_rest_api', resourceId: api.id, region: ctx.region, resourceName: api.name,
      metadata: { description: api.description, createdAt: api.createdDate, endpointTypes: api.endpointConfiguration?.types },
    });
  }

  const v2Body = await getJson('/v2/apis');
  for (const api of (v2Body?.items as V2Api[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: api.ProtocolType === 'WEBSOCKET' ? 'apigateway_websocket_api' : 'apigateway_http_api',
      resourceId: api.ApiId, region: ctx.region, resourceName: api.Name,
      metadata: { createdAt: api.CreatedDate, endpoint: api.ApiEndpoint },
    });
  }

  return out;
}
