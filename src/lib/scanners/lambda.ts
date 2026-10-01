import { createAwsClient } from '../awsApi';
import { fetchJson, reportWalk, walkPages } from './restJson';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const LAMBDA_RESOURCE_TYPES = ['lambda_function', 'lambda_event_source_mapping', 'lambda_layer'] as const;

interface LambdaFunctionConfig {
  FunctionName: string; FunctionArn?: string; Runtime?: string; Role?: string; Handler?: string;
  CodeSize?: number; Description?: string; Timeout?: number; MemorySize?: number;
  LastModified?: string; State?: string; PackageType?: string;
}
interface EventSourceMapping {
  UUID: string; EventSourceArn?: string; FunctionArn?: string; State?: string; LastModified?: number; BatchSize?: number;
}
interface LambdaLayer {
  LayerName: string; LayerArn?: string; LatestMatchingVersion?: { LayerVersionArn?: string; Version?: number; CreatedDate?: string };
}

/**
 * Lambda's ListFunctions is REST-JSON (a plain GET with a JSON body, no
 * Action param or X-Amz-Target header) — createAwsClient's raw signed
 * fetch again, like s3.ts. All three account/region-wide lists paginate on
 * NextMarker. An incomplete walk is reported so finalization cannot mistake
 * unread pages for deleted functions, mappings, or layers.
 */
export async function scanLambda(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'lambda', ctx.region);
  const base = `https://lambda.${ctx.region}.amazonaws.com`;
  const list = <T>(path: string, itemsKey: string, maxItems: number) => walkPages<T>(
    (marker) => fetchJson(client, `${base}${path}${path.includes('?') ? '&' : '?'}MaxItems=${maxItems}${marker ? `&Marker=${encodeURIComponent(marker)}` : ''}`),
    (body) => body[itemsKey],
    (body) => body.NextMarker,
    200,
  );

  const out: ScannedResource[] = [];

  const [functions, mappings, layers] = await Promise.all([
    list<LambdaFunctionConfig>('/2015-03-31/functions/', 'Functions', 200),
    list<EventSourceMapping>('/2015-03-31/event-source-mappings/', 'EventSourceMappings', 100),
    list<LambdaLayer>('/2018-10-31/layers', 'Layers', 50),
  ]);
  reportWalk(ctx, functions, 'lambda', 'ListFunctions');
  reportWalk(ctx, mappings, 'lambda', 'ListEventSourceMappings');
  reportWalk(ctx, layers, 'lambda', 'ListLayers');

  for (const fn of functions.items) {
    out.push({
      resourceTypeKey: 'lambda_function', resourceId: fn.FunctionArn ?? fn.FunctionName, region: ctx.region,
      resourceName: fn.FunctionName, state: fn.State,
      metadata: {
        runtime: fn.Runtime, handler: fn.Handler, codeSizeBytes: fn.CodeSize, description: fn.Description,
        timeoutSeconds: fn.Timeout, memoryMB: fn.MemorySize, lastModified: fn.LastModified, packageType: fn.PackageType,
      },
      relationships: { roleArn: fn.Role },
    });
  }

  for (const esm of mappings.items) {
    out.push({
      resourceTypeKey: 'lambda_event_source_mapping', resourceId: esm.UUID, region: ctx.region,
      state: esm.State, metadata: { batchSize: esm.BatchSize, lastModified: esm.LastModified },
      relationships: { eventSourceArn: esm.EventSourceArn, functionArn: esm.FunctionArn },
    });
  }

  for (const layer of layers.items) {
    out.push({
      resourceTypeKey: 'lambda_layer', resourceId: layer.LatestMatchingVersion?.LayerVersionArn ?? layer.LayerArn ?? layer.LayerName,
      region: ctx.region, resourceName: layer.LayerName,
      metadata: { latestVersion: layer.LatestMatchingVersion?.Version, createdAt: layer.LatestMatchingVersion?.CreatedDate },
    });
  }

  return out;
}
