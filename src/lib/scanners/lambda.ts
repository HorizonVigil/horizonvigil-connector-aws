import { createAwsClient, safeFetch } from '../awsApi';
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
 * fetch again, like s3.ts. One page (up to 200 functions) per region-step;
 * accounts with more than that in one region would need a paginated
 * follow-up (NextMarker), not built yet. Event source mappings and layers
 * are two more account/region-wide GETs, same shape.
 */
export async function scanLambda(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'lambda', ctx.region);
  const base = `https://lambda.${ctx.region}.amazonaws.com`;
  const getJson = async (path: string): Promise<Record<string, unknown> | null> => {
    const res = await safeFetch(client, `${base}${path}`, { method: 'GET' });
    const text = await res.text();
    if (!res.ok) {
      console.error(`Lambda GET ${path} failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };

  const out: ScannedResource[] = [];

  const fnBody = await getJson('/2015-03-31/functions/?MaxItems=200');
  for (const fn of (fnBody?.Functions as LambdaFunctionConfig[] | undefined) ?? []) {
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

  const esmBody = await getJson('/2015-03-31/event-source-mappings/');
  for (const esm of (esmBody?.EventSourceMappings as EventSourceMapping[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'lambda_event_source_mapping', resourceId: esm.UUID, region: ctx.region,
      state: esm.State, metadata: { batchSize: esm.BatchSize, lastModified: esm.LastModified },
      relationships: { eventSourceArn: esm.EventSourceArn, functionArn: esm.FunctionArn },
    });
  }

  const layersBody = await getJson('/2015-03-31/layers');
  for (const layer of (layersBody?.Layers as LambdaLayer[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'lambda_layer', resourceId: layer.LatestMatchingVersion?.LayerVersionArn ?? layer.LayerArn ?? layer.LayerName,
      region: ctx.region, resourceName: layer.LayerName,
      metadata: { latestVersion: layer.LatestMatchingVersion?.Version, createdAt: layer.LatestMatchingVersion?.CreatedDate },
    });
  }

  return out;
}
