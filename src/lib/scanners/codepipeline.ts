import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'CodePipeline_20150709';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CODEPIPELINE_RESOURCE_TYPES = ['codepipeline_pipeline'] as const;

interface PipelineSummary {
  name: string; version?: number; created?: number; updated?: number;
}

/** One list call, already returns everything this catalog entry needs — no per-pipeline fan-out (GetPipelineState would add stage/action detail, not built here). */
export async function scanCodePipeline(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `codepipeline.${ctx.region}.amazonaws.com`;
  const result = await callJsonApi(ctx.creds, { service: 'codepipeline', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListPipelines`, body: {} });
  if (!result.ok) {
    console.error(`CodePipeline ListPipelines failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  return ((result.body as { pipelines?: PipelineSummary[] }).pipelines ?? []).map((p) => ({
    resourceTypeKey: 'codepipeline_pipeline', resourceId: p.name, region: ctx.region, resourceName: p.name,
    metadata: { version: p.version, createdAt: p.created, updatedAt: p.updated },
  }));
}
