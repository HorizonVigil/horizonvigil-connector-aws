import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'CodeBuild_20161006';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CODEBUILD_RESOURCE_TYPES = ['codebuild_project'] as const;

interface ProjectDetail {
  name: string; arn?: string; description?: string; created?: number; lastModified?: number;
  source?: { type?: string }; environment?: { type?: string; image?: string; computeType?: string };
}

/** ListProjects only returns bare names — BatchGetProjects fills in the rest, capped to AWS's own 100-per-call limit so no fan-out is needed. */
export async function scanCodeBuild(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `codebuild.${ctx.region}.amazonaws.com`;
  const listResult = await callJsonApi(ctx.creds, { service: 'codebuild', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListProjects`, body: {} });
  if (!listResult.ok) {
    console.error(`CodeBuild ListProjects failed in ${ctx.region} (continuing without it): ${listResult.errorMessage ?? listResult.errorCode ?? listResult.status}`);
    return [];
  }

  const names = ((listResult.body as { projects?: string[] }).projects ?? []).slice(0, 100);
  if (names.length === 0) return [];

  const detail = await callJsonApi(ctx.creds, { service: 'codebuild', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.BatchGetProjects`, body: { names } });
  if (!detail.ok) {
    console.error(`CodeBuild BatchGetProjects failed in ${ctx.region} (continuing without it): ${detail.errorMessage ?? detail.errorCode ?? detail.status}`);
    return names.map((name) => ({ resourceTypeKey: 'codebuild_project', resourceId: name, region: ctx.region, resourceName: name }));
  }

  return ((detail.body as { projects?: ProjectDetail[] }).projects ?? []).map((p) => ({
    resourceTypeKey: 'codebuild_project', resourceId: p.arn ?? p.name, region: ctx.region, resourceName: p.name,
    metadata: {
      description: p.description, createdAt: p.created, lastModified: p.lastModified,
      sourceType: p.source?.type, environmentType: p.environment?.type, image: p.environment?.image, computeType: p.environment?.computeType,
    },
  }));
}
