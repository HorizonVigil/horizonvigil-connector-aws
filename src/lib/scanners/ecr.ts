import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AmazonEC2ContainerRegistry_V20150921';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ECR_RESOURCE_TYPES = ['ecr_repository', 'ecr_image'] as const;

interface EcrRepository {
  repositoryArn?: string; repositoryName: string; repositoryUri?: string; createdAt?: number;
  imageTagMutability?: string; imageScanningConfiguration?: { scanOnPush?: boolean };
  encryptionConfiguration?: { encryptionType?: string };
}

interface EcrImageDetail {
  imageDigest?: string; imageTags?: string[]; imageSizeInBytes?: number; imagePushedAt?: number; artifactMediaType?: string;
}

/** DescribeRepositories — one JSON-RPC call — then, per repository, DescribeImages for a bounded image inventory. */
export async function scanEcr(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `api.ecr.${ctx.region}.amazonaws.com`;
  const call = async (action: string, body: Record<string, unknown>) => {
    const result = await callJsonApi(ctx.creds, { service: 'ecr', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.${action}`, body });
    if (!result.ok) {
      console.error(`ECR ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return null;
    }
    return result.body as Record<string, unknown>;
  };

  const out: ScannedResource[] = [];
  const listResult = await call('DescribeRepositories', {});
  const repos = (listResult?.repositories as EcrRepository[] | undefined) ?? [];
  for (const r of repos) {
    out.push({
      resourceTypeKey: 'ecr_repository', resourceId: r.repositoryArn ?? r.repositoryName, region: ctx.region, resourceName: r.repositoryName,
      metadata: {
        repositoryUri: r.repositoryUri, createdAt: r.createdAt, imageTagMutability: r.imageTagMutability,
        scanOnPush: r.imageScanningConfiguration?.scanOnPush, encryptionType: r.encryptionConfiguration?.encryptionType,
      },
    });
  }

  // Images are listed per-repository, not account-wide — capped to the
  // first 10 repos and 25 images each to stay well inside Cloudflare's
  // free-tier ~50-subrequest budget for one invocation.
  for (const r of repos.slice(0, 10)) {
    const imagesResult = await call('DescribeImages', { repositoryName: r.repositoryName, maxResults: 25 });
    for (const img of (imagesResult?.imageDetails as EcrImageDetail[] | undefined) ?? []) {
      if (!img.imageDigest) continue;
      const tag = img.imageTags?.[0];
      out.push({
        resourceTypeKey: 'ecr_image', resourceId: `${r.repositoryName}@${img.imageDigest}`, region: ctx.region,
        resourceName: tag ? `${r.repositoryName}:${tag}` : img.imageDigest,
        metadata: { tags: img.imageTags, sizeBytes: img.imageSizeInBytes, pushedAt: img.imagePushedAt, mediaType: img.artifactMediaType },
        relationships: { repositoryName: r.repositoryName },
      });
    }
  }

  return out;
}
