import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CODECOMMIT_RESOURCE_TYPES = ['codecommit_repository'] as const;

interface RepositoryNameIdPair { repositoryName: string; repositoryId: string }
interface ListRepositoriesResponse { repositories?: RepositoryNameIdPair[] }
interface RepositoryMetadata { repositoryId: string; repositoryName?: string; Arn?: string; cloneUrlHttp?: string; defaultBranch?: string }
interface BatchGetRepositoriesResponse { repositories?: RepositoryMetadata[] }

export async function scanCodeCommit(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `codecommit.${ctx.region}.amazonaws.com`;
  const call = async (target: string, body: Record<string, unknown> = {}) =>
    callJsonApi(ctx.creds, { service: 'codecommit', region: ctx.region, host, target: `CodeCommit_20150413.${target}`, body });

  const listResult = await call('ListRepositories');
  if (!listResult.ok) {
    console.error(`CodeCommit ListRepositories failed in ${ctx.region} (continuing without it): ${listResult.errorMessage ?? listResult.errorCode ?? listResult.status}`);
    return [];
  }
  const repoNames = ((listResult.body as ListRepositoriesResponse).repositories ?? []).map((r) => r.repositoryName);
  if (repoNames.length === 0) return [];

  const detailResult = await call('BatchGetRepositories', { repositoryNames: repoNames.slice(0, 25) });
  if (!detailResult.ok) {
    console.error(`CodeCommit BatchGetRepositories failed in ${ctx.region} (continuing without it): ${detailResult.errorMessage ?? detailResult.errorCode ?? detailResult.status}`);
    return [];
  }

  const repos = (detailResult.body as BatchGetRepositoriesResponse).repositories ?? [];
  return repos.map((r) => ({
    resourceTypeKey: 'codecommit_repository', resourceId: r.Arn ?? r.repositoryId, region: ctx.region, resourceName: r.repositoryName,
    metadata: { cloneUrlHttp: r.cloneUrlHttp, defaultBranch: r.defaultBranch },
  }));
}
