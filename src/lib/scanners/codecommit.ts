import { callJsonApi } from '../awsApi';
import { reportWalk, toIso, walkJsonRpc } from './restJson';
import { mapWithConcurrency, reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CODECOMMIT_RESOURCE_TYPES = ['codecommit_repository'] as const;

const TARGET_PREFIX = 'CodeCommit_20150413';
/** BatchGetRepositories accepts at most 25 names per call. */
const BATCH_SIZE = 25;

interface RepositoryNameIdPair { repositoryName: string; repositoryId: string }
interface RepositoryMetadata {
  repositoryId: string; repositoryName?: string; Arn?: string; cloneUrlHttp?: string; defaultBranch?: string;
  accountId?: string; creationDate?: number; lastModifiedDate?: number; kmsKeyId?: string; repositoryDescription?: string;
}

const chunk = <T>(xs: T[], n: number): T[][] => Array.from({ length: Math.ceil(xs.length / n) }, (_, i) => xs.slice(i * n, i * n + n));

/**
 * CodeCommit repositories (JSON-RPC, CodeCommit_20150413).
 *
 * What changed, and why:
 *  - ListRepositories paginates (nextToken), and BatchGetRepositories runs in
 *    chunks of 25. The previous version silently kept the first 25 repos.
 *  - A failed detail batch used to return [] for the WHOLE scan. It now
 *    reports that batch and keeps the others; rows are not synthesized for
 *    it, because the list only carries ids and existing rows are keyed on
 *    the ARN -- a different id would read as delete + create.
 *  - Each repository records its KMS key (customer-managed vs AWS-owned).
 */
export async function scanCodeCommit(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `codecommit.${ctx.region}.amazonaws.com`;
  const list = await walkJsonRpc<RepositoryNameIdPair>(ctx, { service: 'codecommit', host, target: `${TARGET_PREFIX}.ListRepositories`, body: {} }, 'repositories', { tokenIn: 'nextToken', tokenOut: 'nextToken' });
  reportWalk(ctx, list, 'codecommit', 'ListRepositories');
  const names = [...new Set(list.items.map((r) => r?.repositoryName).filter((n): n is string => !!n))];
  if (names.length === 0) return [];

  const batches = await mapWithConcurrency(chunk(names, BATCH_SIZE), 3, async (batch) => {
    const r = await callJsonApi(ctx.creds, { service: 'codecommit', region: ctx.region, host, target: `${TARGET_PREFIX}.BatchGetRepositories`, body: { repositoryNames: batch } });
    return r.ok ? ((r.body as { repositories?: RepositoryMetadata[] })?.repositories ?? []) : null;
  });
  if (batches.some((b) => b === null)) {
    console.error(`CodeCommit BatchGetRepositories failed for some repositories in ${ctx.region}; coverage degraded.`);
    reportListingFailure(ctx, { service: 'codecommit', action: 'BatchGetRepositories', region: ctx.region });
  }

  const out: ScannedResource[] = [];
  for (const repos of batches) {
    for (const r of repos ?? []) {
      if (!r?.repositoryId) continue;
      out.push({
        resourceTypeKey: 'codecommit_repository', resourceId: r.Arn ?? r.repositoryId, region: ctx.region, resourceName: r.repositoryName,
        metadata: {
          cloneUrlHttp: r.cloneUrlHttp, defaultBranch: r.defaultBranch,
          description: r.repositoryDescription ?? null,
          createdAtIso: toIso(r.creationDate), lastModifiedIso: toIso(r.lastModifiedDate),
          kmsKeyId: r.kmsKeyId ?? null,
          customerManagedKms: !!r.kmsKeyId && !r.kmsKeyId.includes('alias/aws/codecommit'),
        },
      });
    }
  }
  return out;
}