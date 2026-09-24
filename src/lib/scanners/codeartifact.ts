import { createAwsClient } from '../awsApi';
import { accountIdFromArn, summarizePolicy } from './policyEvidence';
import { fetchJson, postJson, reportWalk, walkPages } from './restJson';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CODEARTIFACT_RESOURCE_TYPES = ['codeartifact_repository'] as const;

/** Repository permission-policy lookups per region. */
const MAX_POLICY_LOOKUPS = 25;

interface RepositorySummary {
  name: string; administratorAccount?: string; domainName?: string; domainOwner?: string; arn?: string; description?: string; createdTime?: number | string;
}
interface DomainSummary { name?: string; owner?: string; arn?: string; status?: string; encryptionKey?: string }

/**
 * AWS CodeArtifact (REST-JSON). ListRepositories is account-wide at POST
 * /v1/repositories; CodeArtifact is not in every region, and a transport
 * failure there is handled by the shared helper.
 *
 * What changed, and why:
 *  - ListRepositories paginates (nextToken). Previously page one only.
 *  - A failed list is reported instead of returned as [], and the body is
 *    parsed defensively.
 *  - Supply-chain evidence: each repository's resource policy (anonymous or
 *    cross-account access to packages), and its domain's KMS key.
 */
export async function scanCodeArtifact(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'codeartifact', ctx.region);
  const base = `https://codeartifact.${ctx.region}.amazonaws.com`;

  const [repos, domains] = await Promise.all([
    walkPages<RepositorySummary>(
      (token) => postJson(client, `${base}/v1/repositories`, { maxResults: 1000, ...(token ? { nextToken: token } : {}) }),
      (b) => b.repositories,
      (b) => b.nextToken,
    ),
    walkPages<DomainSummary>(
      (token) => postJson(client, `${base}/v1/domains`, { maxResults: 1000, ...(token ? { nextToken: token } : {}) }),
      (b) => b.domains,
      (b) => b.nextToken,
    ),
  ]);
  reportWalk(ctx, repos, 'codeartifact', 'ListRepositories');
  const domainKeys = new Map(domains.items.filter((d) => d?.name).map((d) => [`${d.owner ?? ''}/${d.name}`, d.encryptionKey ?? null]));

  const list = repos.items.filter((r) => !!r?.name);
  const policies = new Map<string, ReturnType<typeof summarizePolicy> | 'none' | null>();
  await mapWithConcurrency(list.slice(0, MAX_POLICY_LOOKUPS), 4, async (r) => {
    if (!r.domainName) return;
    const q = new URLSearchParams({ domain: r.domainName, repository: r.name, ...(r.domainOwner ? { 'domain-owner': r.domainOwner } : {}) });
    const res = await fetchJson(client, `${base}/v1/repository/permissions/policy?${q.toString()}`);
    const key = r.arn ?? `${r.domainName}/${r.name}`;
    if (res.ok) {
      const doc = (res.body?.policy as { document?: string } | undefined)?.document;
      policies.set(key, summarizePolicy(doc, accountIdFromArn(r.arn) ?? r.domainOwner ?? null));
    } else {
      policies.set(key, res.status === 404 ? 'none' : null);
    }
  });

  return list.map((r) => {
    const id = r.arn ?? `${r.domainName}/${r.name}`;
    const policy = policies.get(id);
    return {
      resourceTypeKey: 'codeartifact_repository', resourceId: id, region: ctx.region, resourceName: r.name,
      metadata: {
        description: r.description,
        administratorAccount: r.administratorAccount ?? null,
        domainOwner: r.domainOwner ?? null,
        createdTime: r.createdTime ?? null,
        domainEncryptionKey: domainKeys.get(`${r.domainOwner ?? ''}/${r.domainName}`) ?? null,
        policyCollected: policy !== undefined && policy !== null,
        hasResourcePolicy: policy === undefined || policy === null ? null : policy !== 'none',
        resourcePolicy: policy && policy !== 'none' ? policy : null,
      },
      relationships: { domainName: r.domainName },
    };
  });
}