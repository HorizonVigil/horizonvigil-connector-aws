import { createAwsClient } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CODEARTIFACT_RESOURCE_TYPES = ['codeartifact_repository'] as const;

interface RepositorySummary { name: string; administratorAccount?: string; domainName?: string; arn?: string; description?: string }
interface ListRepositoriesResponse { repositories?: RepositorySummary[] }

/** AWS CodeArtifact — REST-JSON, confirmed against AWS's API reference (POST /v1/domains uses this exact shape; ListRepositories mirrors it at POST /v1/repositories, account-wide rather than scoped to one domain). */
export async function scanCodeArtifact(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'codeartifact', ctx.region);
  const res = await client.fetch(`https://codeartifact.${ctx.region}.amazonaws.com/v1/repositories`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
  });
  const text = await res.text();
  if (!res.ok) {
    console.error(`CodeArtifact ListRepositories failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const repos = ((text ? JSON.parse(text) : {}) as ListRepositoriesResponse).repositories ?? [];
  return repos.map((r) => ({
    resourceTypeKey: 'codeartifact_repository', resourceId: r.arn ?? `${r.domainName}/${r.name}`, region: ctx.region, resourceName: r.name,
    metadata: { description: r.description }, relationships: { domainName: r.domainName },
  }));
}
