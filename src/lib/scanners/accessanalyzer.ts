import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ACCESSANALYZER_RESOURCE_TYPES = ['access_analyzer_analyzer'] as const;

interface AnalyzerSummary {
  arn: string; name?: string; type: string; status: 'ACTIVE' | 'CREATING' | 'DISABLED' | 'FAILED';
  createdAt?: string; lastResourceAnalyzed?: string; lastResourceAnalyzedAt?: string;
}
interface ListAnalyzersResponse { analyzers?: AnalyzerSummary[] }

/**
 * The analyzer resource itself — distinct from accessAnalyzerFindings.ts,
 * which lists the *findings* an ACCOUNT-type analyzer produces. This lists
 * every analyzer regardless of type (ACCOUNT, ORGANIZATION, *_UNUSED_ACCESS,
 * *_INTERNAL_ACCESS), so an org with only an ORGANIZATION-type analyzer
 * (whose findings aren't scanned yet, a tracked gap noted in that file)
 * still shows up here as a real, existing resource.
 */
export async function scanAccessAnalyzer(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'access-analyzer', ctx.region);
  const res = await safeFetch(client, `https://access-analyzer.${ctx.region}.amazonaws.com/analyzer`, { method: 'GET' });
  const text = await res.text();
  if (!res.ok) {
    console.error(`Access Analyzer ListAnalyzers failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const analyzers = ((text ? JSON.parse(text) : {}) as ListAnalyzersResponse).analyzers ?? [];
  return analyzers.map((a) => ({
    resourceTypeKey: 'access_analyzer_analyzer', resourceId: a.arn, region: ctx.region, resourceName: a.name,
    state: a.status, metadata: { type: a.type, createdAt: a.createdAt, lastResourceAnalyzedAt: a.lastResourceAnalyzedAt },
  }));
}
