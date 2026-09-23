import { createAwsClient } from '../awsApi';
import { fetchJson, reportWalk, walkPages } from './restJson';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ACCESSANALYZER_RESOURCE_TYPES = ['access_analyzer_analyzer'] as const;

export interface AnalyzerSummary {
  arn: string;
  name?: string;
  type: string;
  status: 'ACTIVE' | 'CREATING' | 'DISABLED' | 'FAILED' | string;
  statusReason?: { code?: string };
  createdAt?: string;
  lastResourceAnalyzed?: string;
  lastResourceAnalyzedAt?: string;
  configuration?: { unusedAccess?: { unusedAccessAge?: number } };
  tags?: Record<string, string>;
}

/** What an analyzer type covers. AWS's six types are the cross product of these two axes. */
export function analyzerTypeFacts(type: string) {
  return {
    scope: type.startsWith('ORGANIZATION') ? 'organization' : 'account',
    kind: type.endsWith('UNUSED_ACCESS') ? 'unused_access' : type.endsWith('INTERNAL_ACCESS') ? 'internal_access' : 'external_access',
  } as const;
}

/**
 * Every ListAnalyzers page for this region. Shared with
 * accessAnalyzerFindings.ts so both read the same analyzer set.
 */
export async function listAllAnalyzers(ctx: ScannerContext) {
  const client = createAwsClient(ctx.creds, 'access-analyzer', ctx.region);
  const base = `https://access-analyzer.${ctx.region}.amazonaws.com`;
  return walkPages<AnalyzerSummary>(
    (token) => fetchJson(client, `${base}/analyzer?maxResults=100${token ? `&nextToken=${encodeURIComponent(token)}` : ''}`),
    (b) => b.analyzers,
    (b) => b.nextToken,
  );
}

/**
 * The analyzer resources themselves — distinct from accessAnalyzerFindings.ts,
 * which lists the findings they produce. Every type is listed (ACCOUNT,
 * ORGANIZATION, *_UNUSED_ACCESS, *_INTERNAL_ACCESS).
 *
 * CIS 1.20 asks for an ACTIVE external-access analyzer in every region; the
 * `kind`/`scope` facts below let posture answer that from inventory alone.
 * Now paginated, and a failed list is REPORTED rather than returned as [],
 * which finalize would have read as "every analyzer was deleted".
 */
export async function scanAccessAnalyzer(ctx: ScannerContext): Promise<ScannedResource[]> {
  const walk = await listAllAnalyzers(ctx);
  reportWalk(ctx, walk, 'access-analyzer', 'ListAnalyzers');

  return walk.items
    .filter((a) => typeof a?.arn === 'string' && a.arn !== '')
    .map((a) => {
      const facts = analyzerTypeFacts(a.type ?? '');
      return {
        resourceTypeKey: 'access_analyzer_analyzer',
        resourceId: a.arn,
        region: ctx.region,
        resourceName: a.name,
        state: a.status,
        tags: a.tags,
        metadata: {
          type: a.type,
          scope: facts.scope,
          analyzerKind: facts.kind,
          active: a.status === 'ACTIVE',
          statusReason: a.statusReason?.code ?? null,
          createdAt: a.createdAt,
          lastResourceAnalyzedAt: a.lastResourceAnalyzedAt,
          unusedAccessAgeDays: a.configuration?.unusedAccess?.unusedAccessAge ?? null,
        },
      };
    });
}