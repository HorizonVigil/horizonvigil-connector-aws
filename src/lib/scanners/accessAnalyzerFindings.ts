import { createAwsClient } from '../awsApi';
import type { ScannerContext } from './types';
import type { ScannedFinding } from './findingTypes';

interface AnalyzerSummary {
  arn: string;
  type: string;
  status: 'ACTIVE' | 'CREATING' | 'DISABLED' | 'FAILED';
}
interface ListAnalyzersResponse {
  analyzers?: AnalyzerSummary[];
  nextToken?: string;
}

interface ExternalAccessDetails {
  isPublic?: boolean;
  principal?: Record<string, string>;
  action?: string[];
}
interface AccessAnalyzerFinding {
  id: string;
  resource?: string;
  resourceType?: string;
  status?: 'ACTIVE' | 'ARCHIVED' | 'RESOLVED';
  createdAt?: string;
  findingDetails?: { externalAccessDetails?: ExternalAccessDetails }[];
}
interface ListFindingsV2Response {
  findings?: AccessAnalyzerFinding[];
  nextToken?: string;
}

function describePrincipal(principal: Record<string, string> | undefined): string {
  if (!principal || Object.keys(principal).length === 0) return 'an external principal';
  return Object.entries(principal).map(([k, v]) => `${k}: ${v}`).join(', ');
}

/**
 * Only covers `type=ACCOUNT` analyzers — the classic "is this resource
 * reachable from outside my account" analyzer, and the only one of Access
 * Analyzer's six analyzer types (ACCOUNT, ORGANIZATION, *_UNUSED_ACCESS,
 * *_INTERNAL_ACCESS — a genuinely different, newer finding shape each) this
 * batch covers. ORGANIZATION and the unused-access/internal-access
 * analyzer types are a real, tracked gap, not silently skipped — they'd
 * each need their own field mapping, not a one-line addition.
 *
 * REST-JSON, like the other finding scanners. ListFindingsV2 conveniently
 * embeds findingDetails.externalAccessDetails inline per finding (confirmed
 * against AWS's API reference), so — unlike GuardDuty — no separate
 * per-finding GetFinding call is needed, keeping this to 1 ListAnalyzers +
 * up to 2 ListFindingsV2 calls per analyzer.
 *
 * Access Analyzer assigns no severity of its own. `isPublic` is a real,
 * AWS-provided signal for the worse subtype (anyone on the internet, not
 * just another AWS account, can reach this) — mapped to 'critical' vs
 * 'high' rather than inventing a score. Every finding an ACCOUNT-type
 * analyzer produces is inherently "reachable from outside your account" by
 * definition, so there's no lower tier to map here.
 */
export async function scanAccessAnalyzerFindings(ctx: ScannerContext): Promise<ScannedFinding[]> {
  const client = createAwsClient(ctx.creds, 'access-analyzer', ctx.region);
  const base = `https://access-analyzer.${ctx.region}.amazonaws.com`;

  const getJson = async (path: string): Promise<Record<string, unknown> | null> => {
    const res = await client.fetch(`${base}${path}`, { method: 'GET' });
    const text = await res.text();
    if (!res.ok) {
      console.error(`Access Analyzer GET ${path} failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };
  const postJson = async (path: string, body: unknown): Promise<Record<string, unknown> | null> => {
    const res = await client.fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const text = await res.text();
    if (!res.ok) {
      console.error(`Access Analyzer POST ${path} failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };

  const analyzerList = (await getJson('/analyzer?type=ACCOUNT')) as ListAnalyzersResponse | null;
  const analyzers = (analyzerList?.analyzers ?? []).filter((a) => a.status === 'ACTIVE');

  const out: ScannedFinding[] = [];
  for (const analyzer of analyzers) {
    let nextToken: string | undefined;
    for (let page = 0; page < 2; page++) {
      const result = (await postJson('/findingv2', { analyzerArn: analyzer.arn, maxResults: 50, nextToken })) as ListFindingsV2Response | null;
      if (!result) break;
      for (const f of result.findings ?? []) {
        if (f.status !== 'ACTIVE') continue;
        const details = f.findingDetails?.[0]?.externalAccessDetails;
        const resourceLabel = f.resourceType?.split('::').pop() ?? 'Resource';
        out.push({
          findingSource: 'iam_access_analyzer',
          awsFindingId: f.id,
          severity: details?.isPublic ? 'critical' : 'high',
          title: `${resourceLabel} is accessible from outside this account${details?.isPublic ? ' (public)' : ''}`,
          description: `Accessible by ${describePrincipal(details?.principal)}${details?.action?.length ? ` for actions: ${details.action.join(', ')}` : ''}`,
          complianceFrameworks: [],
          discoveredAt: f.createdAt ?? new Date().toISOString(),
          region: ctx.region,
          resourceArn: f.resource,
        });
      }
      nextToken = result.nextToken;
      if (!nextToken) break;
    }
  }
  return out;
}
