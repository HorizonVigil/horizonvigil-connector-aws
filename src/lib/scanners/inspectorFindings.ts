import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannerContext } from './types';
import type { ScannedFinding } from './findingTypes';

/**
 * Amazon Inspector v2 findings — REST-JSON (POST /findings/list), same
 * request shape family as GuardDuty/SecurityHub's own findings APIs.
 *
 * UNVERIFIED against a real AWS account with Inspector enabled (no test
 * account had it active during this session, unlike GuardDuty/SecurityHub/
 * IAM Access Analyzer which were confirmed against real findings earlier).
 * The request/response shape below matches AWS's published API reference
 * for inspector2:ListFindings, but hasn't been exercised against a live
 * response the way this codebase's other finding scanners have — treat
 * with the same caution as gkeWorkloads.ts's "not yet verified" scanner
 * until it's run against a real account and checked.
 */
interface InspectorResource { id?: string; type?: string }
interface InspectorCvss { baseScore?: number }
interface InspectorPackageVulnDetails { vulnerabilityId?: string; cvss?: InspectorCvss[] }
interface InspectorRemediation { recommendation?: { text?: string; url?: string } }
interface InspectorFinding {
  findingArn: string;
  title?: string;
  description?: string;
  severity?: string;
  status?: string;
  firstObservedAt?: string;
  type?: string;
  resources?: InspectorResource[];
  packageVulnerabilityDetails?: InspectorPackageVulnDetails;
  remediation?: InspectorRemediation;
}
interface ListFindingsResponse { findings?: InspectorFinding[]; nextToken?: string }

function mapSeverity(sev: string | undefined): ScannedFinding['severity'] {
  const lower = sev?.toLowerCase();
  if (lower === 'critical' || lower === 'high' || lower === 'medium' || lower === 'low' || lower === 'informational') return lower;
  return 'informational'; // covers Inspector's UNTRIAGED state, which has no equivalent in our vocabulary
}

export async function scanInspectorFindings(ctx: ScannerContext): Promise<ScannedFinding[]> {
  const client = createAwsClient(ctx.creds, 'inspector2', ctx.region);
  const base = `https://inspector2.${ctx.region}.amazonaws.com`;

  const postJson = async (body: Record<string, unknown>): Promise<ListFindingsResponse | null> => {
    const res = await safeFetch(client, `${base}/findings/list`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const text = await res.text();
    if (!res.ok) {
      // Inspector not activated for this account/region is the common,
      // honest-empty case (AccessDeniedException with a
      // "account is not enrolled" style message) — logged, not thrown,
      // matching every other optional-service scanner in this file.
      console.error(`Inspector2 ListFindings failed in ${ctx.region} (continuing without it — likely just not enabled there): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as ListFindingsResponse) : {};
  };

  const out: ScannedFinding[] = [];
  let nextToken: string | undefined;
  for (let page = 0; page < 2; page++) {
    const result = await postJson({
      filterCriteria: { findingStatus: [{ comparison: 'EQUALS', value: 'ACTIVE' }] },
      maxResults: 100,
      nextToken,
    });
    if (!result) break;
    for (const f of result.findings ?? []) {
      out.push({
        findingSource: 'inspector',
        awsFindingId: f.findingArn,
        severity: mapSeverity(f.severity),
        cvssScore: f.packageVulnerabilityDetails?.cvss?.[0]?.baseScore,
        title: f.title ?? f.packageVulnerabilityDetails?.vulnerabilityId ?? 'Inspector finding',
        description: f.description,
        complianceFrameworks: [],
        remediationLink: f.remediation?.recommendation?.url,
        discoveredAt: f.firstObservedAt ?? new Date().toISOString(),
        region: ctx.region,
        resourceArn: f.resources?.[0]?.id,
      });
    }
    nextToken = result.nextToken;
    if (!nextToken) break;
  }
  return out;
}
