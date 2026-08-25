import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannerContext } from './types';
import type { ScannedFinding } from './findingTypes';

interface SecurityHubFinding {
  Id: string;
  Title?: string;
  Description?: string;
  CreatedAt?: string;
  Region?: string;
  Severity?: { Label?: string; Normalized?: number };
  Remediation?: { Recommendation?: { Url?: string } };
  Compliance?: { RelatedRequirements?: string[] };
  Resources?: { Id?: string }[];
  RecordState?: string;
}

interface GetFindingsResponse {
  Findings?: SecurityHubFinding[];
  NextToken?: string;
}

/** Security Hub's Severity.Label already matches our severity column's exact vocabulary (INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL) — just needs lowercasing, no bucketing like GuardDuty's raw score needs. */
function mapSeverity(label: string | undefined): ScannedFinding['severity'] {
  const lower = label?.toLowerCase();
  if (lower === 'critical' || lower === 'high' || lower === 'medium' || lower === 'low' || lower === 'informational') return lower;
  return 'informational';
}

/**
 * GetFindings is REST-JSON (POST /findings), like securityhub.ts's hub scan.
 * Filtered server-side to RecordState=ACTIVE so archived findings (a
 * finding whose underlying issue Security Hub itself considers gone) are
 * never ingested — same reasoning as GuardDuty's Service.Archived skip.
 * Capped at 2 pages / 200 findings (Security Hub allows up to 100 per
 * page) to stay inside one step's subrequest budget; a larger backlog
 * catches up over repeated scans via last_seen_at, same as GuardDuty's.
 */
export async function scanSecurityHubFindings(ctx: ScannerContext): Promise<ScannedFinding[]> {
  const client = createAwsClient(ctx.creds, 'securityhub', ctx.region);
  const base = `https://securityhub.${ctx.region}.amazonaws.com`;

  const postJson = async (body: Record<string, unknown>): Promise<GetFindingsResponse | null> => {
    const res = await safeFetch(client, `${base}/findings`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const text = await res.text();
    if (!res.ok) {
      console.error(`Security Hub GetFindings failed in ${ctx.region} (continuing without it — likely just not enabled there): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as GetFindingsResponse) : {};
  };

  const out: ScannedFinding[] = [];
  let nextToken: string | undefined;
  for (let page = 0; page < 2; page++) {
    const result = await postJson({
      Filters: { RecordState: [{ Comparison: 'EQUALS', Value: 'ACTIVE' }] },
      MaxResults: 100,
      NextToken: nextToken,
    });
    if (!result) break;
    for (const f of result.Findings ?? []) {
      out.push({
        findingSource: 'security_hub',
        awsFindingId: f.Id,
        severity: mapSeverity(f.Severity?.Label),
        cvssScore: f.Severity?.Normalized !== undefined ? f.Severity.Normalized / 10 : undefined,
        title: f.Title ?? 'Security Hub finding',
        description: f.Description,
        complianceFrameworks: f.Compliance?.RelatedRequirements ?? [],
        remediationLink: f.Remediation?.Recommendation?.Url,
        discoveredAt: f.CreatedAt ?? new Date().toISOString(),
        region: f.Region ?? ctx.region,
        resourceArn: f.Resources?.[0]?.Id,
      });
    }
    nextToken = result.NextToken;
    if (!nextToken) break;
  }
  return out;
}
