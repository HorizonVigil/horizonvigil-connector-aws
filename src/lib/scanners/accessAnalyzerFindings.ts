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
// UNUSED_ACCESS finding detail shapes -- one of these four is present
// depending on what the analyzer flagged, never more than one per finding.
interface UnusedPermissionDetails { actions?: string[]; serviceNamespace?: string; lastAccessed?: string }
interface UnusedIamRoleDetails { lastAccessed?: string }
interface UnusedIamUserAccessKeyDetails { accessKeyId?: string; lastAccessed?: string }
interface UnusedIamUserPasswordDetails { lastAccessed?: string }
interface FindingDetails {
  externalAccessDetails?: ExternalAccessDetails;
  unusedPermissionDetails?: UnusedPermissionDetails;
  unusedIamRoleDetails?: UnusedIamRoleDetails;
  unusedIamUserAccessKeyDetails?: UnusedIamUserAccessKeyDetails;
  unusedIamUserPasswordDetails?: UnusedIamUserPasswordDetails;
}
interface AccessAnalyzerFinding {
  id: string;
  resource?: string;
  resourceType?: string;
  status?: 'ACTIVE' | 'ARCHIVED' | 'RESOLVED';
  createdAt?: string;
  findingDetails?: FindingDetails[];
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
 * UNVERIFIED against a real account with an active UNUSED_ACCESS analyzer
 * (none was available this session -- same caveat inspectorFindings.ts
 * already carries for the same reason). Shape matches AWS's published
 * ListFindingsV2 reference for unused-access finding detail types, not yet
 * exercised against a live response -- if AWS's actual field names differ,
 * this degrades to the generic fallback title below rather than throwing,
 * same "never crash on an unexpected shape" convention as everywhere else
 * in this file.
 */
function describeUnusedAccess(details: FindingDetails, resourceLabel: string): { title: string; description: string } | null {
  if (details.unusedIamUserAccessKeyDetails) {
    const d = details.unusedIamUserAccessKeyDetails;
    return {
      title: `Unused IAM access key on ${resourceLabel}`,
      description: `Access key ${d.accessKeyId ?? '(unknown)'} has not been used${d.lastAccessed ? ` since ${d.lastAccessed}` : ', ever'}.`,
    };
  }
  if (details.unusedIamUserPasswordDetails) {
    const d = details.unusedIamUserPasswordDetails;
    return {
      title: `Unused IAM console password on ${resourceLabel}`,
      description: `Console password has not been used${d.lastAccessed ? ` since ${d.lastAccessed}` : ', ever'}.`,
    };
  }
  if (details.unusedIamRoleDetails) {
    const d = details.unusedIamRoleDetails;
    return {
      title: `Unused IAM role: ${resourceLabel}`,
      description: `This role has not been assumed${d.lastAccessed ? ` since ${d.lastAccessed}` : ', ever'}.`,
    };
  }
  if (details.unusedPermissionDetails) {
    const d = details.unusedPermissionDetails;
    return {
      title: `Unused permissions on ${resourceLabel}`,
      description: `${d.actions?.length ? `${d.actions.length} unused action(s)` : 'Unused permissions'} in ${d.serviceNamespace ?? 'a service'}${d.lastAccessed ? `, last accessed ${d.lastAccessed}` : ', never used'}.`,
    };
  }
  return null;
}

/**
 * Covers `type=ACCOUNT` (external-access) and `type=UNUSED_ACCESS`
 * analyzers — the two of Access Analyzer's four analyzer types (ACCOUNT,
 * ORGANIZATION, ACCOUNT_UNUSED_ACCESS, ORGANIZATION_UNUSED_ACCESS) most
 * relevant outside an AWS Organizations management account. ORGANIZATION
 * and ORGANIZATION_UNUSED_ACCESS remain a real, tracked gap, not silently
 * skipped — organization-wide analyzers need org-level credentials this
 * per-account scanner doesn't have.
 *
 * Unused-access findings (over-permissioned/unused roles, users, access
 * keys, passwords -- the "non-human identity" risk this analyzer type is
 * purpose-built for) get their own finding_source, iam_access_analyzer_unused,
 * so they're distinguishable from the external-access findings below that
 * feed the attack-path correlation engine's exposure leg -- an unused
 * permission alone isn't "exposed," it's a different risk category.
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

  // Shared ListAnalyzers + paginated ListFindingsV2 walk for one analyzer
  // `type` -- ACCOUNT and UNUSED_ACCESS each need their own analyzer lookup
  // (a customer creates each type separately; having one doesn't imply the
  // other exists) but otherwise page through findings identically.
  const scanAnalyzerType = async (type: string, processFinding: (f: AccessAnalyzerFinding) => void): Promise<void> => {
    const analyzerList = (await getJson(`/analyzer?type=${type}`)) as ListAnalyzersResponse | null;
    const analyzers = (analyzerList?.analyzers ?? []).filter((a) => a.status === 'ACTIVE');
    for (const analyzer of analyzers) {
      let nextToken: string | undefined;
      for (let page = 0; page < 2; page++) {
        const result = (await postJson('/findingv2', { analyzerArn: analyzer.arn, maxResults: 50, nextToken })) as ListFindingsV2Response | null;
        if (!result) break;
        for (const f of result.findings ?? []) {
          if (f.status !== 'ACTIVE') continue;
          processFinding(f);
        }
        nextToken = result.nextToken;
        if (!nextToken) break;
      }
    }
  };

  const out: ScannedFinding[] = [];

  await scanAnalyzerType('ACCOUNT', (f) => {
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
  });

  await scanAnalyzerType('UNUSED_ACCESS', (f) => {
    const detailEntry = f.findingDetails?.[0];
    if (!detailEntry) return;
    const resourceLabel = f.resourceType?.split('::').pop() ?? f.resource ?? 'Resource';
    const described = describeUnusedAccess(detailEntry, resourceLabel);
    if (!described) return; // an unrecognized detail shape -- degrade by skipping this one finding, not the whole scan
    out.push({
      findingSource: 'iam_access_analyzer_unused',
      awsFindingId: f.id,
      severity: 'medium',
      title: described.title,
      description: described.description,
      complianceFrameworks: [],
      discoveredAt: f.createdAt ?? new Date().toISOString(),
      region: ctx.region,
      resourceArn: f.resource,
    });
  });

  return out;
}
