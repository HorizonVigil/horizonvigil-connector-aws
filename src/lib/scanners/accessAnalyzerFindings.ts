import { createAwsClient } from '../awsApi';
import { analyzerTypeFacts, listAllAnalyzers, type AnalyzerSummary } from './accessanalyzer';
import { fetchJson, postJson, walkPages } from './restJson';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannerContext } from './types';
import type { ScannedFinding } from './findingTypes';

/** Findings pages per analyzer (100 per page). Beyond this the scan logs that it is partial. */
const MAX_FINDING_PAGES = 10;
/** GetFindingV2 detail lookups per region for unused-access findings. */
const MAX_UNUSED_DETAIL_LOOKUPS = 25;
const DETAIL_CONCURRENCY = 4;

/**
 * v1 ListFindings summary (external-access analyzers). Carries isPublic,
 * principal and action INLINE, which is exactly what severity needs.
 */
interface FindingSummaryV1 {
  id: string;
  resource?: string;
  resourceType?: string;
  resourceOwnerAccount?: string;
  status?: 'ACTIVE' | 'ARCHIVED' | 'RESOLVED';
  isPublic?: boolean;
  principal?: Record<string, string>;
  action?: string[];
  condition?: Record<string, string>;
  createdAt?: string;
}

// Unused-access detail shapes (GetFindingV2) -- one per finding.
interface UnusedPermissionDetails { actions?: unknown[]; serviceNamespace?: string; lastAccessed?: string }
interface UnusedIamRoleDetails { lastAccessed?: string }
interface UnusedIamUserAccessKeyDetails { accessKeyId?: string; lastAccessed?: string }
interface UnusedIamUserPasswordDetails { lastAccessed?: string }
export interface FindingDetails {
  unusedPermissionDetails?: UnusedPermissionDetails;
  unusedIamRoleDetails?: UnusedIamRoleDetails;
  unusedIamUserAccessKeyDetails?: UnusedIamUserAccessKeyDetails;
  unusedIamUserPasswordDetails?: UnusedIamUserPasswordDetails;
}

/**
 * v2 ListFindingsV2 summary (unused-access analyzers). Carries `findingType`
 * but NOT `findingDetails` -- details only come from GetFindingV2.
 */
interface FindingSummaryV2 {
  id: string;
  resource?: string;
  resourceType?: string;
  resourceOwnerAccount?: string;
  status?: 'ACTIVE' | 'ARCHIVED' | 'RESOLVED';
  findingType?: string;
  createdAt?: string;
  /** Present only if AWS ever inlines it; used when it does. */
  findingDetails?: FindingDetails[];
}

function describePrincipal(principal: Record<string, string> | undefined): string {
  if (!principal || Object.keys(principal).length === 0) return 'an external principal';
  return Object.entries(principal).map(([k, v]) => `${k}: ${v}`).join(', ');
}

/** Title/description for an unused-access finding from its detail block. */
export function describeUnusedAccess(details: FindingDetails, resourceLabel: string): { title: string; description: string } | null {
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
 * Title/description from `findingType` alone -- used when details could not
 * be fetched, so a real finding is never dropped for want of its details.
 */
export function describeUnusedByType(findingType: string | undefined, resourceLabel: string): { title: string; description: string } | null {
  switch (findingType) {
    case 'UnusedIAMRole': return { title: `Unused IAM role: ${resourceLabel}`, description: 'This role has not been assumed within the analyzer\'s unused-access window.' };
    case 'UnusedIAMUserAccessKey': return { title: `Unused IAM access key on ${resourceLabel}`, description: 'An access key has not been used within the analyzer\'s unused-access window.' };
    case 'UnusedIAMUserPassword': return { title: `Unused IAM console password on ${resourceLabel}`, description: 'The console password has not been used within the analyzer\'s unused-access window.' };
    case 'UnusedPermission': return { title: `Unused permissions on ${resourceLabel}`, description: 'This identity holds permissions it has not used within the analyzer\'s unused-access window.' };
    default: return null;
  }
}

const labelOf = (resourceType: string | undefined, fallback?: string) => resourceType?.split('::').pop() ?? fallback ?? 'Resource';

/**
 * IAM Access Analyzer findings.
 *
 * What changed, and why:
 *
 *  - Unused-access findings were NEVER collected. The analyzer lookup asked
 *    for `type=UNUSED_ACCESS`, which is not an analyzer type (the real ones
 *    are ACCOUNT_UNUSED_ACCESS / ORGANIZATION_UNUSED_ACCESS), so it returned
 *    a validation error and the branch silently did nothing.
 *
 *  - External-access severity was always 'high'. ListFindingsV2 returns
 *    summaries WITHOUT findingDetails, so `isPublic` was always undefined.
 *    External-access findings now come from v1 ListFindings, whose summary
 *    carries isPublic/principal/action inline -- public exposure is
 *    'critical' again. Unused-access findings come from ListFindingsV2 and
 *    are titled from `findingType`, enriched from GetFindingV2 where budget
 *    allows, so none are dropped for missing details.
 *
 *  - ORGANIZATION analyzers are included. An analyzer this account can list
 *    is one this account owns (management account or delegated admin), and
 *    its findings are readable with these same credentials.
 *
 *  - Only ACTIVE findings are requested (server-side filter), and paging goes
 *    to MAX_FINDING_PAGES instead of stopping at 100 findings.
 *
 * Access Analyzer assigns no severity. `isPublic` is AWS's own signal for the
 * worse subtype, mapped critical vs high rather than inventing a score.
 * Internal-access analyzers are not yet mapped (a separate finding category).
 */
export async function scanAccessAnalyzerFindings(ctx: ScannerContext): Promise<ScannedFinding[]> {
  const client = createAwsClient(ctx.creds, 'access-analyzer', ctx.region);
  const base = `https://access-analyzer.${ctx.region}.amazonaws.com`;

  const analyzersWalk = await listAllAnalyzers(ctx);
  if (!analyzersWalk.complete) {
    console.error(`Access Analyzer ListAnalyzers ${analyzersWalk.firstPageFailed ? 'failed' : 'was incomplete'} in ${ctx.region}: ${analyzersWalk.error ?? ''}`);
  }
  const active = analyzersWalk.items.filter((a): a is AnalyzerSummary => !!a?.arn && a.status === 'ACTIVE');
  const external = active.filter((a) => analyzerTypeFacts(a.type ?? '').kind === 'external_access');
  const unused = active.filter((a) => analyzerTypeFacts(a.type ?? '').kind === 'unused_access');

  const out: ScannedFinding[] = [];
  const seen = new Set<string>();
  const push = (f: ScannedFinding) => {
    if (seen.has(f.awsFindingId)) return;
    seen.add(f.awsFindingId);
    out.push(f);
  };
  const activeOnly = { status: { eq: ['ACTIVE'] } };

  // ── External access (v1 ListFindings: details inline) ──────────────────────
  for (const analyzer of external) {
    const walk = await walkPages<FindingSummaryV1>(
      (token) => postJson(client, `${base}/finding`, { analyzerArn: analyzer.arn, filter: activeOnly, maxResults: 100, ...(token ? { nextToken: token } : {}) }),
      (b) => b.findings,
      (b) => b.nextToken,
      MAX_FINDING_PAGES,
    );
    if (!walk.complete) console.error(`Access Analyzer ListFindings for ${analyzer.name ?? analyzer.arn} in ${ctx.region} is partial: ${walk.error ?? ''}`);

    for (const f of walk.items) {
      if (!f?.id || (f.status && f.status !== 'ACTIVE')) continue;
      const label = labelOf(f.resourceType);
      const actions = Array.isArray(f.action) ? f.action : [];
      push({
        findingSource: 'iam_access_analyzer',
        awsFindingId: f.id,
        severity: f.isPublic ? 'critical' : 'high',
        title: `${label} is accessible from outside this ${analyzerTypeFacts(analyzer.type).scope === 'organization' ? 'organization' : 'account'}${f.isPublic ? ' (public)' : ''}`,
        description: `Accessible by ${describePrincipal(f.principal)}${actions.length ? ` for actions: ${actions.join(', ')}` : ''}` +
          `${f.condition && Object.keys(f.condition).length ? ` (conditions: ${Object.keys(f.condition).join(', ')})` : ''}` +
          `${f.resourceOwnerAccount ? `. Resource owner: ${f.resourceOwnerAccount}` : ''}`,
        complianceFrameworks: [],
        discoveredAt: f.createdAt ?? new Date().toISOString(),
        region: ctx.region,
        resourceArn: f.resource,
      });
    }
  }

  // ── Unused access (ListFindingsV2 + bounded GetFindingV2) ──────────────────
  const unusedFindings: { analyzer: AnalyzerSummary; f: FindingSummaryV2 }[] = [];
  for (const analyzer of unused) {
    const walk = await walkPages<FindingSummaryV2>(
      (token) => postJson(client, `${base}/findingv2`, { analyzerArn: analyzer.arn, filter: activeOnly, maxResults: 100, ...(token ? { nextToken: token } : {}) }),
      (b) => b.findings,
      (b) => b.nextToken,
      MAX_FINDING_PAGES,
    );
    if (!walk.complete) console.error(`Access Analyzer ListFindingsV2 for ${analyzer.name ?? analyzer.arn} in ${ctx.region} is partial: ${walk.error ?? ''}`);
    for (const f of walk.items) {
      if (f?.id && (!f.status || f.status === 'ACTIVE')) unusedFindings.push({ analyzer, f });
    }
  }

  const details = new Map<string, FindingDetails>();
  const needDetails = unusedFindings.filter(({ f }) => !f.findingDetails?.length).slice(0, MAX_UNUSED_DETAIL_LOOKUPS);
  await mapWithConcurrency(needDetails, DETAIL_CONCURRENCY, async ({ analyzer, f }) => {
    const res = await fetchJson(client, `${base}/findingv2/${encodeURIComponent(f.id)}?analyzerArn=${encodeURIComponent(analyzer.arn)}`);
    const list = res.ok ? res.body?.findingDetails : undefined;
    if (Array.isArray(list) && list[0] && typeof list[0] === 'object') details.set(f.id, list[0] as FindingDetails);
  });

  for (const { f } of unusedFindings) {
    const label = labelOf(f.resourceType, f.resource);
    const detail = f.findingDetails?.[0] ?? details.get(f.id);
    const described = (detail ? describeUnusedAccess(detail, label) : null) ?? describeUnusedByType(f.findingType, label);
    if (!described) {
      // An unrecognized finding type: degrade by skipping this one, not the scan.
      console.error(`Access Analyzer: unrecognized unused-access finding type '${f.findingType ?? 'unknown'}' (${f.id}) in ${ctx.region}.`);
      continue;
    }
    push({
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
  }

  return out;
}