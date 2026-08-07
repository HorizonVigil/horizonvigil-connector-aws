import { callJsonApi } from '../awsApi';
import type { ScannerContext } from './types';
import type { ScannedFinding } from './findingTypes';

/**
 * AWS Trusted Advisor security checks, surfaced as findings — same JSON 1.1
 * (target-header) protocol as awsConfigFindings.ts, service name `support`.
 * The Support API only exists in us-east-1 regardless of which region this
 * step is nominally scanning — every call below is hardcoded there, unlike
 * every other finding scanner in this file, which uses ctx.region.
 *
 * Trusted Advisor's full check catalog needs a Business/Enterprise support
 * plan — an account on Basic/Developer support gets an access-denied style
 * error on every call here, which is an honest, common, and expected state
 * (not a real failure), so this scanner logs and returns an empty result
 * rather than throwing, same as GuardDuty/SecurityHub's per-call handling.
 *
 * UNVERIFIED against a real account with Business+ support (no such account
 * was available this session) — the request/response shapes match AWS's
 * published API reference for support:DescribeTrustedAdvisorChecks /
 * support:DescribeTrustedAdvisorCheckResult, not exercised against a live
 * response. Only the 'security' category is queried, capped to the first 5
 * checks per step, to stay inside one step's subrequest budget — Trusted
 * Advisor has 100+ checks across all categories.
 */
interface TrustedAdvisorCheck { id: string; name: string; description?: string; category: string }
interface DescribeChecksResponse { checks?: TrustedAdvisorCheck[] }

interface FlaggedResource { status?: string; resourceId?: string; isSuppressed?: boolean; metadata?: string[] }
interface CheckResult { checkId: string; status?: string; flaggedResources?: FlaggedResource[] }
interface CheckResultResponse { result?: CheckResult }

function severityFromStatus(status: string | undefined): ScannedFinding['severity'] {
  if (status === 'error') return 'high';
  if (status === 'warning') return 'medium';
  return 'informational';
}

export async function scanTrustedAdvisorFindings(ctx: ScannerContext): Promise<ScannedFinding[]> {
  const host = 'support.us-east-1.amazonaws.com';
  const call = async (target: string, body: Record<string, unknown>) =>
    callJsonApi(ctx.creds, { service: 'support', region: 'us-east-1', host, target: `AWSSupport_20130415.${target}`, body });

  const checksResult = await call('DescribeTrustedAdvisorChecks', { language: 'en' });
  if (!checksResult.ok) {
    console.error(`Trusted Advisor DescribeTrustedAdvisorChecks failed (continuing without it — likely a Basic/Developer support plan, which doesn't include Trusted Advisor's full check catalog): ${checksResult.errorMessage ?? checksResult.errorCode ?? checksResult.status}`);
    return [];
  }
  const securityChecks = ((checksResult.body as DescribeChecksResponse).checks ?? [])
    .filter((c) => c.category === 'security')
    .slice(0, 5);

  const out: ScannedFinding[] = [];
  for (const check of securityChecks) {
    const resultResponse = await call('DescribeTrustedAdvisorCheckResult', { checkId: check.id, language: 'en' });
    if (!resultResponse.ok) {
      console.error(`Trusted Advisor DescribeTrustedAdvisorCheckResult failed for check ${check.id} (continuing without it): ${resultResponse.errorMessage ?? resultResponse.errorCode}`);
      continue;
    }
    const result = (resultResponse.body as CheckResultResponse).result;
    if (!result || result.status === 'ok' || result.status === 'not_available') continue;
    for (const flagged of result.flaggedResources ?? []) {
      if (flagged.isSuppressed || !flagged.resourceId) continue;
      out.push({
        findingSource: 'trusted_advisor',
        awsFindingId: `${check.id}/${flagged.resourceId}`,
        severity: severityFromStatus(flagged.status),
        title: check.name,
        description: check.description,
        complianceFrameworks: [],
        discoveredAt: new Date().toISOString(), // Trusted Advisor doesn't report a per-resource discovery timestamp, only overall check-run time
        region: null, // Trusted Advisor findings aren't scoped to a single region
        resourceArn: flagged.resourceId,
      });
    }
  }
  return out;
}
