import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const TRUSTEDADVISOR_RESOURCE_TYPES = ['trusted_advisor_check'] as const;

interface TrustedAdvisorCheck { id: string; name: string; description?: string; category: string }
interface DescribeChecksResponse { checks?: TrustedAdvisorCheck[] }
interface CheckSummary { checkId: string; status?: string; resourcesSummary?: { resourcesProcessed?: number; resourcesFlagged?: number } }
interface CheckSummariesResponse { summaries?: CheckSummary[] }

/**
 * The check definitions themselves as resources (status/flagged-count per
 * check), distinct from trustedAdvisorFindings.ts, which surfaces
 * individual flagged *resources* within the security-category checks as
 * findings. This covers the security category only, same 5-check cap and
 * same "Basic/Developer support plan" honest-empty handling as that file —
 * see its header comment for the full UNVERIFIED-against-live-data caveat,
 * which applies here identically (same host/target/support-plan gate).
 */
export async function scanTrustedAdvisorResource(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = 'support.us-east-1.amazonaws.com';
  const call = async (target: string, body: Record<string, unknown>) =>
    callJsonApi(ctx.creds, { service: 'support', region: 'us-east-1', host, target: `AWSSupport_20130415.${target}`, body });

  const checksResult = await call('DescribeTrustedAdvisorChecks', { language: 'en' });
  if (!checksResult.ok) {
    console.error(`Trusted Advisor DescribeTrustedAdvisorChecks failed (continuing without it — likely a Basic/Developer support plan): ${checksResult.errorMessage ?? checksResult.errorCode ?? checksResult.status}`);
    return [];
  }
  const securityChecks = ((checksResult.body as DescribeChecksResponse).checks ?? []).filter((c) => c.category === 'security').slice(0, 5);
  if (securityChecks.length === 0) return [];

  const summariesResult = await call('DescribeTrustedAdvisorCheckSummaries', { checkIds: securityChecks.map((c) => c.id) });
  const summaryById = new Map(
    (summariesResult.ok ? (summariesResult.body as CheckSummariesResponse).summaries : [])?.map((s) => [s.checkId, s]) ?? [],
  );

  return securityChecks.map((check) => {
    const summary = summaryById.get(check.id);
    return {
      resourceTypeKey: 'trusted_advisor_check', resourceId: check.id, region: null, resourceName: check.name,
      state: summary?.status, metadata: { description: check.description, resourcesProcessed: summary?.resourcesSummary?.resourcesProcessed, resourcesFlagged: summary?.resourcesSummary?.resourcesFlagged },
    };
  });
}
