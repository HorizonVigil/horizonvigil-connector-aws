import { callJsonApi } from '../awsApi';
import type { ScannerContext } from './types';
import type { ScannedFinding } from './findingTypes';

/**
 * AWS Config non-compliant rule evaluations, surfaced as findings — Config
 * itself is the older JSON 1.1 (target-header) protocol, like CloudTrail/
 * DynamoDB elsewhere in this codebase, not the REST-JSON path-based style
 * GuardDuty/SecurityHub/Inspector use.
 *
 * UNVERIFIED against a real account with AWS Config rules configured (same
 * caveat as inspectorFindings.ts — request/response shapes match AWS's
 * published API reference for config:DescribeComplianceByConfigRule /
 * config:GetComplianceDetailsByConfigRule, not exercised against a live
 * response yet).
 *
 * Config has no severity concept of its own (a rule is just compliant or
 * not) — every finding here is reported at 'medium', a deliberate
 * middle-ground rather than a real signal Config provides, since a policy
 * violation is more actionable than purely informational but this scanner
 * has no basis to rate one non-compliant resource above another.
 */
interface ComplianceByConfigRule { ConfigRuleName: string; Compliance?: { ComplianceType?: string } }
interface DescribeComplianceResponse { ComplianceByConfigRules?: ComplianceByConfigRule[] }

interface EvaluationResultQualifier { ConfigRuleName?: string; ResourceType?: string; ResourceId?: string }
interface EvaluationResultIdentifier { EvaluationResultQualifier?: EvaluationResultQualifier }
interface EvaluationResult {
  EvaluationResultIdentifier?: EvaluationResultIdentifier;
  ComplianceType?: string;
  ResultRecordedTime?: string;
  Annotation?: string;
}
interface GetComplianceDetailsResponse { EvaluationResults?: EvaluationResult[]; NextToken?: string }

export async function scanAwsConfigFindings(ctx: ScannerContext): Promise<ScannedFinding[]> {
  const host = `config.${ctx.region}.amazonaws.com`;
  const call = async (target: string, body: Record<string, unknown>) =>
    callJsonApi(ctx.creds, { service: 'config', region: ctx.region, host, target: `StarlingDoveService.${target}`, body });

  const rulesResult = await call('DescribeComplianceByConfigRule', { ComplianceTypes: ['NON_COMPLIANT'] });
  if (!rulesResult.ok) {
    console.error(`AWS Config DescribeComplianceByConfigRule failed in ${ctx.region} (continuing without it — likely just not set up there): ${rulesResult.errorMessage ?? rulesResult.errorCode ?? rulesResult.status}`);
    return [];
  }
  const nonCompliantRules = ((rulesResult.body as DescribeComplianceResponse).ComplianceByConfigRules ?? [])
    .filter((r) => r.Compliance?.ComplianceType === 'NON_COMPLIANT')
    .slice(0, 10); // cap rules fanned out per step, same subrequest-budget reasoning as every other finding scanner here

  const out: ScannedFinding[] = [];
  for (const rule of nonCompliantRules) {
    const detailsResult = await call('GetComplianceDetailsByConfigRule', {
      ConfigRuleName: rule.ConfigRuleName,
      ComplianceTypes: ['NON_COMPLIANT'],
      Limit: 100,
    });
    if (!detailsResult.ok) {
      console.error(`AWS Config GetComplianceDetailsByConfigRule failed for rule ${rule.ConfigRuleName} in ${ctx.region} (continuing without it): ${detailsResult.errorMessage ?? detailsResult.errorCode}`);
      continue;
    }
    for (const evalResult of (detailsResult.body as GetComplianceDetailsResponse).EvaluationResults ?? []) {
      const q = evalResult.EvaluationResultIdentifier?.EvaluationResultQualifier;
      if (!q?.ConfigRuleName || !q.ResourceId) continue;
      out.push({
        findingSource: 'aws_config',
        awsFindingId: `${q.ConfigRuleName}/${q.ResourceType ?? 'resource'}/${q.ResourceId}`,
        severity: 'medium',
        title: `${q.ConfigRuleName} — ${q.ResourceType ?? 'resource'} non-compliant`,
        description: evalResult.Annotation,
        complianceFrameworks: [],
        discoveredAt: evalResult.ResultRecordedTime ?? new Date().toISOString(),
        region: ctx.region,
        resourceArn: q.ResourceId,
      });
    }
  }
  return out;
}
