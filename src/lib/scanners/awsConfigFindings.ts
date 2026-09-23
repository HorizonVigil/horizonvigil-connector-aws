import { toIso, walkJsonRpc } from './restJson';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannerContext } from './types';
import type { ScannedFinding } from './findingTypes';

/** Non-compliant rules fanned out per region (Workers subrequest budget). */
const MAX_RULES = 25;
/** GetComplianceDetailsByConfigRule pages per rule (100 evaluations each). */
const MAX_DETAIL_PAGES = 3;
const RULE_CONCURRENCY = 3;

interface ComplianceByConfigRule { ConfigRuleName: string; Compliance?: { ComplianceType?: string } }
interface EvaluationResultQualifier { ConfigRuleName?: string; ResourceType?: string; ResourceId?: string; EvaluationMode?: string }
interface EvaluationResult {
  EvaluationResultIdentifier?: { EvaluationResultQualifier?: EvaluationResultQualifier };
  ComplianceType?: string;
  ResultRecordedTime?: number | string;
  ConfigRuleInvokedTime?: number | string;
  Annotation?: string;
}

/**
 * The finding's resource reference. Config reports a resource ID ("i-0abc",
 * "sg-123", a bucket name), and only sometimes an ARN. It is passed through
 * as-is in resourceArn -- as before -- because building an ARN needs the
 * account ID and per-type ARN formats this scanner does not have; the
 * resource type is carried in the title so the two together identify it.
 */
function resourceRef(q: EvaluationResultQualifier): string {
  return q.ResourceId ?? '';
}

/**
 * AWS Config non-compliant rule evaluations, surfaced as findings (JSON 1.1,
 * target StarlingDoveService).
 *
 * What changed, and why:
 *  - discoveredAt was an epoch NUMBER. Config's JSON 1.1 protocol returns
 *    timestamps as epoch seconds; the value was passed straight through into
 *    a string field. It is now an ISO string.
 *  - DescribeComplianceByConfigRule paginates (NextToken). Previously page
 *    one only, then a silent cap of 10 rules.
 *  - GetComplianceDetailsByConfigRule reads up to MAX_DETAIL_PAGES pages per
 *    rule (it stopped at 100 evaluations), and rules run with bounded
 *    concurrency.
 *
 * Config has no severity concept (a rule is compliant or not), so every
 * finding is 'medium' -- a deliberate middle ground, not a real signal.
 */
export async function scanAwsConfigFindings(ctx: ScannerContext): Promise<ScannedFinding[]> {
  const host = `config.${ctx.region}.amazonaws.com`;

  const rulesWalk = await walkJsonRpc<ComplianceByConfigRule>(ctx, {
    service: 'config', host, target: 'StarlingDoveService.DescribeComplianceByConfigRule',
    body: { ComplianceTypes: ['NON_COMPLIANT'] },
  }, 'ComplianceByConfigRules');
  if (rulesWalk.firstPageFailed) {
    console.error(`AWS Config DescribeComplianceByConfigRule failed in ${ctx.region} (continuing without it — likely not set up there): ${rulesWalk.error ?? ''}`);
    return [];
  }
  if (!rulesWalk.complete) console.error(`AWS Config DescribeComplianceByConfigRule in ${ctx.region} is partial: ${rulesWalk.error ?? ''}`);

  const nonCompliant = rulesWalk.items.filter((r) => !!r?.ConfigRuleName && r.Compliance?.ComplianceType === 'NON_COMPLIANT');
  const rules = nonCompliant.slice(0, MAX_RULES);
  if (nonCompliant.length > rules.length) {
    console.error(`AWS Config ${ctx.region}: ${nonCompliant.length} non-compliant rules; evaluations read for the first ${rules.length}.`);
  }

  const perRule = await mapWithConcurrency(rules, RULE_CONCURRENCY, async (rule) => {
    const walk = await walkJsonRpc<EvaluationResult>(ctx, {
      service: 'config', host, target: 'StarlingDoveService.GetComplianceDetailsByConfigRule',
      body: { ConfigRuleName: rule.ConfigRuleName, ComplianceTypes: ['NON_COMPLIANT'], Limit: 100 },
    }, 'EvaluationResults', { maxPages: MAX_DETAIL_PAGES });
    if (!walk.complete) console.error(`AWS Config evaluations for ${rule.ConfigRuleName} in ${ctx.region} are partial: ${walk.error ?? ''}`);
    return walk.items;
  });

  const out: ScannedFinding[] = [];
  const seen = new Set<string>();
  for (const evaluations of perRule) {
    for (const evalResult of evaluations) {
      const q = evalResult?.EvaluationResultIdentifier?.EvaluationResultQualifier;
      if (!q?.ConfigRuleName || !q.ResourceId) continue;
      const id = `${q.ConfigRuleName}/${q.ResourceType ?? 'resource'}/${q.ResourceId}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push({
        findingSource: 'aws_config',
        awsFindingId: id,
        severity: 'medium',
        title: `${q.ConfigRuleName} — ${q.ResourceType ?? 'resource'} non-compliant`,
        description: evalResult.Annotation,
        complianceFrameworks: [],
        discoveredAt: toIso(evalResult.ResultRecordedTime) ?? toIso(evalResult.ConfigRuleInvokedTime) ?? new Date().toISOString(),
        region: ctx.region,
        resourceArn: resourceRef(q),
      });
    }
  }
  return out;
}