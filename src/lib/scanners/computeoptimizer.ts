import { callJsonApi } from '../awsApi';
import { reportWalk, walkJsonRpc } from './restJson';
import { reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const COMPUTEOPTIMIZER_RESOURCE_TYPES = ['compute_optimizer_recommendation'] as const;

interface RecommendationOption {
  instanceType?: string; rank?: number; performanceRisk?: number;
  savingsOpportunity?: { savingsOpportunityPercentage?: number; estimatedMonthlySavings?: { currency?: string; value?: number } };
}
export interface InstanceRecommendation {
  instanceArn: string; instanceName?: string; currentInstanceType?: string; finding?: string;
  findingReasonCodes?: string[]; lookBackPeriodInDays?: number; currentPerformanceRisk?: string;
  recommendationOptions?: RecommendationOption[];
}

/**
 * AWS returns `Optimized`, `Underprovisioned`, `Overprovisioned` and
 * `NotOptimized` (mixed case). The previous filter compared against the
 * upper-case 'OPTIMIZED', which never matched, so instances AWS considers
 * optimal were stored as "recommendations".
 */
export function isActionable(finding: string | undefined): boolean {
  return !!finding && finding.toLowerCase() !== 'optimized';
}

/** The top-ranked option and its estimated savings. */
export function recommendationMetadata(r: InstanceRecommendation) {
  const top = [...(r.recommendationOptions ?? [])].sort((a, b) => (a.rank ?? 99) - (b.rank ?? 99))[0];
  return {
    currentInstanceType: r.currentInstanceType, findingReasonCodes: r.findingReasonCodes, lookBackPeriodInDays: r.lookBackPeriodInDays,
    currentPerformanceRisk: r.currentPerformanceRisk ?? null,
    recommendedInstanceType: top?.instanceType ?? null,
    estimatedMonthlySavings: top?.savingsOpportunity?.estimatedMonthlySavings?.value ?? null,
    savingsCurrency: top?.savingsOpportunity?.estimatedMonthlySavings?.currency ?? null,
    savingsOpportunityPercentage: top?.savingsOpportunity?.savingsOpportunityPercentage ?? null,
  };
}

/**
 * Compute Optimizer EC2 recommendations (JSON-RPC, ComputeOptimizerService).
 * The account must be opted in; GetEnrollmentStatus is checked first.
 *
 * What changed:
 *  - Optimized instances are excluded (see isActionable).
 *  - GetEC2InstanceRecommendations paginates (nextToken, up to 1000/page);
 *    it used to return one page.
 *  - An enrollment check that FAILED (as opposed to "not enrolled") is
 *    reported, so existing recommendation rows are not read as resolved.
 */
export async function scanComputeOptimizer(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `compute-optimizer.${ctx.region}.amazonaws.com`;

  const enrollment = await callJsonApi(ctx.creds, { service: 'compute-optimizer', region: ctx.region, host, target: 'ComputeOptimizerService.GetEnrollmentStatus', body: {} });
  if (!enrollment.ok) {
    console.error(`Compute Optimizer GetEnrollmentStatus failed in ${ctx.region} (continuing without it): ${enrollment.errorMessage ?? enrollment.errorCode ?? enrollment.status}`);
    reportListingFailure(ctx, { service: 'compute-optimizer', action: 'GetEC2InstanceRecommendations', region: ctx.region });
    return [];
  }
  // Not opted in (or opting out): a settled answer -- there are no recommendations.
  if ((enrollment.body as { status?: string } | null)?.status !== 'Active') return [];

  const walk = await walkJsonRpc<InstanceRecommendation>(ctx, {
    service: 'compute-optimizer', host, target: 'ComputeOptimizerService.GetEC2InstanceRecommendations', body: { maxResults: 1000 },
  }, 'instanceRecommendations', { tokenIn: 'nextToken', tokenOut: 'nextToken', maxPages: 20 });
  reportWalk(ctx, walk, 'compute-optimizer', 'GetEC2InstanceRecommendations');

  return walk.items.filter((r) => !!r?.instanceArn && isActionable(r.finding)).map((r) => ({
    resourceTypeKey: 'compute_optimizer_recommendation', resourceId: r.instanceArn, region: ctx.region, resourceName: r.instanceName,
    state: r.finding,
    metadata: recommendationMetadata(r),
    relationships: { instanceArn: r.instanceArn },
  }));
}