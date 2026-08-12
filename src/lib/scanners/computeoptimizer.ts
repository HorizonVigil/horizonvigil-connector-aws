import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const COMPUTEOPTIMIZER_RESOURCE_TYPES = ['compute_optimizer_recommendation'] as const;

interface EnrollmentStatus { status?: string }
interface InstanceRecommendation {
  instanceArn: string; instanceName?: string; currentInstanceType?: string; finding?: string;
  findingReasonCodes?: string[]; lookBackPeriodInDays?: number;
}
interface GetRecommendationsResponse { instanceRecommendations?: InstanceRecommendation[] }

/**
 * Compute Optimizer — target prefix (ComputeOptimizerService) is a best
 * effort against AWS's internal service-identifier convention, not spelled
 * out verbatim in the public API reference the way StarlingDoveService/
 * AWSHealth are — UNVERIFIED against a real account, same caveat as
 * cloudhsm.ts. Requires the account to be opted in (a per-account setting,
 * off by default); GetEnrollmentStatus is checked first and this returns
 * early rather than calling GetEC2InstanceRecommendations against a
 * not-opted-in account, which would just fail the same way on every call.
 */
export async function scanComputeOptimizer(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `compute-optimizer.${ctx.region}.amazonaws.com`;
  const call = async (target: string, body: Record<string, unknown> = {}) =>
    callJsonApi(ctx.creds, { service: 'compute-optimizer', region: ctx.region, host, target: `ComputeOptimizerService.${target}`, body });

  const enrollment = await call('GetEnrollmentStatus');
  if (!enrollment.ok || (enrollment.body as EnrollmentStatus).status !== 'Active') {
    if (!enrollment.ok) console.error(`Compute Optimizer GetEnrollmentStatus failed in ${ctx.region} (continuing without it): ${enrollment.errorMessage ?? enrollment.errorCode ?? enrollment.status}`);
    return [];
  }

  const result = await call('GetEC2InstanceRecommendations');
  if (!result.ok) {
    console.error(`Compute Optimizer GetEC2InstanceRecommendations failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const recs = (result.body as GetRecommendationsResponse).instanceRecommendations ?? [];
  return recs.filter((r) => r.finding && r.finding !== 'OPTIMIZED').map((r) => ({
    resourceTypeKey: 'compute_optimizer_recommendation', resourceId: r.instanceArn, region: ctx.region, resourceName: r.instanceName,
    state: r.finding, metadata: { currentInstanceType: r.currentInstanceType, findingReasonCodes: r.findingReasonCodes, lookBackPeriodInDays: r.lookBackPeriodInDays },
    relationships: { instanceArn: r.instanceArn },
  }));
}
