import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CLOUDHSM_RESOURCE_TYPES = ['cloudhsm_cluster'] as const;

interface Cluster { ClusterId: string; State?: string; StateMessage?: string; HsmType?: string; CreateTimestamp?: number; VpcId?: string; Hsms?: unknown[] }
interface DescribeClustersResponse { Clusters?: Cluster[] }

/**
 * CloudHSM v2 — request/response body shape confirmed against AWS's API
 * reference (DescribeClusters), but the exact X-Amz-Target service prefix
 * (BaldrApiService) is AWS's internal codename for this service and isn't
 * spelled out in the public docs the way StarlingDoveService/AWSShield are
 * — UNVERIFIED against a real account, same caveat this codebase already
 * uses for awsConfigFindings.ts/trustedAdvisorFindings.ts when a live
 * response wasn't available to confirm against.
 */
export async function scanCloudHsm(ctx: ScannerContext): Promise<ScannedResource[]> {
  const result = await callJsonApi(ctx.creds, {
    service: 'cloudhsm', region: ctx.region, host: `cloudhsmv2.${ctx.region}.amazonaws.com`,
    target: 'BaldrApiService.DescribeClusters', body: {},
  });
  if (!result.ok) {
    console.error(`CloudHSM DescribeClusters failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const clusters = (result.body as DescribeClustersResponse).Clusters ?? [];
  return clusters.map((c) => ({
    resourceTypeKey: 'cloudhsm_cluster', resourceId: c.ClusterId, region: ctx.region,
    state: c.State, metadata: { stateMessage: c.StateMessage, hsmType: c.HsmType, createTimestamp: c.CreateTimestamp, hsmCount: c.Hsms?.length ?? 0 },
    relationships: { vpcId: c.VpcId },
  }));
}
