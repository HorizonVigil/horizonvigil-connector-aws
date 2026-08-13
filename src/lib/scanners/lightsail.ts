import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const LIGHTSAIL_RESOURCE_TYPES = ['lightsail_instance', 'lightsail_disk', 'lightsail_load_balancer'] as const;

interface LightsailInstance { arn: string; name?: string; blueprintName?: string; bundleId?: string; state?: { name?: string }; publicIpAddress?: string }
interface GetInstancesResponse { instances?: LightsailInstance[] }
interface LightsailDisk { arn: string; name?: string; sizeInGb?: number; isAttached?: boolean; attachedTo?: string; state?: string }
interface GetDisksResponse { disks?: LightsailDisk[] }
interface LightsailLoadBalancer { arn: string; name?: string; state?: string; dnsName?: string }
interface GetLoadBalancersResponse { loadBalancers?: LightsailLoadBalancer[] }

/** Amazon Lightsail — target prefix (Lightsail_20161128) confirmed against AWS's API reference sample request. */
export async function scanLightsail(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `lightsail.${ctx.region}.amazonaws.com`;
  const call = async (target: string, body: Record<string, unknown> = {}) =>
    callJsonApi(ctx.creds, { service: 'lightsail', region: ctx.region, host, target: `Lightsail_20161128.${target}`, body });

  const out: ScannedResource[] = [];

  const instancesResult = await call('GetInstances');
  if (!instancesResult.ok) {
    console.error(`Lightsail GetInstances failed in ${ctx.region} (continuing without it): ${instancesResult.errorMessage ?? instancesResult.errorCode ?? instancesResult.status}`);
    return out;
  }
  for (const i of (instancesResult.body as GetInstancesResponse).instances ?? []) {
    out.push({ resourceTypeKey: 'lightsail_instance', resourceId: i.arn, region: ctx.region, resourceName: i.name, state: i.state?.name, metadata: { blueprintName: i.blueprintName, bundleId: i.bundleId, publicIpAddress: i.publicIpAddress } });
  }

  const disksResult = await call('GetDisks');
  for (const d of (disksResult.ok ? (disksResult.body as GetDisksResponse).disks : []) ?? []) {
    out.push({ resourceTypeKey: 'lightsail_disk', resourceId: d.arn, region: ctx.region, resourceName: d.name, state: d.state, metadata: { sizeInGb: d.sizeInGb, isAttached: d.isAttached }, relationships: { attachedTo: d.attachedTo } });
  }

  const lbResult = await call('GetLoadBalancers');
  for (const lb of (lbResult.ok ? (lbResult.body as GetLoadBalancersResponse).loadBalancers : []) ?? []) {
    out.push({ resourceTypeKey: 'lightsail_load_balancer', resourceId: lb.arn, region: ctx.region, resourceName: lb.name, state: lb.state, metadata: { dnsName: lb.dnsName } });
  }

  return out;
}
