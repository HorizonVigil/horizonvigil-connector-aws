import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const NETWORKFIREWALL_RESOURCE_TYPES = ['network_firewall', 'network_firewall_policy'] as const;

interface FirewallMetadata { FirewallName?: string; FirewallArn?: string }
interface ListFirewallsResponse { Firewalls?: FirewallMetadata[] }
interface FirewallPolicyMetadata { Name?: string; Arn?: string }
interface ListFirewallPoliciesResponse { FirewallPolicies?: FirewallPolicyMetadata[] }

/** VPC Network Firewall — list-only summaries (name+ARN), no per-firewall DescribeFirewall detail call in this pass. */
export async function scanNetworkFirewall(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `network-firewall.${ctx.region}.amazonaws.com`;
  const call = async (target: string, body: Record<string, unknown> = {}) =>
    callJsonApi(ctx.creds, { service: 'network-firewall', region: ctx.region, host, target: `NetworkFirewall_20201112.${target}`, body });

  const out: ScannedResource[] = [];

  const firewallsResult = await call('ListFirewalls');
  if (!firewallsResult.ok) {
    console.error(`Network Firewall ListFirewalls failed in ${ctx.region} (continuing without it): ${firewallsResult.errorMessage ?? firewallsResult.errorCode ?? firewallsResult.status}`);
  } else {
    for (const fw of (firewallsResult.body as ListFirewallsResponse).Firewalls ?? []) {
      if (!fw.FirewallArn) continue;
      out.push({ resourceTypeKey: 'network_firewall', resourceId: fw.FirewallArn, region: ctx.region, resourceName: fw.FirewallName });
    }
  }

  const policiesResult = await call('ListFirewallPolicies');
  if (policiesResult.ok) {
    for (const p of (policiesResult.body as ListFirewallPoliciesResponse).FirewallPolicies ?? []) {
      if (!p.Arn) continue;
      out.push({ resourceTypeKey: 'network_firewall_policy', resourceId: p.Arn, region: ctx.region, resourceName: p.Name });
    }
  }

  return out;
}
