import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems, field } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ELB_RESOURCE_TYPES = ['elb_classic', 'elb_alb', 'elb_nlb', 'elb_gwlb', 'elb_target_group'] as const;

/**
 * Classic Load Balancers, ALB/NLB/GWLB, and target groups are all one API
 * ('elasticloadbalancing') and Query-protocol shape, just different
 * Action/Version pairs and response tags — same pattern as rds.ts covering
 * instances+clusters+snapshots in one file.
 */
export async function scanElb(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `elasticloadbalancing.${ctx.region}.amazonaws.com`;
  const call = async (action: string, version: string): Promise<string> => {
    const result = await callQueryApi(ctx.creds, { service: 'elasticloadbalancing', region: ctx.region, host: endpoint, action, version });
    if (!result.ok) {
      console.error(`ELB ${action} (${version}) failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return '';
    }
    return result.body as string;
  };

  const [classic, v2, targetGroups] = await Promise.all([
    call('DescribeLoadBalancers', '2012-06-01'),
    call('DescribeLoadBalancers', '2015-12-01'),
    call('DescribeTargetGroups', '2015-12-01'),
  ]);

  const out: ScannedResource[] = [];

  for (const lb of extractListItems(extractSection(classic, 'LoadBalancerDescriptions'), 'member')) {
    const name = field(lb, 'LoadBalancerName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'elb_classic', resourceId: name, region: ctx.region, resourceName: name,
      metadata: { dnsName: field(lb, 'DNSName'), scheme: field(lb, 'Scheme'), createdTime: field(lb, 'CreatedTime') },
      relationships: {
        vpcId: field(lb, 'VPCId'),
        instanceIds: extractListItems(extractSection(lb, 'Instances'), 'member').map((i) => field(i, 'InstanceId')),
      },
    });
  }

  for (const lb of extractListItems(extractSection(v2, 'LoadBalancers'), 'member')) {
    const arn = field(lb, 'LoadBalancerArn');
    if (!arn) continue;
    const type = field(lb, 'Type'); // 'application' | 'network' | 'gateway'
    const resourceTypeKey = type === 'network' ? 'elb_nlb' : type === 'gateway' ? 'elb_gwlb' : type === 'application' ? 'elb_alb' : null;
    if (!resourceTypeKey) continue; // an unrecognized future type
    const stateSection = extractSection(lb, 'State');
    out.push({
      resourceTypeKey, resourceId: arn, region: ctx.region, resourceName: field(lb, 'LoadBalancerName') ?? undefined,
      state: stateSection ? (field(stateSection, 'Code') ?? undefined) : undefined,
      metadata: { dnsName: field(lb, 'DNSName'), scheme: field(lb, 'Scheme'), createdTime: field(lb, 'CreatedTime') },
      relationships: {
        vpcId: field(lb, 'VpcId'),
        securityGroupIds: extractListItems(extractSection(lb, 'SecurityGroups'), 'member'),
      },
    });
  }

  for (const tg of extractListItems(extractSection(targetGroups, 'TargetGroups'), 'member')) {
    const arn = field(tg, 'TargetGroupArn');
    const name = field(tg, 'TargetGroupName');
    if (!arn || !name) continue;
    out.push({
      resourceTypeKey: 'elb_target_group', resourceId: arn, region: ctx.region, resourceName: name,
      metadata: {
        protocol: field(tg, 'Protocol'), port: field(tg, 'Port'), targetType: field(tg, 'TargetType'),
        healthCheckProtocol: field(tg, 'HealthCheckProtocol'),
      },
      relationships: {
        vpcId: field(tg, 'VpcId'),
        loadBalancerArns: extractListItems(extractSection(tg, 'LoadBalancerArns'), 'member'),
      },
    });
  }

  return out;
}
