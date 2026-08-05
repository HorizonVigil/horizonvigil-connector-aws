import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems, field, numField } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2011-01-01';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const AUTOSCALING_RESOURCE_TYPES = ['autoscaling_group', 'ec2_launch_config', 'autoscaling_policy'] as const;

/** Auto Scaling's Query-protocol tags use `<Tags><member><Key>/<Value></member></Tags>` — capitalized field names, same shape as RDS's TagList, different wrapper tag names. */
function asgTags(xml: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const tag of extractListItems(extractSection(xml, 'Tags'), 'member')) {
    const key = field(tag, 'Key');
    if (key) out[key] = field(tag, 'Value') ?? '';
  }
  return out;
}

/** Groups, launch configurations, and scaling policies — one signer, 3 Query-protocol calls. */
export async function scanAutoScaling(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `autoscaling.${ctx.region}.amazonaws.com`;
  const call = async (action: string): Promise<string> => {
    const result = await callQueryApi(ctx.creds, { service: 'autoscaling', region: ctx.region, host: endpoint, action, version: VERSION });
    if (!result.ok) {
      console.error(`Auto Scaling ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return '';
    }
    return result.body as string;
  };

  const [groups, launchConfigs, policies] = await Promise.all([
    call('DescribeAutoScalingGroups'),
    call('DescribeLaunchConfigurations'),
    call('DescribePolicies'),
  ]);

  const out: ScannedResource[] = [];
  for (const asg of extractListItems(extractSection(groups, 'AutoScalingGroups'), 'member')) {
    const tags = asgTags(asg);
    const name = field(asg, 'AutoScalingGroupName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'autoscaling_group', resourceId: field(asg, 'AutoScalingGroupARN') ?? name, region: ctx.region,
      resourceName: name, tags,
      metadata: {
        minSize: numField(asg, 'MinSize'), maxSize: numField(asg, 'MaxSize'), desiredCapacity: numField(asg, 'DesiredCapacity'),
        createdTime: field(asg, 'CreatedTime'), launchConfigurationName: field(asg, 'LaunchConfigurationName'),
      },
      relationships: {
        instanceIds: extractListItems(extractSection(asg, 'Instances'), 'member').map((i) => field(i, 'InstanceId')),
      },
    });
  }
  // Launch Configurations are a legacy, deprecated-in-favor-of-launch-templates
  // resource type — no tags of their own in this API.
  for (const lc of extractListItems(extractSection(launchConfigs, 'LaunchConfigurations'), 'member')) {
    const name = field(lc, 'LaunchConfigurationName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'ec2_launch_config', resourceId: field(lc, 'LaunchConfigurationARN') ?? name, region: ctx.region, resourceName: name,
      metadata: { imageId: field(lc, 'ImageId'), instanceType: field(lc, 'InstanceType'), createdTime: field(lc, 'CreatedTime'), keyName: field(lc, 'KeyName') },
    });
  }
  for (const p of extractListItems(extractSection(policies, 'ScalingPolicies'), 'member')) {
    const name = field(p, 'PolicyName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'autoscaling_policy', resourceId: field(p, 'PolicyARN') ?? name, region: ctx.region, resourceName: name,
      metadata: { policyType: field(p, 'PolicyType'), adjustmentType: field(p, 'AdjustmentType') },
      relationships: { autoScalingGroupName: field(p, 'AutoScalingGroupName') },
    });
  }
  return out;
}
