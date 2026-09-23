import { paginateQueryApi, detectQueryTruncation, incompleteSink } from '../pagination';
import { extractSection, extractListItems, field, numField, boolField } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';
import { withoutSections } from './xmlShape';

const VERSION = '2011-01-01';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const AUTOSCALING_RESOURCE_TYPES = ['autoscaling_group', 'ec2_launch_config', 'autoscaling_policy'] as const;

/** Auto Scaling's Query-protocol tags use `<Tags><member><Key>/<Value></member></Tags>`. */
function asgTags(xml: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const tag of extractListItems(extractSection(xml, 'Tags'), 'member')) {
    const key = field(tag, 'Key');
    if (key) out[key] = field(tag, 'Value') ?? '';
  }
  return out;
}

const strings = (xml: string, section: string): string[] =>
  extractListItems(extractSection(xml, section), 'member').map((s) => s.trim()).filter(Boolean);

const boolOrNull = (xml: string, name: string): boolean | null => boolField(xml, name) ?? null;

/** Security + resilience evidence for one Auto Scaling group. */
export function groupEvidence(asg: string) {
  const top = withoutSections(asg, ['Instances', 'Tags', 'MixedInstancesPolicy', 'SuspendedProcesses', 'EnabledMetrics', 'WarmPoolConfiguration']);
  const lt = extractSection(top, 'LaunchTemplate') ?? extractSection(extractSection(asg, 'MixedInstancesPolicy') ?? '', 'LaunchTemplateSpecification');
  const azs = strings(top, 'AvailabilityZones');
  return {
    metadata: {
      minSize: numField(top, 'MinSize'), maxSize: numField(top, 'MaxSize'), desiredCapacity: numField(top, 'DesiredCapacity'),
      createdTime: field(top, 'CreatedTime'), launchConfigurationName: field(top, 'LaunchConfigurationName'),
      launchTemplateId: lt ? field(lt, 'LaunchTemplateId') : null,
      launchTemplateVersion: lt ? field(lt, 'Version') : null,
      usesMixedInstancesPolicy: extractSection(asg, 'MixedInstancesPolicy') !== null,
      // Legacy launch configurations are deprecated; FSBP AutoScaling.9.
      usesLaunchConfiguration: !!field(top, 'LaunchConfigurationName'),
      // Multiple AZs (FSBP AutoScaling.2) and ELB health checks (AutoScaling.1).
      availabilityZones: azs,
      availabilityZoneCount: azs.length,
      healthCheckType: field(top, 'HealthCheckType'),
      healthCheckGracePeriod: numField(top, 'HealthCheckGracePeriod'),
      capacityRebalance: boolOrNull(top, 'CapacityRebalance'),
      status: field(top, 'Status'),
      instanceCount: extractListItems(extractSection(asg, 'Instances'), 'member').length,
    },
    relationships: {
      instanceIds: extractListItems(extractSection(asg, 'Instances'), 'member')
        .map((i) => field(i, 'InstanceId'))
        .filter((v): v is string => !!v),
      subnetIds: (field(top, 'VPCZoneIdentifier') ?? '').split(',').map((s) => s.trim()).filter(Boolean),
      targetGroupArns: strings(top, 'TargetGroupARNs'),
      loadBalancerNames: strings(top, 'LoadBalancerNames'),
      launchTemplateId: lt ? field(lt, 'LaunchTemplateId') : null,
      serviceLinkedRoleArn: field(top, 'ServiceLinkedRoleARN'),
    },
  };
}

/** Security evidence for one (legacy) launch configuration. User data is never stored. */
export function launchConfigEvidence(lc: string) {
  const metadataOptions = extractSection(lc, 'MetadataOptions') ?? '';
  const devices = extractListItems(extractSection(lc, 'BlockDeviceMappings'), 'member');
  const ebsEncryption = devices
    .map((d) => extractSection(d, 'Ebs'))
    .filter((e): e is string => e !== null)
    .map((e) => boolField(e, 'Encrypted'));
  return {
    imageId: field(lc, 'ImageId'), instanceType: field(lc, 'InstanceType'), createdTime: field(lc, 'CreatedTime'), keyName: field(lc, 'KeyName'),
    // FSBP AutoScaling.5: launched instances should not get public IPs.
    associatePublicIpAddress: boolOrNull(lc, 'AssociatePublicIpAddress'),
    // FSBP AutoScaling.3: IMDSv2 required.
    imdsHttpTokens: field(metadataOptions, 'HttpTokens'),
    imdsHttpEndpoint: field(metadataOptions, 'HttpEndpoint'),
    imdsHttpPutResponseHopLimit: numField(metadataOptions, 'HttpPutResponseHopLimit') ?? null,
    iamInstanceProfile: field(lc, 'IamInstanceProfile'),
    securityGroupIds: strings(lc, 'SecurityGroups'),
    // Presence only: user data frequently contains secrets and is never persisted.
    hasUserData: !!field(lc, 'UserData'),
    ebsVolumeCount: ebsEncryption.length,
    unencryptedEbsVolumeCount: ebsEncryption.filter((v) => v === false).length,
    instanceMonitoringEnabled: boolOrNull(extractSection(lc, 'InstanceMonitoring') ?? '', 'Enabled'),
  };
}

/**
 * Auto Scaling groups, launch configurations and scaling policies.
 *
 * Every call now paginates (NextToken; MaxRecords defaults to 50 and caps
 * at 100), and an incomplete walk degrades coverage through the shared sink.
 * The previous version read one page, so group number 51 looked deleted.
 * Null instance ids are no longer stored in relationships.
 */
export async function scanAutoScaling(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `autoscaling.${ctx.region}.amazonaws.com`;
  const onIncomplete = incompleteSink(ctx.creds);
  const walk = (action: string, section: string, maxRecords: string) => paginateQueryApi<string, string>(
    ctx.creds,
    { service: 'autoscaling', region: ctx.region, host, action, version: VERSION, params: { MaxRecords: maxRecords } },
    (page) => extractListItems(extractSection(page, section), 'member'),
    (page) => detectQueryTruncation(page),
    { onIncomplete },
  );

  const [groups, launchConfigs, policies] = await Promise.all([
    walk('DescribeAutoScalingGroups', 'AutoScalingGroups', '100'),
    walk('DescribeLaunchConfigurations', 'LaunchConfigurations', '100'),
    walk('DescribePolicies', 'ScalingPolicies', '50'),
  ]);
  for (const [action, w] of [['DescribeAutoScalingGroups', groups], ['DescribeLaunchConfigurations', launchConfigs], ['DescribePolicies', policies]] as const) {
    if (w.termination !== 'complete') console.error(`Auto Scaling ${action} in ${ctx.region} ended '${w.termination}' after ${w.pages} page(s); continuing with what was read.`);
  }

  const out: ScannedResource[] = [];
  for (const asg of groups.items) {
    const name = field(asg, 'AutoScalingGroupName');
    if (!name) continue;
    const evidence = groupEvidence(asg);
    out.push({
      resourceTypeKey: 'autoscaling_group', resourceId: field(asg, 'AutoScalingGroupARN') ?? name, region: ctx.region,
      resourceName: name, tags: asgTags(asg), state: evidence.metadata.status ?? undefined,
      metadata: evidence.metadata,
      relationships: evidence.relationships,
    });
  }
  for (const lc of launchConfigs.items) {
    const name = field(lc, 'LaunchConfigurationName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'ec2_launch_config', resourceId: field(lc, 'LaunchConfigurationARN') ?? name, region: ctx.region, resourceName: name,
      metadata: launchConfigEvidence(lc),
    });
  }
  for (const p of policies.items) {
    const name = field(p, 'PolicyName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'autoscaling_policy', resourceId: field(p, 'PolicyARN') ?? name, region: ctx.region, resourceName: name,
      metadata: { policyType: field(p, 'PolicyType'), adjustmentType: field(p, 'AdjustmentType'), enabled: boolOrNull(p, 'Enabled') },
      relationships: { autoScalingGroupName: field(p, 'AutoScalingGroupName') },
    });
  }
  return out;
}