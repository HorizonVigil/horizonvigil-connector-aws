import { callQueryApi, listParams } from '../awsApi';
import { extractSection, extractListItems, field, boolField, numField, tagsFromSet } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2016-11-15';

/** Every resource_type_key this scanner can produce — used by discovery.ts to scope "vanished resource" cleanup to only the types this scanner actually checks, so resource types from not-yet-ported scanners (kms_alias, iam_role, s3_bucket, ...) are never touched by an EC2-only run. */
export const EC2_RESOURCE_TYPES = [
  'ec2_instance', 'ec2_ami', 'ec2_key_pair', 'ebs_volume', 'ebs_snapshot', 'security_group', 'elastic_ip',
  'network_interface', 'vpc', 'subnet', 'route_table', 'internet_gateway', 'nat_gateway', 'network_acl',
  'vpc_endpoint', 'vpc_peering_connection', 'ec2_launch_template', 'vpc_flow_log', 'ec2_placement_group',
  'prefix_list',
] as const;

/**
 * Everything that hangs off the core EC2 API in one pass — instances,
 * AMIs/key pairs, EBS volumes/snapshots, and the VPC networking primitives.
 * One signer, ~16 raw Describe* calls (aws4fetch, not the SDK — see
 * awsApi.ts). Ported from the pre-teardown cloud-api's scanEc2 (git tag
 * pre-teardown-2026-07-28), rewritten to parse with regex-based
 * extraction (xmlList.ts) instead of @xmldom/xmldom's DOMParser — that
 * dependency was the one this project's own history flagged as a real
 * Workers cost, which is why every AWS call elsewhere in this rebuild
 * already avoids it.
 */
export async function scanEc2(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `ec2.${ctx.region}.amazonaws.com`;
  const call = async (action: string, params?: Record<string, string>): Promise<string> => {
    const result = await callQueryApi(ctx.creds, { service: 'ec2', region: ctx.region, host: endpoint, action, version: VERSION, params });
    if (!result.ok) {
      console.error(`EC2 ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return '';
    }
    return result.body as string;
  };

  const [
    instances, images, keyPairs, volumes, snapshots, sgs, addresses, enis,
    vpcs, subnets, routeTables, igws, natGateways, nacls, vpcEndpoints, peerings,
    launchTemplates, flowLogs, placementGroups, prefixLists,
  ] = await Promise.all([
    call('DescribeInstances'),
    call('DescribeImages', listParams('Owner', ['self'])),
    call('DescribeKeyPairs'),
    call('DescribeVolumes'),
    call('DescribeSnapshots', listParams('Owner', ['self'])),
    call('DescribeSecurityGroups'),
    call('DescribeAddresses'),
    call('DescribeNetworkInterfaces'),
    call('DescribeVpcs'),
    call('DescribeSubnets'),
    call('DescribeRouteTables'),
    call('DescribeInternetGateways'),
    call('DescribeNatGateways'),
    call('DescribeNetworkAcls'),
    call('DescribeVpcEndpoints'),
    call('DescribeVpcPeeringConnections'),
    call('DescribeLaunchTemplates'),
    call('DescribeFlowLogs'),
    call('DescribePlacementGroups'),
    call('DescribeManagedPrefixLists'),
  ]);

  const out: ScannedResource[] = [];

  for (const reservation of extractListItems(extractSection(instances, 'reservationSet'))) {
    for (const i of extractListItems(extractSection(reservation, 'instancesSet'))) {
      const tags = tagsFromSet(i);
      const state = extractSection(i, 'instanceState');
      out.push({
        resourceTypeKey: 'ec2_instance', resourceId: field(i, 'instanceId')!, region: ctx.region,
        resourceName: tags['Name'], state: state ? (field(state, 'name') ?? undefined) : undefined, tags,
        metadata: { instanceType: field(i, 'instanceType'), launchTime: field(i, 'launchTime'), privateIp: field(i, 'privateIpAddress'), publicIp: field(i, 'publicIpAddress'), platform: field(i, 'platformDetails') },
        relationships: { vpcId: field(i, 'vpcId'), subnetId: field(i, 'subnetId'), securityGroupIds: extractListItems(extractSection(i, 'groupSet')).map(g => field(g, 'groupId')) },
      });
    }
  }
  for (const a of extractListItems(extractSection(images, 'imagesSet'))) {
    out.push({ resourceTypeKey: 'ec2_ami', resourceId: field(a, 'imageId')!, region: ctx.region, resourceName: field(a, 'name') ?? undefined, state: field(a, 'imageState') ?? undefined, tags: tagsFromSet(a), metadata: { creationDate: field(a, 'creationDate'), architecture: field(a, 'architecture') } });
  }
  for (const k of extractListItems(extractSection(keyPairs, 'keySet'))) {
    out.push({ resourceTypeKey: 'ec2_key_pair', resourceId: field(k, 'keyPairId')!, region: ctx.region, resourceName: field(k, 'keyName') ?? undefined, tags: tagsFromSet(k), metadata: { fingerprint: field(k, 'keyFingerprint') } });
  }
  for (const v of extractListItems(extractSection(volumes, 'volumeSet'))) {
    const tags = tagsFromSet(v);
    out.push({
      resourceTypeKey: 'ebs_volume', resourceId: field(v, 'volumeId')!, region: ctx.region, resourceName: tags['Name'],
      state: field(v, 'status') ?? undefined, tags,
      metadata: { sizeGiB: numField(v, 'size'), volumeType: field(v, 'volumeType'), iops: numField(v, 'iops'), encrypted: boolField(v, 'encrypted'), createTime: field(v, 'createTime') },
      relationships: { attachedInstanceIds: extractListItems(extractSection(v, 'attachmentSet')).map(at => field(at, 'instanceId')) },
    });
  }
  for (const s of extractListItems(extractSection(snapshots, 'snapshotSet'))) {
    const tags = tagsFromSet(s);
    out.push({ resourceTypeKey: 'ebs_snapshot', resourceId: field(s, 'snapshotId')!, region: ctx.region, resourceName: tags['Name'], state: field(s, 'status') ?? undefined, tags, metadata: { volumeSizeGiB: numField(s, 'volumeSize'), startTime: field(s, 'startTime'), encrypted: boolField(s, 'encrypted') }, relationships: { volumeId: field(s, 'volumeId') } });
  }
  for (const sg of extractListItems(extractSection(sgs, 'securityGroupInfo'))) {
    const tags = tagsFromSet(sg);
    out.push({ resourceTypeKey: 'security_group', resourceId: field(sg, 'groupId')!, region: ctx.region, resourceName: field(sg, 'groupName') ?? undefined, isDefault: field(sg, 'groupName') === 'default', tags, metadata: { description: field(sg, 'groupDescription'), inboundRuleCount: extractListItems(extractSection(sg, 'ipPermissions')).length, outboundRuleCount: extractListItems(extractSection(sg, 'ipPermissionsEgress')).length }, relationships: { vpcId: field(sg, 'vpcId') } });
  }
  for (const eip of extractListItems(extractSection(addresses, 'addressesSet'))) {
    const tags = tagsFromSet(eip);
    out.push({ resourceTypeKey: 'elastic_ip', resourceId: field(eip, 'allocationId') ?? field(eip, 'publicIp')!, region: ctx.region, resourceName: field(eip, 'publicIp') ?? undefined, tags, metadata: { publicIp: field(eip, 'publicIp'), domain: field(eip, 'domain') }, relationships: { instanceId: field(eip, 'instanceId'), networkInterfaceId: field(eip, 'networkInterfaceId') } });
  }
  for (const eni of extractListItems(extractSection(enis, 'networkInterfaceSet'))) {
    const tags = tagsFromSet(eni);
    const attachment = extractSection(eni, 'attachment');
    out.push({ resourceTypeKey: 'network_interface', resourceId: field(eni, 'networkInterfaceId')!, region: ctx.region, resourceName: field(eni, 'description') ?? undefined, state: field(eni, 'status') ?? undefined, tags, metadata: { privateIp: field(eni, 'privateIpAddress'), interfaceType: field(eni, 'interfaceType') }, relationships: { vpcId: field(eni, 'vpcId'), subnetId: field(eni, 'subnetId'), attachedInstanceId: attachment ? field(attachment, 'instanceId') : null } });
  }
  for (const vpc of extractListItems(extractSection(vpcs, 'vpcSet'))) {
    const tags = tagsFromSet(vpc);
    out.push({ resourceTypeKey: 'vpc', resourceId: field(vpc, 'vpcId')!, region: ctx.region, resourceName: tags['Name'], isDefault: boolField(vpc, 'isDefault'), state: field(vpc, 'state') ?? undefined, tags, metadata: { cidrBlock: field(vpc, 'cidrBlock'), instanceTenancy: field(vpc, 'instanceTenancy') } });
  }
  for (const sn of extractListItems(extractSection(subnets, 'subnetSet'))) {
    const tags = tagsFromSet(sn);
    out.push({ resourceTypeKey: 'subnet', resourceId: field(sn, 'subnetId')!, region: ctx.region, resourceName: tags['Name'], isDefault: boolField(sn, 'defaultForAz'), state: field(sn, 'state') ?? undefined, tags, metadata: { cidrBlock: field(sn, 'cidrBlock'), availabilityZone: field(sn, 'availabilityZone'), availableIpCount: numField(sn, 'availableIpAddressCount') }, relationships: { vpcId: field(sn, 'vpcId') } });
  }
  for (const rt of extractListItems(extractSection(routeTables, 'routeTableSet'))) {
    const tags = tagsFromSet(rt);
    out.push({ resourceTypeKey: 'route_table', resourceId: field(rt, 'routeTableId')!, region: ctx.region, resourceName: tags['Name'], isDefault: extractListItems(extractSection(rt, 'associationSet')).some(a => boolField(a, 'main')), tags, metadata: { routeCount: extractListItems(extractSection(rt, 'routeSet')).length }, relationships: { vpcId: field(rt, 'vpcId') } });
  }
  for (const igw of extractListItems(extractSection(igws, 'internetGatewaySet'))) {
    const tags = tagsFromSet(igw);
    out.push({ resourceTypeKey: 'internet_gateway', resourceId: field(igw, 'internetGatewayId')!, region: ctx.region, resourceName: tags['Name'], tags, relationships: { vpcIds: extractListItems(extractSection(igw, 'attachmentSet')).map(a => field(a, 'vpcId')) } });
  }
  for (const nat of extractListItems(extractSection(natGateways, 'natGatewaySet'))) {
    const tags = tagsFromSet(nat);
    out.push({ resourceTypeKey: 'nat_gateway', resourceId: field(nat, 'natGatewayId')!, region: ctx.region, resourceName: tags['Name'], state: field(nat, 'state') ?? undefined, tags, metadata: { connectivityType: field(nat, 'connectivityType') }, relationships: { vpcId: field(nat, 'vpcId'), subnetId: field(nat, 'subnetId') } });
  }
  for (const nacl of extractListItems(extractSection(nacls, 'networkAclSet'))) {
    const tags = tagsFromSet(nacl);
    out.push({ resourceTypeKey: 'network_acl', resourceId: field(nacl, 'networkAclId')!, region: ctx.region, resourceName: tags['Name'], isDefault: boolField(nacl, 'isDefault'), tags, metadata: { entryCount: extractListItems(extractSection(nacl, 'entrySet')).length }, relationships: { vpcId: field(nacl, 'vpcId') } });
  }
  for (const vpce of extractListItems(extractSection(vpcEndpoints, 'vpcEndpointSet'))) {
    const tags = tagsFromSet(vpce);
    out.push({ resourceTypeKey: 'vpc_endpoint', resourceId: field(vpce, 'vpcEndpointId')!, region: ctx.region, resourceName: tags['Name'], state: field(vpce, 'state') ?? undefined, tags, metadata: { serviceName: field(vpce, 'serviceName'), vpcEndpointType: field(vpce, 'vpcEndpointType') }, relationships: { vpcId: field(vpce, 'vpcId') } });
  }
  for (const pcx of extractListItems(extractSection(peerings, 'vpcPeeringConnectionSet'))) {
    const status = extractSection(pcx, 'status');
    const requester = extractSection(pcx, 'requesterVpcInfo');
    const accepter = extractSection(pcx, 'accepterVpcInfo');
    out.push({ resourceTypeKey: 'vpc_peering_connection', resourceId: field(pcx, 'vpcPeeringConnectionId')!, region: ctx.region, state: status ? (field(status, 'code') ?? undefined) : undefined, tags: tagsFromSet(pcx), relationships: { requesterVpcId: requester ? field(requester, 'vpcId') : null, accepterVpcId: accepter ? field(accepter, 'vpcId') : null } });
  }
  for (const lt of extractListItems(extractSection(launchTemplates, 'launchTemplates'))) {
    const tags = tagsFromSet(lt);
    out.push({ resourceTypeKey: 'ec2_launch_template', resourceId: field(lt, 'launchTemplateId')!, region: ctx.region, resourceName: field(lt, 'launchTemplateName') ?? undefined, tags, metadata: { createTime: field(lt, 'createTime'), defaultVersionNumber: numField(lt, 'defaultVersionNumber'), latestVersionNumber: numField(lt, 'latestVersionNumber') } });
  }
  for (const fl of extractListItems(extractSection(flowLogs, 'flowLogSet'))) {
    const tags = tagsFromSet(fl);
    out.push({ resourceTypeKey: 'vpc_flow_log', resourceId: field(fl, 'flowLogId')!, region: ctx.region, state: field(fl, 'flowLogStatus') ?? undefined, tags, metadata: { trafficType: field(fl, 'trafficType'), logDestinationType: field(fl, 'logDestinationType'), deliverLogsStatus: field(fl, 'deliverLogsStatus'), creationTime: field(fl, 'creationTime') }, relationships: { resourceId: field(fl, 'resourceId') } });
  }
  for (const pg of extractListItems(extractSection(placementGroups, 'placementGroupSet'))) {
    const tags = tagsFromSet(pg);
    out.push({ resourceTypeKey: 'ec2_placement_group', resourceId: field(pg, 'groupId') ?? field(pg, 'groupName')!, region: ctx.region, resourceName: field(pg, 'groupName') ?? undefined, state: field(pg, 'state') ?? undefined, tags, metadata: { strategy: field(pg, 'strategy') } });
  }
  for (const pl of extractListItems(extractSection(prefixLists, 'prefixListSet'))) {
    // AWS's own service-managed prefix lists (com.amazonaws.<region>.s3,
    // .dynamodb, ...) show up in this same list with ownerId "AWS" — every
    // region has several regardless of anything the customer did. Confirmed
    // via a real discovery run: without this filter, a 17-region scan
    // returned 250 "prefix lists" that were almost entirely these, drowning
    // out the handful (if any) the customer actually created.
    if (field(pl, 'ownerId') === 'AWS') continue;
    const tags = tagsFromSet(pl);
    out.push({ resourceTypeKey: 'prefix_list', resourceId: field(pl, 'prefixListId')!, region: ctx.region, resourceName: field(pl, 'prefixListName') ?? undefined, state: field(pl, 'state') ?? undefined, tags, metadata: { addressFamily: field(pl, 'addressFamily'), maxEntries: numField(pl, 'maxEntries'), ownerId: field(pl, 'ownerId') } });
  }

  return out;
}
