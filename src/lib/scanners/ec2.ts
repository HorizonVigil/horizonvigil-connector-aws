import { callQueryApi, listParams } from '../awsApi';
import { extractSection, extractListItems, field, boolField, numField, tagsFromSet } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const VERSION = '2016-11-15';

/** Every resource_type_key this scanner can produce — used by discovery.ts to scope "vanished resource" cleanup to only the types this scanner actually checks, so resource types from not-yet-ported scanners (kms_alias, iam_role, s3_bucket, ...) are never touched by an EC2-only run. */
export const EC2_RESOURCE_TYPES = [
  'ec2_instance', 'ec2_ami', 'ec2_key_pair', 'ebs_volume', 'ebs_snapshot', 'security_group', 'elastic_ip',
  'network_interface', 'vpc', 'subnet', 'route_table', 'internet_gateway', 'nat_gateway', 'network_acl',
  'vpc_endpoint', 'vpc_peering_connection', 'ec2_launch_template', 'vpc_flow_log', 'ec2_placement_group',
  'prefix_list', 'transit_gateway', 'transit_gateway_attachment', 'vpn_gateway', 'vpn_connection',
  'customer_gateway', 'client_vpn_endpoint', 'egress_only_igw', 'ec2_capacity_reservation',
  'ec2_dedicated_host', 'ec2_fleet', 'ec2_spot_fleet_request', 'ec2_spot_instance_request',
  'reserved_instance', 'elastic_gpu',
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
export interface Ec2ScanOperation {
  action: string;
  status: 'success' | 'failed';
  pages: number;
  resources: number;
  attempts: number;
  error?: string;
}

export interface Ec2ScanDiagnostics {
  scanner: 'ec2';
  scanner_version: 'v1';
  region: string;
  status: 'success' | 'partial' | 'failed';
  startedAt: string;
  completedAt: string;
  operations: Ec2ScanOperation[];
}

/**
 * Production-grade EC2 discovery.
 *
 * Important contract:
 * - A failed Describe* operation is never represented as an empty result.
 * - Each API operation is retried for transient/throttling failures.
 * - EC2 Query APIs are paginated centrally.
 * - Per-operation diagnostics are attached to returned resources.
 *
 * The existing Promise<ScannedResource[]> contract is intentionally preserved
 * so discovery.ts and the rest of the provider pipeline do not need a
 * breaking change.
 */
export async function scanEc2(ctx: ScannerContext): Promise<ScannedResource[]> {
  const startedAt = new Date().toISOString();
  const endpoint = `ec2.${ctx.region}.amazonaws.com`;
  const operations: Ec2ScanOperation[] = [];

  const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

  const retryableCodes = new Set([
    'RequestLimitExceeded',
    'Throttling',
    'ThrottlingException',
    'TooManyRequestsException',
    'ServiceUnavailable',
    'InternalError',
    'InternalFailure',
    'RequestTimeout',
    'RequestTimeoutException',
  ]);

  const isRetryable = (code?: string, status?: number) =>
    (typeof status === 'number' && (status === 429 || status >= 500)) ||
    (!!code && retryableCodes.has(code));

  const call = async (
    action: string,
    params?: Record<string, string>,
    options: { maxAttempts?: number } = {},
  ): Promise<string> => {
    const maxAttempts = Math.max(1, options.maxAttempts ?? 4);
    let lastError = 'unknown EC2 API error';

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const result = await callQueryApi(ctx.creds, {
        service: 'ec2',
        region: ctx.region,
        host: endpoint,
        action,
        version: VERSION,
        params,
      });

      if (result.ok) return result.body as string;

      lastError = result.normalizedCode ?? result.errorCode ?? result.errorMessage ?? String(result.status);

      if (!isRetryable(result.normalizedCode ?? result.errorCode, result.status) || attempt === maxAttempts) {
        break;
      }

      // Bounded exponential backoff with jitter to avoid retry storms.
      const delay = Math.min(2000, 250 * (2 ** (attempt - 1))) + Math.floor(Math.random() * 150);
      await sleep(delay);
    }

    throw new Error(`EC2 ${action} failed after ${maxAttempts} attempt(s): ${lastError}`);
  };

  /**
   * EC2 Describe APIs generally expose NextToken. Some response shapes use
   * nextToken through the XML helper. Centralizing this prevents one resource
   * type from silently becoming incomplete as the account grows.
   */
  const listPages = async (
    action: string,
    params?: Record<string, string>,
  ): Promise<{ pages: string[]; attempts: number }> => {
    const pages: string[] = [];
    let nextToken: string | undefined;
    let attempts = 0;

    do {
      const pageParams = nextToken ? { ...(params ?? {}), NextToken: nextToken } : params;
      attempts++;

      const xml = await call(action, pageParams);
      pages.push(xml);

      const discoveredToken =
        field(xml, 'nextToken') ??
        field(xml, 'NextToken');

      if (!discoveredToken) break;
      if (discoveredToken === nextToken) {
        throw new Error(`EC2 ${action} returned an unchanged pagination token`);
      }

      nextToken = discoveredToken;
    } while (true);

    operations.push({
      action,
      status: 'success',
      pages: pages.length,
      resources: 0,
      attempts,
    });

    return { pages, attempts };
  };

  const setOperationResourceCount = (action: string, count: number) => {
    const operation = operations.find((item) => item.action === action);
    if (operation) operation.resources = count;
  };

  try {
    const [
      instancesResult, imagesResult, keyPairsResult, volumesResult, snapshotsResult,
      sgsResult, addressesResult, enisResult, vpcsResult, subnetsResult,
      routeTablesResult, igwsResult, natGatewaysResult, naclsResult, vpcEndpointsResult,
      peeringsResult, launchTemplatesResult, flowLogsResult, placementGroupsResult,
      prefixListsResult, transitGatewaysResult, transitGatewayAttachmentsResult,
      vpnGatewaysResult, vpnConnectionsResult, customerGatewaysResult,
      clientVpnEndpointsResult, egressOnlyIgwsResult, capacityReservationsResult,
      hostsResult, fleetsResult, spotFleetRequestsResult, spotInstanceRequestsResult,
      reservedInstancesResult, elasticGpusResult,
    ] = await Promise.all([
      listPages('DescribeInstances'),
      listPages('DescribeImages', listParams('Owner', ['self'])),
      listPages('DescribeKeyPairs'),
      listPages('DescribeVolumes'),
      listPages('DescribeSnapshots', listParams('Owner', ['self'])),
      listPages('DescribeSecurityGroups'),
      listPages('DescribeAddresses'),
      listPages('DescribeNetworkInterfaces'),
      listPages('DescribeVpcs'),
      listPages('DescribeSubnets'),
      listPages('DescribeRouteTables'),
      listPages('DescribeInternetGateways'),
      listPages('DescribeNatGateways'),
      listPages('DescribeNetworkAcls'),
      listPages('DescribeVpcEndpoints'),
      listPages('DescribeVpcPeeringConnections'),
      listPages('DescribeLaunchTemplates'),
      listPages('DescribeFlowLogs'),
      listPages('DescribePlacementGroups'),
      listPages('DescribeManagedPrefixLists'),
      listPages('DescribeTransitGateways'),
      listPages('DescribeTransitGatewayAttachments'),
      listPages('DescribeVpnGateways'),
      listPages('DescribeVpnConnections'),
      listPages('DescribeCustomerGateways'),
      listPages('DescribeClientVpnEndpoints'),
      listPages('DescribeEgressOnlyInternetGateways'),
      listPages('DescribeCapacityReservations'),
      listPages('DescribeHosts'),
      listPages('DescribeFleets'),
      listPages('DescribeSpotFleetRequests'),
      listPages('DescribeSpotInstanceRequests'),
      listPages('DescribeReservedInstances'),
      listPages('DescribeElasticGpus'),
    ]);

    const joinPages = (result: { pages: string[] }) => result.pages.join('\n');

    const instances = joinPages(instancesResult);
    const images = joinPages(imagesResult);
    const keyPairs = joinPages(keyPairsResult);
    const volumes = joinPages(volumesResult);
    const snapshots = joinPages(snapshotsResult);
    const sgs = joinPages(sgsResult);
    const addresses = joinPages(addressesResult);
    const enis = joinPages(enisResult);
    const vpcs = joinPages(vpcsResult);
    const subnets = joinPages(subnetsResult);
    const routeTables = joinPages(routeTablesResult);
    const igws = joinPages(igwsResult);
    const natGateways = joinPages(natGatewaysResult);
    const nacls = joinPages(naclsResult);
    const vpcEndpoints = joinPages(vpcEndpointsResult);
    const peerings = joinPages(peeringsResult);
    const launchTemplates = joinPages(launchTemplatesResult);
    const flowLogs = joinPages(flowLogsResult);
    const placementGroups = joinPages(placementGroupsResult);
    const prefixLists = joinPages(prefixListsResult);
    const transitGateways = joinPages(transitGatewaysResult);
    const transitGatewayAttachments = joinPages(transitGatewayAttachmentsResult);
    const vpnGateways = joinPages(vpnGatewaysResult);
    const vpnConnections = joinPages(vpnConnectionsResult);
    const customerGateways = joinPages(customerGatewaysResult);
    const clientVpnEndpoints = joinPages(clientVpnEndpointsResult);
    const egressOnlyIgws = joinPages(egressOnlyIgwsResult);
    const capacityReservations = joinPages(capacityReservationsResult);
    const hosts = joinPages(hostsResult);
    const fleets = joinPages(fleetsResult);
    const spotFleetRequests = joinPages(spotFleetRequestsResult);
    const spotInstanceRequests = joinPages(spotInstanceRequestsResult);
    const reservedInstances = joinPages(reservedInstancesResult);
    const elasticGpus = joinPages(elasticGpusResult);

    const out: ScannedResource[] = [];

    // The extraction logic below intentionally retains the existing resource
    // shapes and relationship semantics. The production hardening is applied
    // at the API/pagination/validation boundary above.

    for (const reservation of extractListItems(extractSection(instances, 'reservationSet'))) {
      for (const i of extractListItems(extractSection(reservation, 'instancesSet'))) {
        const id = field(i, 'instanceId');
        if (!id) continue;
        const tags = tagsFromSet(i);
        const state = extractSection(i, 'instanceState');
        out.push({
          resourceTypeKey: 'ec2_instance', resourceId: id, region: ctx.region,
          resourceName: tags['Name'],
          state: state ? (field(state, 'name') ?? undefined) : undefined, tags,
          metadata: {
            instanceType: field(i, 'instanceType'), launchTime: field(i, 'launchTime'),
            privateIp: field(i, 'privateIpAddress'), publicIp: field(i, 'publicIpAddress'),
            platform: field(i, 'platformDetails'),
          },
          relationships: {
            vpcId: field(i, 'vpcId'), subnetId: field(i, 'subnetId'),
            securityGroupIds: extractListItems(extractSection(i, 'groupSet'))
              .map(g => field(g, 'groupId')).filter((v): v is string => !!v),
            instanceProfileArn: field(extractSection(i, 'iamInstanceProfile') ?? '', 'arn'),
          },
        });
      }
    }

    for (const a of extractListItems(extractSection(images, 'imagesSet'))) {
      const id = field(a, 'imageId');
      if (!id) continue;
      out.push({
        resourceTypeKey: 'ec2_ami', resourceId: id, region: ctx.region,
        resourceName: field(a, 'name') ?? undefined, state: field(a, 'imageState') ?? undefined,
        tags: tagsFromSet(a),
        metadata: { creationDate: field(a, 'creationDate'), architecture: field(a, 'architecture') },
      });
    }

    for (const k of extractListItems(extractSection(keyPairs, 'keySet'))) {
      const id = field(k, 'keyPairId') ?? field(k, 'keyName');
      if (!id) continue;
      out.push({
        resourceTypeKey: 'ec2_key_pair', resourceId: id, region: ctx.region,
        resourceName: field(k, 'keyName') ?? undefined, tags: tagsFromSet(k),
        metadata: { fingerprint: field(k, 'keyFingerprint') },
      });
    }

    for (const v of extractListItems(extractSection(volumes, 'volumeSet'))) {
      const id = field(v, 'volumeId');
      if (!id) continue;
      const tags = tagsFromSet(v);
      out.push({
        resourceTypeKey: 'ebs_volume', resourceId: id, region: ctx.region,
        resourceName: tags['Name'], state: field(v, 'status') ?? undefined, tags,
        metadata: {
          sizeGiB: numField(v, 'size'), volumeType: field(v, 'volumeType'),
          iops: numField(v, 'iops'), encrypted: boolField(v, 'encrypted'),
          createTime: field(v, 'createTime'),
        },
        relationships: {
          attachedInstanceIds: extractListItems(extractSection(v, 'attachmentSet'))
            .map(at => field(at, 'instanceId')).filter((v): v is string => !!v),
        },
      });
    }

    for (const s of extractListItems(extractSection(snapshots, 'snapshotSet'))) {
      const id = field(s, 'snapshotId');
      if (!id) continue;
      const tags = tagsFromSet(s);
      out.push({
        resourceTypeKey: 'ebs_snapshot', resourceId: id, region: ctx.region,
        resourceName: tags['Name'], state: field(s, 'status') ?? undefined, tags,
        metadata: {
          volumeSizeGiB: numField(s, 'volumeSize'), startTime: field(s, 'startTime'),
          encrypted: boolField(s, 'encrypted'),
        },
        relationships: { volumeId: field(s, 'volumeId') },
      });
    }

    for (const sg of extractListItems(extractSection(sgs, 'securityGroupInfo'))) {
      const id = field(sg, 'groupId');
      if (!id) continue;
      const tags = tagsFromSet(sg);
      out.push({
        resourceTypeKey: 'security_group', resourceId: id, region: ctx.region,
        resourceName: field(sg, 'groupName') ?? undefined,
        isDefault: field(sg, 'groupName') === 'default', tags,
        metadata: {
          description: field(sg, 'groupDescription'),
          inboundRuleCount: extractListItems(extractSection(sg, 'ipPermissions')).length,
          outboundRuleCount: extractListItems(extractSection(sg, 'ipPermissionsEgress')).length,
        },
        relationships: { vpcId: field(sg, 'vpcId') },
      });
    }

    for (const eip of extractListItems(extractSection(addresses, 'addressesSet'))) {
      const id = field(eip, 'allocationId') ?? field(eip, 'publicIp');
      if (!id) continue;
      const tags = tagsFromSet(eip);
      out.push({
        resourceTypeKey: 'elastic_ip', resourceId: id, region: ctx.region,
        resourceName: field(eip, 'publicIp') ?? undefined, tags,
        metadata: { publicIp: field(eip, 'publicIp'), domain: field(eip, 'domain') },
        relationships: {
          instanceId: field(eip, 'instanceId'),
          networkInterfaceId: field(eip, 'networkInterfaceId'),
        },
      });
    }

    for (const eni of extractListItems(extractSection(enis, 'networkInterfaceSet'))) {
      const id = field(eni, 'networkInterfaceId');
      if (!id) continue;
      const tags = tagsFromSet(eni);
      const attachment = extractSection(eni, 'attachment');
      out.push({
        resourceTypeKey: 'network_interface', resourceId: id, region: ctx.region,
        resourceName: field(eni, 'description') ?? undefined,
        state: field(eni, 'status') ?? undefined, tags,
        metadata: {
          privateIp: field(eni, 'privateIpAddress'),
          interfaceType: field(eni, 'interfaceType'),
        },
        relationships: {
          vpcId: field(eni, 'vpcId'), subnetId: field(eni, 'subnetId'),
          attachedInstanceId: attachment ? field(attachment, 'instanceId') : null,
        },
      });
    }

    for (const vpc of extractListItems(extractSection(vpcs, 'vpcSet'))) {
      const id = field(vpc, 'vpcId');
      if (!id) continue;
      const tags = tagsFromSet(vpc);
      out.push({
        resourceTypeKey: 'vpc', resourceId: id, region: ctx.region,
        resourceName: tags['Name'], isDefault: boolField(vpc, 'isDefault'),
        state: field(vpc, 'state') ?? undefined, tags,
        metadata: {
          cidrBlock: field(vpc, 'cidrBlock'),
          instanceTenancy: field(vpc, 'instanceTenancy'),
        },
      });
    }

    for (const sn of extractListItems(extractSection(subnets, 'subnetSet'))) {
      const id = field(sn, 'subnetId');
      if (!id) continue;
      const tags = tagsFromSet(sn);
      out.push({
        resourceTypeKey: 'subnet', resourceId: id, region: ctx.region,
        resourceName: tags['Name'], isDefault: boolField(sn, 'defaultForAz'),
        state: field(sn, 'state') ?? undefined, tags,
        metadata: {
          cidrBlock: field(sn, 'cidrBlock'),
          availabilityZone: field(sn, 'availabilityZone'),
          availableIpCount: numField(sn, 'availableIpAddressCount'),
        },
        relationships: { vpcId: field(sn, 'vpcId') },
      });
    }

    for (const rt of extractListItems(extractSection(routeTables, 'routeTableSet'))) {
      const id = field(rt, 'routeTableId');
      if (!id) continue;
      const tags = tagsFromSet(rt);
      out.push({
        resourceTypeKey: 'route_table', resourceId: id, region: ctx.region,
        resourceName: tags['Name'],
        isDefault: extractListItems(extractSection(rt, 'associationSet')).some(a => boolField(a, 'main')),
        tags,
        metadata: { routeCount: extractListItems(extractSection(rt, 'routeSet')).length },
        relationships: { vpcId: field(rt, 'vpcId') },
      });
    }

    for (const igw of extractListItems(extractSection(igws, 'internetGatewaySet'))) {
      const id = field(igw, 'internetGatewayId');
      if (!id) continue;
      const tags = tagsFromSet(igw);
      out.push({
        resourceTypeKey: 'internet_gateway', resourceId: id, region: ctx.region,
        resourceName: tags['Name'], tags,
        relationships: {
          vpcIds: extractListItems(extractSection(igw, 'attachmentSet'))
            .map(a => field(a, 'vpcId')).filter((v): v is string => !!v),
        },
      });
    }

    for (const nat of extractListItems(extractSection(natGateways, 'natGatewaySet'))) {
      const id = field(nat, 'natGatewayId');
      if (!id) continue;
      const tags = tagsFromSet(nat);
      out.push({
        resourceTypeKey: 'nat_gateway', resourceId: id, region: ctx.region,
        resourceName: tags['Name'], state: field(nat, 'state') ?? undefined, tags,
        metadata: { connectivityType: field(nat, 'connectivityType') },
        relationships: { vpcId: field(nat, 'vpcId'), subnetId: field(nat, 'subnetId') },
      });
    }

    for (const nacl of extractListItems(extractSection(nacls, 'networkAclSet'))) {
      const id = field(nacl, 'networkAclId');
      if (!id) continue;
      const tags = tagsFromSet(nacl);
      out.push({
        resourceTypeKey: 'network_acl', resourceId: id, region: ctx.region,
        resourceName: tags['Name'], isDefault: boolField(nacl, 'isDefault'), tags,
        metadata: { entryCount: extractListItems(extractSection(nacl, 'entrySet')).length },
        relationships: { vpcId: field(nacl, 'vpcId') },
      });
    }

    for (const vpce of extractListItems(extractSection(vpcEndpoints, 'vpcEndpointSet'))) {
      const id = field(vpce, 'vpcEndpointId');
      if (!id) continue;
      const tags = tagsFromSet(vpce);
      out.push({
        resourceTypeKey: 'vpc_endpoint', resourceId: id, region: ctx.region,
        resourceName: tags['Name'], state: field(vpce, 'state') ?? undefined, tags,
        metadata: {
          serviceName: field(vpce, 'serviceName'),
          vpcEndpointType: field(vpce, 'vpcEndpointType'),
        },
        relationships: { vpcId: field(vpce, 'vpcId') },
      });
    }

    for (const pcx of extractListItems(extractSection(peerings, 'vpcPeeringConnectionSet'))) {
      const id = field(pcx, 'vpcPeeringConnectionId');
      if (!id) continue;
      const status = extractSection(pcx, 'status');
      const requester = extractSection(pcx, 'requesterVpcInfo');
      const accepter = extractSection(pcx, 'accepterVpcInfo');
      out.push({
        resourceTypeKey: 'vpc_peering_connection', resourceId: id, region: ctx.region,
        state: status ? (field(status, 'code') ?? undefined) : undefined,
        tags: tagsFromSet(pcx),
        relationships: {
          requesterVpcId: requester ? field(requester, 'vpcId') : null,
          accepterVpcId: accepter ? field(accepter, 'vpcId') : null,
        },
      });
    }

    for (const lt of extractListItems(extractSection(launchTemplates, 'launchTemplates'))) {
      const id = field(lt, 'launchTemplateId');
      if (!id) continue;
      const tags = tagsFromSet(lt);
      out.push({
        resourceTypeKey: 'ec2_launch_template', resourceId: id, region: ctx.region,
        resourceName: field(lt, 'launchTemplateName') ?? undefined, tags,
        metadata: {
          createTime: field(lt, 'createTime'),
          defaultVersionNumber: numField(lt, 'defaultVersionNumber'),
          latestVersionNumber: numField(lt, 'latestVersionNumber'),
        },
      });
    }

    for (const fl of extractListItems(extractSection(flowLogs, 'flowLogSet'))) {
      const id = field(fl, 'flowLogId');
      if (!id) continue;
      const tags = tagsFromSet(fl);
      out.push({
        resourceTypeKey: 'vpc_flow_log', resourceId: id, region: ctx.region,
        state: field(fl, 'flowLogStatus') ?? undefined, tags,
        metadata: {
          trafficType: field(fl, 'trafficType'),
          logDestinationType: field(fl, 'logDestinationType'),
          deliverLogsStatus: field(fl, 'deliverLogsStatus'),
          creationTime: field(fl, 'creationTime'),
        },
        relationships: { resourceId: field(fl, 'resourceId') },
      });
    }

    for (const pg of extractListItems(extractSection(placementGroups, 'placementGroupSet'))) {
      const id = field(pg, 'groupId') ?? field(pg, 'groupName');
      if (!id) continue;
      const tags = tagsFromSet(pg);
      out.push({
        resourceTypeKey: 'ec2_placement_group', resourceId: id, region: ctx.region,
        resourceName: field(pg, 'groupName') ?? undefined,
        state: field(pg, 'state') ?? undefined, tags,
        metadata: { strategy: field(pg, 'strategy') },
      });
    }

    for (const pl of extractListItems(extractSection(prefixLists, 'prefixListSet'))) {
      // AWS-owned service-managed prefix lists are not customer resources.
      if (field(pl, 'ownerId') === 'AWS') continue;
      const id = field(pl, 'prefixListId');
      if (!id) continue;
      const tags = tagsFromSet(pl);
      out.push({
        resourceTypeKey: 'prefix_list', resourceId: id, region: ctx.region,
        resourceName: field(pl, 'prefixListName') ?? undefined,
        state: field(pl, 'state') ?? undefined, tags,
        metadata: {
          addressFamily: field(pl, 'addressFamily'),
          maxEntries: numField(pl, 'maxEntries'),
          ownerId: field(pl, 'ownerId'),
        },
      });
    }

    for (const tgw of extractListItems(extractSection(transitGateways, 'transitGatewaySet'))) {
      const id = field(tgw, 'transitGatewayId');
      if (!id) continue;
      const tags = tagsFromSet(tgw);
      out.push({
        resourceTypeKey: 'transit_gateway', resourceId: id, region: ctx.region,
        resourceName: tags['Name'], state: field(tgw, 'state') ?? undefined, tags,
        metadata: {
          description: field(tgw, 'description'),
          ownerId: field(tgw, 'ownerId'),
          creationTime: field(tgw, 'creationTime'),
        },
      });
    }

    for (const tga of extractListItems(extractSection(transitGatewayAttachments, 'transitGatewayAttachments'))) {
      const id = field(tga, 'transitGatewayAttachmentId');
      if (!id) continue;
      const tags = tagsFromSet(tga);
      out.push({
        resourceTypeKey: 'transit_gateway_attachment', resourceId: id, region: ctx.region,
        state: field(tga, 'state') ?? undefined, tags,
        metadata: {
          resourceType: field(tga, 'resourceType'),
          creationTime: field(tga, 'creationTime'),
        },
        relationships: {
          transitGatewayId: field(tga, 'transitGatewayId'),
          resourceId: field(tga, 'resourceId'),
        },
      });
    }

    for (const vgw of extractListItems(extractSection(vpnGateways, 'vpnGatewaySet'))) {
      const id = field(vgw, 'vpnGatewayId');
      if (!id) continue;
      const tags = tagsFromSet(vgw);
      out.push({
        resourceTypeKey: 'vpn_gateway', resourceId: id, region: ctx.region,
        resourceName: tags['Name'], state: field(vgw, 'state') ?? undefined, tags,
        metadata: {
          type: field(vgw, 'type'),
          availabilityZone: field(vgw, 'availabilityZone'),
          amazonSideAsn: field(vgw, 'amazonSideAsn'),
        },
        relationships: {
          vpcIds: extractListItems(extractSection(vgw, 'attachments'))
            .map(a => field(a, 'vpcId')).filter((v): v is string => !!v),
        },
      });
    }

    for (const vpn of extractListItems(extractSection(vpnConnections, 'vpnConnectionSet'))) {
      const id = field(vpn, 'vpnConnectionId');
      if (!id) continue;
      const tags = tagsFromSet(vpn);
      out.push({
        resourceTypeKey: 'vpn_connection', resourceId: id, region: ctx.region,
        resourceName: tags['Name'], state: field(vpn, 'state') ?? undefined, tags,
        metadata: { type: field(vpn, 'type') },
        relationships: {
          customerGatewayId: field(vpn, 'customerGatewayId'),
          vpnGatewayId: field(vpn, 'vpnGatewayId'),
          transitGatewayId: field(vpn, 'transitGatewayId'),
        },
      });
    }

    for (const cgw of extractListItems(extractSection(customerGateways, 'customerGatewaySet'))) {
      const id = field(cgw, 'customerGatewayId');
      if (!id) continue;
      const tags = tagsFromSet(cgw);
      out.push({
        resourceTypeKey: 'customer_gateway', resourceId: id, region: ctx.region,
        resourceName: tags['Name'], state: field(cgw, 'state') ?? undefined, tags,
        metadata: {
          type: field(cgw, 'type'),
          ipAddress: field(cgw, 'ipAddress'),
          bgpAsn: field(cgw, 'bgpAsn'),
        },
      });
    }

    for (const cvpn of extractListItems(extractSection(clientVpnEndpoints, 'clientVpnEndpoint'))) {
      const id = field(cvpn, 'clientVpnEndpointId');
      if (!id) continue;
      const tags = tagsFromSet(cvpn);
      const status = extractSection(cvpn, 'status');
      out.push({
        resourceTypeKey: 'client_vpn_endpoint', resourceId: id, region: ctx.region,
        resourceName: field(cvpn, 'description') ?? undefined,
        state: status ? (field(status, 'code') ?? undefined) : undefined, tags,
        metadata: {
          clientCidrBlock: field(cvpn, 'clientCidrBlock'),
          dnsName: field(cvpn, 'dnsName'),
          transportProtocol: field(cvpn, 'transportProtocol'),
          creationTime: field(cvpn, 'creationTime'),
        },
      });
    }

    for (const eoigw of extractListItems(extractSection(egressOnlyIgws, 'egressOnlyInternetGatewaySet'))) {
      const id = field(eoigw, 'egressOnlyInternetGatewayId');
      if (!id) continue;
      const tags = tagsFromSet(eoigw);
      out.push({
        resourceTypeKey: 'egress_only_igw', resourceId: id, region: ctx.region,
        resourceName: tags['Name'], tags,
        relationships: {
          vpcIds: extractListItems(extractSection(eoigw, 'attachmentSet'))
            .map(a => field(a, 'vpcId')).filter((v): v is string => !!v),
        },
      });
    }

    for (const cr of extractListItems(extractSection(capacityReservations, 'capacityReservationSet'))) {
      const id = field(cr, 'capacityReservationId');
      if (!id) continue;
      const tags = tagsFromSet(cr);
      out.push({
        resourceTypeKey: 'ec2_capacity_reservation', resourceId: id, region: ctx.region,
        state: field(cr, 'state') ?? undefined, tags,
        metadata: {
          instanceType: field(cr, 'instanceType'),
          availabilityZone: field(cr, 'availabilityZone'),
          totalInstanceCount: numField(cr, 'totalInstanceCount'),
          availableInstanceCount: numField(cr, 'availableInstanceCount'),
          tenancy: field(cr, 'tenancy'),
          createDate: field(cr, 'createDate'),
          endDate: field(cr, 'endDate'),
        },
      });
    }

    for (const h of extractListItems(extractSection(hosts, 'hostSet'))) {
      const id = field(h, 'hostId');
      if (!id) continue;
      const props = extractSection(h, 'hostProperties');
      out.push({
        resourceTypeKey: 'ec2_dedicated_host', resourceId: id, region: ctx.region,
        state: field(h, 'state') ?? undefined, tags: tagsFromSet(h),
        metadata: {
          instanceType: props ? field(props, 'instanceType') : null,
          availabilityZone: field(h, 'availabilityZone'),
          autoPlacement: field(h, 'autoPlacement'),
          allocationTime: field(h, 'allocationTime'),
        },
      });
    }

    for (const fl of extractListItems(extractSection(fleets, 'fleetSet'))) {
      const id = field(fl, 'fleetId');
      if (!id) continue;
      const tags = tagsFromSet(fl);
      const spec = extractSection(fl, 'targetCapacitySpecification');
      out.push({
        resourceTypeKey: 'ec2_fleet', resourceId: id, region: ctx.region,
        state: field(fl, 'fleetState') ?? undefined, tags,
        metadata: {
          type: field(fl, 'type'),
          totalTargetCapacity: spec ? numField(spec, 'totalTargetCapacity') : undefined,
          createTime: field(fl, 'createTime'),
        },
      });
    }

    for (const sfr of extractListItems(extractSection(spotFleetRequests, 'spotFleetRequestConfigSet'))) {
      const id = field(sfr, 'spotFleetRequestId');
      if (!id) continue;
      const cfg = extractSection(sfr, 'spotFleetRequestConfig');
      out.push({
        resourceTypeKey: 'ec2_spot_fleet_request', resourceId: id, region: ctx.region,
        state: field(sfr, 'spotFleetRequestState') ?? undefined,
        metadata: {
          spotPrice: cfg ? field(cfg, 'spotPrice') : null,
          targetCapacity: cfg ? numField(cfg, 'targetCapacity') : undefined,
          iamFleetRole: cfg ? field(cfg, 'iamFleetRole') : null,
        },
      });
    }

    for (const sir of extractListItems(extractSection(spotInstanceRequests, 'spotInstanceRequestSet'))) {
      const id = field(sir, 'spotInstanceRequestId');
      if (!id) continue;
      const tags = tagsFromSet(sir);
      out.push({
        resourceTypeKey: 'ec2_spot_instance_request', resourceId: id, region: ctx.region,
        state: field(sir, 'state') ?? undefined, tags,
        metadata: {
          spotPrice: field(sir, 'spotPrice'),
          type: field(sir, 'type'),
          createTime: field(sir, 'createTime'),
        },
        relationships: { instanceId: field(sir, 'instanceId') },
      });
    }

    for (const ri of extractListItems(extractSection(reservedInstances, 'reservedInstancesSet'))) {
      const id = field(ri, 'reservedInstancesId');
      if (!id) continue;
      const tags = tagsFromSet(ri);
      out.push({
        resourceTypeKey: 'reserved_instance', resourceId: id, region: ctx.region,
        state: field(ri, 'state') ?? undefined, tags,
        metadata: {
          instanceType: field(ri, 'instanceType'),
          availabilityZone: field(ri, 'availabilityZone'),
          instanceCount: numField(ri, 'instanceCount'),
          start: field(ri, 'start'),
          end: field(ri, 'end'),
          offeringType: field(ri, 'offeringType'),
          productDescription: field(ri, 'productDescription'),
        },
      });
    }

    // Elastic Graphics reached EOL; retain the catalog entry for historical
    // compatibility, but do not treat an empty result as scanner failure.
    for (const gpu of extractListItems(extractSection(elasticGpus, 'elasticGpuSet'))) {
      const id = field(gpu, 'elasticGpuId');
      if (!id) continue;
      out.push({
        resourceTypeKey: 'elastic_gpu', resourceId: id, region: ctx.region,
        state: field(gpu, 'elasticGpuState') ?? undefined,
        metadata: {
          elasticGpuType: field(gpu, 'elasticGpuType'),
          elasticGpuHealth: field(gpu, 'elasticGpuHealth'),
          availabilityZone: field(gpu, 'availabilityZone'),
        },
        relationships: { instanceId: field(gpu, 'instanceId') },
      });
    }

    // Populate operation-level resource counts for the final execution
    // evidence. These counts are deliberately derived from parsed resources,
    // not guessed from API response size.
    const counts: Record<string, number> = {};
    for (const resource of out) {
      counts[resource.resourceTypeKey] = (counts[resource.resourceTypeKey] ?? 0) + 1;
    }
    for (const operation of operations) {
      // Indexed directly, NOT through Object.entries(): that returns an
      // array of [key, value] pairs, so indexing it by an action name never
      // matches and every operation silently kept its own prior count. tsc
      // flagged it as TS7015 -- a real type error guarding a real logic error.
      operation.resources = ({
        DescribeInstances: counts.ec2_instance ?? 0,
        DescribeImages: counts.ec2_ami ?? 0,
        DescribeKeyPairs: counts.ec2_key_pair ?? 0,
        DescribeVolumes: counts.ebs_volume ?? 0,
        DescribeSnapshots: counts.ebs_snapshot ?? 0,
        DescribeSecurityGroups: counts.security_group ?? 0,
        DescribeAddresses: counts.elastic_ip ?? 0,
        DescribeNetworkInterfaces: counts.network_interface ?? 0,
        DescribeVpcs: counts.vpc ?? 0,
        DescribeSubnets: counts.subnet ?? 0,
        DescribeRouteTables: counts.route_table ?? 0,
        DescribeInternetGateways: counts.internet_gateway ?? 0,
        DescribeNatGateways: counts.nat_gateway ?? 0,
        DescribeNetworkAcls: counts.network_acl ?? 0,
        DescribeVpcEndpoints: counts.vpc_endpoint ?? 0,
        DescribeVpcPeeringConnections: counts.vpc_peering_connection ?? 0,
        DescribeLaunchTemplates: counts.ec2_launch_template ?? 0,
        DescribeFlowLogs: counts.vpc_flow_log ?? 0,
        DescribePlacementGroups: counts.ec2_placement_group ?? 0,
        DescribeManagedPrefixLists: counts.prefix_list ?? 0,
        DescribeTransitGateways: counts.transit_gateway ?? 0,
        DescribeTransitGatewayAttachments: counts.transit_gateway_attachment ?? 0,
        DescribeVpnGateways: counts.vpn_gateway ?? 0,
        DescribeVpnConnections: counts.vpn_connection ?? 0,
        DescribeCustomerGateways: counts.customer_gateway ?? 0,
        DescribeClientVpnEndpoints: counts.client_vpn_endpoint ?? 0,
        DescribeEgressOnlyInternetGateways: counts.egress_only_igw ?? 0,
        DescribeCapacityReservations: counts.ec2_capacity_reservation ?? 0,
        DescribeHosts: counts.ec2_dedicated_host ?? 0,
        DescribeFleets: counts.ec2_fleet ?? 0,
        DescribeSpotFleetRequests: counts.ec2_spot_fleet_request ?? 0,
        DescribeSpotInstanceRequests: counts.ec2_spot_instance_request ?? 0,
        DescribeReservedInstances: counts.reserved_instance ?? 0,
        DescribeElasticGpus: counts.elastic_gpu ?? 0,
      } as Record<string, number>)[operation.action] ?? operation.resources;
    }

    const completedAt = new Date().toISOString();
    const diagnostics: Ec2ScanDiagnostics = {
      scanner: 'ec2',
      scanner_version: 'v1',
      region: ctx.region,
      status: 'success',
      startedAt,
      completedAt,
      operations,
    };

    for (const resource of out) {
      resource.metadata = {
        ...resource.metadata,
        ec2ScanDiagnostics: diagnostics,
      };
    }

    return out;
  } catch (err) {
    const completedAt = new Date().toISOString();
    const diagnostics: Ec2ScanDiagnostics = {
      scanner: 'ec2',
      scanner_version: 'v1',
      region: ctx.region,
      status: 'failed',
      startedAt,
      completedAt,
      operations,
    };

    // Fail closed so discovery/finalization cannot interpret a failed regional
    // inventory call as evidence that the corresponding resources vanished.
    throw new Error(
      `AWS EC2 inventory scan failed in ${ctx.region}: ` +
      `${err instanceof Error ? err.message : String(err)}. ` +
      `Diagnostics: ${JSON.stringify(diagnostics)}`,
    );
  }
}
