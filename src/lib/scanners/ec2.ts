import { listParams } from '../awsApi';
import { extractSection, extractListItems, field, boolField, numField, tagsFromSet } from '../xmlList';
import { paginateQueryApi, detectQueryTruncation, incompleteSink, type PaginationTermination } from '../pagination';
import type { ScannedResource, ScannerContext } from './types';
import { normalizeProtocol, parsePermissions, SECURITY_GROUP_RULES_EVIDENCE_VERSION } from './securityGroupRules';
import { mapWithConcurrency } from './scannerSupport';

const VERSION = '2016-11-15';

/**
 * Describe* operations in flight at once, per region.
 *
 * EC2's non-mutating API calls share one per-account token bucket; firing all
 * 34 at once (times every region scanned concurrently) burst straight into
 * RequestLimitExceeded and turned the scan into a retry storm. It also blew
 * past the Workers simultaneous-connection limit, which queues silently.
 */
const OPERATION_CONCURRENCY = 8;

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

export type Ec2ResourceType = (typeof EC2_RESOURCE_TYPES)[number];

interface OperationSpec {
  action: string;
  /** The AWS response container for this Describe* operation. */
  section: string;
  resourceType: Ec2ResourceType;
  params?: () => Record<string, string>;
}

/**
 * The single source of truth for what this scanner calls and what each call
 * produces. The action → resource type mapping used to be written out twice
 * (once as calls, once as a 34-line count table), which is how they drift.
 */
const OPERATIONS: readonly OperationSpec[] = [
  { action: 'DescribeInstances', section: 'reservationSet', resourceType: 'ec2_instance' },
  { action: 'DescribeImages', section: 'imagesSet', resourceType: 'ec2_ami', params: () => listParams('Owner', ['self']) },
  { action: 'DescribeKeyPairs', section: 'keySet', resourceType: 'ec2_key_pair' },
  { action: 'DescribeVolumes', section: 'volumeSet', resourceType: 'ebs_volume' },
  { action: 'DescribeSnapshots', section: 'snapshotSet', resourceType: 'ebs_snapshot', params: () => listParams('Owner', ['self']) },
  { action: 'DescribeSecurityGroups', section: 'securityGroupInfo', resourceType: 'security_group' },
  { action: 'DescribeAddresses', section: 'addressesSet', resourceType: 'elastic_ip' },
  { action: 'DescribeNetworkInterfaces', section: 'networkInterfaceSet', resourceType: 'network_interface' },
  { action: 'DescribeVpcs', section: 'vpcSet', resourceType: 'vpc' },
  { action: 'DescribeSubnets', section: 'subnetSet', resourceType: 'subnet' },
  { action: 'DescribeRouteTables', section: 'routeTableSet', resourceType: 'route_table' },
  { action: 'DescribeInternetGateways', section: 'internetGatewaySet', resourceType: 'internet_gateway' },
  { action: 'DescribeNatGateways', section: 'natGatewaySet', resourceType: 'nat_gateway' },
  { action: 'DescribeNetworkAcls', section: 'networkAclSet', resourceType: 'network_acl' },
  { action: 'DescribeVpcEndpoints', section: 'vpcEndpointSet', resourceType: 'vpc_endpoint' },
  { action: 'DescribeVpcPeeringConnections', section: 'vpcPeeringConnectionSet', resourceType: 'vpc_peering_connection' },
  { action: 'DescribeLaunchTemplates', section: 'launchTemplates', resourceType: 'ec2_launch_template' },
  { action: 'DescribeFlowLogs', section: 'flowLogSet', resourceType: 'vpc_flow_log' },
  { action: 'DescribePlacementGroups', section: 'placementGroupSet', resourceType: 'ec2_placement_group' },
  { action: 'DescribeManagedPrefixLists', section: 'prefixListSet', resourceType: 'prefix_list' },
  { action: 'DescribeTransitGateways', section: 'transitGatewaySet', resourceType: 'transit_gateway' },
  { action: 'DescribeTransitGatewayAttachments', section: 'transitGatewayAttachments', resourceType: 'transit_gateway_attachment' },
  { action: 'DescribeVpnGateways', section: 'vpnGatewaySet', resourceType: 'vpn_gateway' },
  { action: 'DescribeVpnConnections', section: 'vpnConnectionSet', resourceType: 'vpn_connection' },
  { action: 'DescribeCustomerGateways', section: 'customerGatewaySet', resourceType: 'customer_gateway' },
  { action: 'DescribeClientVpnEndpoints', section: 'clientVpnEndpoint', resourceType: 'client_vpn_endpoint' },
  { action: 'DescribeEgressOnlyInternetGateways', section: 'egressOnlyInternetGatewaySet', resourceType: 'egress_only_igw' },
  { action: 'DescribeCapacityReservations', section: 'capacityReservationSet', resourceType: 'ec2_capacity_reservation' },
  { action: 'DescribeHosts', section: 'hostSet', resourceType: 'ec2_dedicated_host' },
  { action: 'DescribeFleets', section: 'fleetSet', resourceType: 'ec2_fleet' },
  { action: 'DescribeSpotFleetRequests', section: 'spotFleetRequestConfigSet', resourceType: 'ec2_spot_fleet_request' },
  { action: 'DescribeSpotInstanceRequests', section: 'spotInstanceRequestSet', resourceType: 'ec2_spot_instance_request' },
  { action: 'DescribeReservedInstances', section: 'reservedInstancesSet', resourceType: 'reserved_instance' },
  // Elastic Graphics reached end of life (Jan 2024). Kept for catalog
  // compatibility; see EC2_ACTION_RESOURCE_TYPES for scoping its failures.
  { action: 'DescribeElasticGpus', section: 'elasticGpuSet', resourceType: 'elastic_gpu' },
];

/**
 * Describe* action → the one resource type it proves present/absent.
 *
 * Exported so discovery.ts can scope a degraded-coverage report from
 * onCallFailure (which carries `action`) to the ONE affected type, instead of
 * suppressing tombstoning for all 34 EC2 types because, say,
 * DescribeElasticGpus was denied.
 */
export const EC2_ACTION_RESOURCE_TYPES: Readonly<Record<string, Ec2ResourceType>> = Object.freeze(
  Object.fromEntries(OPERATIONS.map((o) => [o.action, o.resourceType])),
);

/**
 * Per-operation outcome for one regional EC2 scan.
 *
 * `termination` is carried through from the shared page walker rather than
 * re-derived here: it is the same value that decides whether the operation's
 * resource types may be treated as fully enumerated, so a scanner-local guess
 * would be a second source of truth for the thing that governs tombstoning.
 */
export interface Ec2ScanOperation {
  action: string;
  status: 'success' | 'partial';
  pages: number;
  resources: number;
  termination: PaginationTermination;
  detail?: string;
}

export interface Ec2ScanDiagnostics {
  scanner: 'ec2';
  scanner_version: 'v2';
  region: string;
  /** 'partial' when any one operation did not read every page or failed. */
  status: 'success' | 'partial';
  startedAt: string;
  completedAt: string;
  /** Always in OPERATIONS order, so identical scans produce identical diagnostics. */
  operations: Ec2ScanOperation[];
}

// ---------------------------------------------------------------------------
// Small extraction helpers
// ---------------------------------------------------------------------------

const sub = (xml: string, section: string): string => extractSection(xml, section) ?? '';

const idsIn = (xml: string, section: string, idField: string): string[] =>
  extractListItems(extractSection(xml, section))
    .map((item) => field(item, idField))
    .filter((v): v is string => !!v);

const intOrNull = (raw: string | null): number | null => {
  if (raw === null || raw.trim() === '') return null;
  const n = Number(raw);
  return Number.isInteger(n) ? n : null;
};

const nonEmpty = (v: string | null): string | null => (v && v.trim() !== '' ? v : null);

/**
 * Network ACL entries as evidence (CIS 5.1: no NACL allows ingress from
 * 0.0.0.0/0 to remote-admin ports). Only a count was stored before, which made
 * that check uncomputable. Protocol is normalized with the same function the
 * security-group normalizer uses, so "6" and "tcp" never disagree.
 */
export function parseNaclEntries(naclXml: string) {
  return extractListItems(extractSection(naclXml, 'entrySet')).map((e) => {
    const range = extractSection(e, 'portRange');
    const icmp = extractSection(e, 'icmpTypeCode');
    return {
      ruleNumber: intOrNull(field(e, 'ruleNumber')),
      protocol: normalizeProtocol(field(e, 'protocol')),
      ruleAction: field(e, 'ruleAction'),
      egress: boolField(e, 'egress') ?? null,
      cidrBlock: field(e, 'cidrBlock'),
      ipv6CidrBlock: field(e, 'ipv6CidrBlock'),
      fromPort: range ? intOrNull(field(range, 'from')) : null,
      toPort: range ? intOrNull(field(range, 'to')) : null,
      icmpType: icmp ? intOrNull(field(icmp, 'type')) : null,
      icmpCode: icmp ? intOrNull(field(icmp, 'code')) : null,
    };
  });
}

/** Route table routes as evidence (public-subnet detection, blackholes, peering paths). */
export function parseRoutes(routeTableXml: string) {
  return extractListItems(extractSection(routeTableXml, 'routeSet')).map((r) => ({
    destinationCidrBlock: field(r, 'destinationCidrBlock'),
    destinationIpv6CidrBlock: field(r, 'destinationIpv6CidrBlock'),
    destinationPrefixListId: field(r, 'destinationPrefixListId'),
    gatewayId: field(r, 'gatewayId'),
    natGatewayId: field(r, 'natGatewayId'),
    transitGatewayId: field(r, 'transitGatewayId'),
    vpcPeeringConnectionId: field(r, 'vpcPeeringConnectionId'),
    egressOnlyInternetGatewayId: field(r, 'egressOnlyInternetGatewayId'),
    networkInterfaceId: field(r, 'networkInterfaceId'),
    instanceId: field(r, 'instanceId'),
    state: field(r, 'state'),
    origin: field(r, 'origin'),
  }));
}

// ---------------------------------------------------------------------------
// Per-type builders: one list item in, zero or more resources out.
// ---------------------------------------------------------------------------

type Builder = (item: string, region: string) => ScannedResource[];

const BUILDERS: Record<Ec2ResourceType, Builder> = {
  ec2_instance: (reservation, region) => {
    const out: ScannedResource[] = [];
    for (const i of extractListItems(extractSection(reservation, 'instancesSet'))) {
      const id = field(i, 'instanceId');
      if (!id) continue;
      const tags = tagsFromSet(i);
      const state = extractSection(i, 'instanceState');
      const imds = sub(i, 'metadataOptions');
      out.push({
        resourceTypeKey: 'ec2_instance', resourceId: id, region,
        resourceName: tags['Name'],
        state: state ? (field(state, 'name') ?? undefined) : undefined, tags,
        metadata: {
          instanceType: field(i, 'instanceType'), launchTime: field(i, 'launchTime'),
          privateIp: field(i, 'privateIpAddress'),
          // EC2's Query-protocol XML names the public IP `ipAddress` (and the
          // public DNS name `dnsName`). The previous version read
          // `publicIpAddress`, which never appears on the wire, so publicIp
          // was null for every instance and "public instance" checks could
          // not fire. `publicIpAddress` is kept as a fallback only.
          publicIp: nonEmpty(field(i, 'ipAddress')) ?? nonEmpty(field(i, 'publicIpAddress')),
          publicDnsName: nonEmpty(field(i, 'dnsName')),
          platform: field(i, 'platformDetails'),
          imageId: field(i, 'imageId'),
          keyName: field(i, 'keyName'),
          architecture: field(i, 'architecture'),
          rootDeviceType: field(i, 'rootDeviceType'),
          availabilityZone: field(sub(i, 'placement'), 'availabilityZone'),
          ebsOptimized: boolField(i, 'ebsOptimized') ?? null,
          monitoringState: field(sub(i, 'monitoring'), 'state'),
          // IMDSv2 enforcement (FSBP EC2.8): httpTokens === 'required'.
          imdsHttpTokens: field(imds, 'httpTokens'),
          imdsHttpEndpoint: field(imds, 'httpEndpoint'),
          imdsHttpPutResponseHopLimit: intOrNull(field(imds, 'httpPutResponseHopLimit')),
        },
        relationships: {
          vpcId: field(i, 'vpcId'), subnetId: field(i, 'subnetId'),
          securityGroupIds: idsIn(i, 'groupSet', 'groupId'),
          instanceProfileArn: field(sub(i, 'iamInstanceProfile'), 'arn'),
          imageId: field(i, 'imageId'),
          volumeIds: extractListItems(extractSection(i, 'blockDeviceMapping'))
            .map((b) => field(sub(b, 'ebs'), 'volumeId')).filter((v): v is string => !!v),
          networkInterfaceIds: idsIn(i, 'networkInterfaceSet', 'networkInterfaceId'),
        },
      });
    }
    return out;
  },

  ec2_ami: (a, region) => {
    const id = field(a, 'imageId');
    if (!id) return [];
    return [{
      resourceTypeKey: 'ec2_ami', resourceId: id, region,
      resourceName: field(a, 'name') ?? undefined, state: field(a, 'imageState') ?? undefined,
      tags: tagsFromSet(a),
      metadata: {
        creationDate: field(a, 'creationDate'), architecture: field(a, 'architecture'),
        // A self-owned AMI shared publicly is a data-exposure finding.
        isPublic: boolField(a, 'isPublic') ?? null,
        platformDetails: field(a, 'platformDetails'),
        rootDeviceType: field(a, 'rootDeviceType'),
        deprecationTime: field(a, 'deprecationTime'),
      },
    }];
  },

  ec2_key_pair: (k, region) => {
    const id = field(k, 'keyPairId') ?? field(k, 'keyName');
    if (!id) return [];
    return [{
      resourceTypeKey: 'ec2_key_pair', resourceId: id, region,
      resourceName: field(k, 'keyName') ?? undefined, tags: tagsFromSet(k),
      metadata: { fingerprint: field(k, 'keyFingerprint'), keyType: field(k, 'keyType'), createTime: field(k, 'createTime') },
    }];
  },

  ebs_volume: (v, region) => {
    const id = field(v, 'volumeId');
    if (!id) return [];
    const tags = tagsFromSet(v);
    return [{
      resourceTypeKey: 'ebs_volume', resourceId: id, region,
      resourceName: tags['Name'], state: field(v, 'status') ?? undefined, tags,
      metadata: {
        sizeGiB: numField(v, 'size'), volumeType: field(v, 'volumeType'),
        iops: numField(v, 'iops'), encrypted: boolField(v, 'encrypted'),
        createTime: field(v, 'createTime'),
        kmsKeyId: field(v, 'kmsKeyId'),
        availabilityZone: field(v, 'availabilityZone'),
        multiAttachEnabled: boolField(v, 'multiAttachEnabled') ?? null,
      },
      relationships: {
        attachedInstanceIds: idsIn(v, 'attachmentSet', 'instanceId'),
        snapshotId: nonEmpty(field(v, 'snapshotId')),
      },
    }];
  },

  ebs_snapshot: (s, region) => {
    const id = field(s, 'snapshotId');
    if (!id) return [];
    const tags = tagsFromSet(s);
    return [{
      resourceTypeKey: 'ebs_snapshot', resourceId: id, region,
      resourceName: tags['Name'], state: field(s, 'status') ?? undefined, tags,
      metadata: {
        volumeSizeGiB: numField(s, 'volumeSize'), startTime: field(s, 'startTime'),
        encrypted: boolField(s, 'encrypted'),
        kmsKeyId: field(s, 'kmsKeyId'),
        ownerId: field(s, 'ownerId'),
        description: field(s, 'description'),
        storageTier: field(s, 'storageTier'),
      },
      relationships: { volumeId: field(s, 'volumeId') },
    }];
  },

  security_group: (sg, region) => {
    const id = field(sg, 'groupId');
    if (!id) return [];
    const tags = tagsFromSet(sg);

    /*
     * AWS-16. The rules themselves are retained, not just counted.
     *
     * `inboundRules` is written UNCONDITIONALLY, including as an empty array.
     * Its presence is what tells posture the rules were actually read: a group
     * with no ingress and a group whose rules were never collected both yield
     * zero findings, and only one of them is safe. Groups written by the
     * previous scanner carry no such key and are reported NOT_ASSESSED until
     * their next collection.
     */
    const inbound = parsePermissions(extractSection(sg, 'ipPermissions'), 'ingress');
    const outbound = parsePermissions(extractSection(sg, 'ipPermissionsEgress'), 'egress');

    return [{
      resourceTypeKey: 'security_group', resourceId: id, region,
      resourceName: field(sg, 'groupName') ?? undefined,
      isDefault: field(sg, 'groupName') === 'default', tags,
      metadata: {
        description: field(sg, 'groupDescription'),
        // Kept: existing consumers read these, and they remain correct.
        inboundRuleCount: inbound.rules.length,
        outboundRuleCount: outbound.rules.length,
        inboundRules: inbound.rules,
        outboundRules: outbound.rules,
        /*
         * A permission entry we could not normalize. Non-zero means this
         * group's evidence is incomplete, so posture must degrade rather
         * than report a clean result from a partial read.
         */
        unparsedInboundRuleCount: inbound.unparsedCount,
        unparsedOutboundRuleCount: outbound.unparsedCount,
        rulesEvidenceVersion: SECURITY_GROUP_RULES_EVIDENCE_VERSION,
      },
      relationships: { vpcId: field(sg, 'vpcId') },
    }];
  },

  elastic_ip: (eip, region) => {
    const id = field(eip, 'allocationId') ?? field(eip, 'publicIp');
    if (!id) return [];
    const tags = tagsFromSet(eip);
    const instanceId = field(eip, 'instanceId');
    const networkInterfaceId = field(eip, 'networkInterfaceId');
    const associationId = field(eip, 'associationId');
    return [{
      resourceTypeKey: 'elastic_ip', resourceId: id, region,
      resourceName: field(eip, 'publicIp') ?? undefined, tags,
      metadata: {
        publicIp: field(eip, 'publicIp'), domain: field(eip, 'domain'),
        associationId,
        privateIpAddress: field(eip, 'privateIpAddress'),
        // Unattached EIPs cost money and are a hygiene finding.
        associated: Boolean(associationId || instanceId || networkInterfaceId),
      },
      relationships: { instanceId, networkInterfaceId },
    }];
  },

  network_interface: (eni, region) => {
    const id = field(eni, 'networkInterfaceId');
    if (!id) return [];
    const tags = tagsFromSet(eni);
    const attachment = extractSection(eni, 'attachment');
    return [{
      resourceTypeKey: 'network_interface', resourceId: id, region,
      resourceName: field(eni, 'description') ?? undefined,
      state: field(eni, 'status') ?? undefined, tags,
      metadata: {
        privateIp: field(eni, 'privateIpAddress'),
        interfaceType: field(eni, 'interfaceType'),
        publicIp: field(sub(eni, 'association'), 'publicIp'),
        requesterManaged: boolField(eni, 'requesterManaged') ?? null,
      },
      relationships: {
        vpcId: field(eni, 'vpcId'), subnetId: field(eni, 'subnetId'),
        attachedInstanceId: attachment ? field(attachment, 'instanceId') : null,
        securityGroupIds: idsIn(eni, 'groupSet', 'groupId'),
      },
    }];
  },

  vpc: (vpc, region) => {
    const id = field(vpc, 'vpcId');
    if (!id) return [];
    const tags = tagsFromSet(vpc);
    return [{
      resourceTypeKey: 'vpc', resourceId: id, region,
      resourceName: tags['Name'], isDefault: boolField(vpc, 'isDefault'),
      state: field(vpc, 'state') ?? undefined, tags,
      metadata: {
        cidrBlock: field(vpc, 'cidrBlock'),
        instanceTenancy: field(vpc, 'instanceTenancy'),
        ownerId: field(vpc, 'ownerId'),
      },
    }];
  },

  subnet: (sn, region) => {
    const id = field(sn, 'subnetId');
    if (!id) return [];
    const tags = tagsFromSet(sn);
    return [{
      resourceTypeKey: 'subnet', resourceId: id, region,
      resourceName: tags['Name'], isDefault: boolField(sn, 'defaultForAz'),
      state: field(sn, 'state') ?? undefined, tags,
      metadata: {
        cidrBlock: field(sn, 'cidrBlock'),
        availabilityZone: field(sn, 'availabilityZone'),
        availableIpCount: numField(sn, 'availableIpAddressCount'),
        // FSBP EC2.15: subnets should not auto-assign public IPs.
        mapPublicIpOnLaunch: boolField(sn, 'mapPublicIpOnLaunch') ?? null,
        assignIpv6AddressOnCreation: boolField(sn, 'assignIpv6AddressOnCreation') ?? null,
      },
      relationships: { vpcId: field(sn, 'vpcId') },
    }];
  },

  route_table: (rt, region) => {
    const id = field(rt, 'routeTableId');
    if (!id) return [];
    const tags = tagsFromSet(rt);
    const routes = parseRoutes(rt);
    const associations = extractListItems(extractSection(rt, 'associationSet'));
    return [{
      resourceTypeKey: 'route_table', resourceId: id, region,
      resourceName: tags['Name'],
      isDefault: associations.some((a) => boolField(a, 'main')),
      tags,
      metadata: {
        routeCount: routes.length,
        routes,
        hasInternetGatewayRoute: routes.some((r) => (r.gatewayId ?? '').startsWith('igw-')),
      },
      relationships: {
        vpcId: field(rt, 'vpcId'),
        subnetIds: associations.map((a) => field(a, 'subnetId')).filter((v): v is string => !!v),
      },
    }];
  },

  internet_gateway: (igw, region) => {
    const id = field(igw, 'internetGatewayId');
    if (!id) return [];
    const tags = tagsFromSet(igw);
    return [{
      resourceTypeKey: 'internet_gateway', resourceId: id, region,
      resourceName: tags['Name'], tags,
      relationships: { vpcIds: idsIn(igw, 'attachmentSet', 'vpcId') },
    }];
  },

  nat_gateway: (nat, region) => {
    const id = field(nat, 'natGatewayId');
    if (!id) return [];
    const tags = tagsFromSet(nat);
    return [{
      resourceTypeKey: 'nat_gateway', resourceId: id, region,
      resourceName: tags['Name'], state: field(nat, 'state') ?? undefined, tags,
      metadata: {
        connectivityType: field(nat, 'connectivityType'),
        publicIps: idsIn(nat, 'natGatewayAddressSet', 'publicIp'),
      },
      relationships: { vpcId: field(nat, 'vpcId'), subnetId: field(nat, 'subnetId') },
    }];
  },

  network_acl: (nacl, region) => {
    const id = field(nacl, 'networkAclId');
    if (!id) return [];
    const tags = tagsFromSet(nacl);
    const entries = parseNaclEntries(nacl);
    return [{
      resourceTypeKey: 'network_acl', resourceId: id, region,
      resourceName: tags['Name'], isDefault: boolField(nacl, 'isDefault'), tags,
      metadata: { entryCount: entries.length, entries },
      relationships: {
        vpcId: field(nacl, 'vpcId'),
        subnetIds: idsIn(nacl, 'associationSet', 'subnetId'),
      },
    }];
  },

  vpc_endpoint: (vpce, region) => {
    const id = field(vpce, 'vpcEndpointId');
    if (!id) return [];
    const tags = tagsFromSet(vpce);
    return [{
      resourceTypeKey: 'vpc_endpoint', resourceId: id, region,
      resourceName: tags['Name'], state: field(vpce, 'state') ?? undefined, tags,
      metadata: {
        serviceName: field(vpce, 'serviceName'),
        vpcEndpointType: field(vpce, 'vpcEndpointType'),
        privateDnsEnabled: boolField(vpce, 'privateDnsEnabled') ?? null,
      },
      relationships: { vpcId: field(vpce, 'vpcId') },
    }];
  },

  vpc_peering_connection: (pcx, region) => {
    const id = field(pcx, 'vpcPeeringConnectionId');
    if (!id) return [];
    const status = extractSection(pcx, 'status');
    const requester = sub(pcx, 'requesterVpcInfo');
    const accepter = sub(pcx, 'accepterVpcInfo');
    return [{
      resourceTypeKey: 'vpc_peering_connection', resourceId: id, region,
      state: status ? (field(status, 'code') ?? undefined) : undefined,
      tags: tagsFromSet(pcx),
      metadata: {
        // Cross-account / cross-region peering is a trust-boundary signal.
        requesterOwnerId: field(requester, 'ownerId'),
        requesterRegion: field(requester, 'region'),
        accepterOwnerId: field(accepter, 'ownerId'),
        accepterRegion: field(accepter, 'region'),
      },
      relationships: {
        requesterVpcId: requester ? field(requester, 'vpcId') : null,
        accepterVpcId: accepter ? field(accepter, 'vpcId') : null,
      },
    }];
  },

  ec2_launch_template: (lt, region) => {
    const id = field(lt, 'launchTemplateId');
    if (!id) return [];
    const tags = tagsFromSet(lt);
    return [{
      resourceTypeKey: 'ec2_launch_template', resourceId: id, region,
      resourceName: field(lt, 'launchTemplateName') ?? undefined, tags,
      metadata: {
        createTime: field(lt, 'createTime'),
        defaultVersionNumber: numField(lt, 'defaultVersionNumber'),
        latestVersionNumber: numField(lt, 'latestVersionNumber'),
      },
    }];
  },

  vpc_flow_log: (fl, region) => {
    const id = field(fl, 'flowLogId');
    if (!id) return [];
    const tags = tagsFromSet(fl);
    return [{
      resourceTypeKey: 'vpc_flow_log', resourceId: id, region,
      state: field(fl, 'flowLogStatus') ?? undefined, tags,
      metadata: {
        trafficType: field(fl, 'trafficType'),
        logDestinationType: field(fl, 'logDestinationType'),
        logDestination: field(fl, 'logDestination'),
        logGroupName: field(fl, 'logGroupName'),
        deliverLogsStatus: field(fl, 'deliverLogsStatus'),
        creationTime: field(fl, 'creationTime'),
      },
      relationships: { resourceId: field(fl, 'resourceId') },
    }];
  },

  ec2_placement_group: (pg, region) => {
    const id = field(pg, 'groupId') ?? field(pg, 'groupName');
    if (!id) return [];
    const tags = tagsFromSet(pg);
    return [{
      resourceTypeKey: 'ec2_placement_group', resourceId: id, region,
      resourceName: field(pg, 'groupName') ?? undefined,
      state: field(pg, 'state') ?? undefined, tags,
      metadata: { strategy: field(pg, 'strategy') },
    }];
  },

  prefix_list: (pl, region) => {
    // AWS-owned service-managed prefix lists are not customer resources.
    if (field(pl, 'ownerId') === 'AWS') return [];
    const id = field(pl, 'prefixListId');
    if (!id) return [];
    const tags = tagsFromSet(pl);
    return [{
      resourceTypeKey: 'prefix_list', resourceId: id, region,
      resourceName: field(pl, 'prefixListName') ?? undefined,
      state: field(pl, 'state') ?? undefined, tags,
      metadata: {
        addressFamily: field(pl, 'addressFamily'),
        maxEntries: numField(pl, 'maxEntries'),
        ownerId: field(pl, 'ownerId'),
      },
    }];
  },

  transit_gateway: (tgw, region) => {
    const id = field(tgw, 'transitGatewayId');
    if (!id) return [];
    const tags = tagsFromSet(tgw);
    return [{
      resourceTypeKey: 'transit_gateway', resourceId: id, region,
      resourceName: tags['Name'], state: field(tgw, 'state') ?? undefined, tags,
      metadata: {
        description: field(tgw, 'description'),
        ownerId: field(tgw, 'ownerId'),
        creationTime: field(tgw, 'creationTime'),
      },
    }];
  },

  transit_gateway_attachment: (tga, region) => {
    const id = field(tga, 'transitGatewayAttachmentId');
    if (!id) return [];
    const tags = tagsFromSet(tga);
    return [{
      resourceTypeKey: 'transit_gateway_attachment', resourceId: id, region,
      state: field(tga, 'state') ?? undefined, tags,
      metadata: {
        resourceType: field(tga, 'resourceType'),
        creationTime: field(tga, 'creationTime'),
      },
      relationships: {
        transitGatewayId: field(tga, 'transitGatewayId'),
        resourceId: field(tga, 'resourceId'),
      },
    }];
  },

  vpn_gateway: (vgw, region) => {
    const id = field(vgw, 'vpnGatewayId');
    if (!id) return [];
    const tags = tagsFromSet(vgw);
    return [{
      resourceTypeKey: 'vpn_gateway', resourceId: id, region,
      resourceName: tags['Name'], state: field(vgw, 'state') ?? undefined, tags,
      metadata: {
        type: field(vgw, 'type'),
        availabilityZone: field(vgw, 'availabilityZone'),
        amazonSideAsn: field(vgw, 'amazonSideAsn'),
      },
      relationships: { vpcIds: idsIn(vgw, 'attachments', 'vpcId') },
    }];
  },

  vpn_connection: (vpn, region) => {
    const id = field(vpn, 'vpnConnectionId');
    if (!id) return [];
    const tags = tagsFromSet(vpn);
    return [{
      resourceTypeKey: 'vpn_connection', resourceId: id, region,
      resourceName: tags['Name'], state: field(vpn, 'state') ?? undefined, tags,
      metadata: { type: field(vpn, 'type') },
      relationships: {
        customerGatewayId: field(vpn, 'customerGatewayId'),
        vpnGatewayId: field(vpn, 'vpnGatewayId'),
        transitGatewayId: field(vpn, 'transitGatewayId'),
      },
    }];
  },

  customer_gateway: (cgw, region) => {
    const id = field(cgw, 'customerGatewayId');
    if (!id) return [];
    const tags = tagsFromSet(cgw);
    return [{
      resourceTypeKey: 'customer_gateway', resourceId: id, region,
      resourceName: tags['Name'], state: field(cgw, 'state') ?? undefined, tags,
      metadata: {
        type: field(cgw, 'type'),
        ipAddress: field(cgw, 'ipAddress'),
        bgpAsn: field(cgw, 'bgpAsn'),
      },
    }];
  },

  client_vpn_endpoint: (cvpn, region) => {
    const id = field(cvpn, 'clientVpnEndpointId');
    if (!id) return [];
    const tags = tagsFromSet(cvpn);
    const status = extractSection(cvpn, 'status');
    return [{
      resourceTypeKey: 'client_vpn_endpoint', resourceId: id, region,
      resourceName: field(cvpn, 'description') ?? undefined,
      state: status ? (field(status, 'code') ?? undefined) : undefined, tags,
      metadata: {
        clientCidrBlock: field(cvpn, 'clientCidrBlock'),
        dnsName: field(cvpn, 'dnsName'),
        transportProtocol: field(cvpn, 'transportProtocol'),
        creationTime: field(cvpn, 'creationTime'),
        splitTunnel: boolField(cvpn, 'splitTunnel') ?? null,
      },
    }];
  },

  egress_only_igw: (eoigw, region) => {
    const id = field(eoigw, 'egressOnlyInternetGatewayId');
    if (!id) return [];
    const tags = tagsFromSet(eoigw);
    return [{
      resourceTypeKey: 'egress_only_igw', resourceId: id, region,
      resourceName: tags['Name'], tags,
      relationships: { vpcIds: idsIn(eoigw, 'attachmentSet', 'vpcId') },
    }];
  },

  ec2_capacity_reservation: (cr, region) => {
    const id = field(cr, 'capacityReservationId');
    if (!id) return [];
    const tags = tagsFromSet(cr);
    return [{
      resourceTypeKey: 'ec2_capacity_reservation', resourceId: id, region,
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
    }];
  },

  ec2_dedicated_host: (h, region) => {
    const id = field(h, 'hostId');
    if (!id) return [];
    const props = extractSection(h, 'hostProperties');
    return [{
      resourceTypeKey: 'ec2_dedicated_host', resourceId: id, region,
      state: field(h, 'state') ?? undefined, tags: tagsFromSet(h),
      metadata: {
        instanceType: props ? field(props, 'instanceType') : null,
        availabilityZone: field(h, 'availabilityZone'),
        autoPlacement: field(h, 'autoPlacement'),
        allocationTime: field(h, 'allocationTime'),
      },
    }];
  },

  ec2_fleet: (fl, region) => {
    const id = field(fl, 'fleetId');
    if (!id) return [];
    const tags = tagsFromSet(fl);
    const spec = extractSection(fl, 'targetCapacitySpecification');
    return [{
      resourceTypeKey: 'ec2_fleet', resourceId: id, region,
      state: field(fl, 'fleetState') ?? undefined, tags,
      metadata: {
        type: field(fl, 'type'),
        totalTargetCapacity: spec ? numField(spec, 'totalTargetCapacity') : undefined,
        createTime: field(fl, 'createTime'),
      },
    }];
  },

  ec2_spot_fleet_request: (sfr, region) => {
    const id = field(sfr, 'spotFleetRequestId');
    if (!id) return [];
    const cfg = extractSection(sfr, 'spotFleetRequestConfig');
    return [{
      resourceTypeKey: 'ec2_spot_fleet_request', resourceId: id, region,
      state: field(sfr, 'spotFleetRequestState') ?? undefined,
      metadata: {
        spotPrice: cfg ? field(cfg, 'spotPrice') : null,
        targetCapacity: cfg ? numField(cfg, 'targetCapacity') : undefined,
        iamFleetRole: cfg ? field(cfg, 'iamFleetRole') : null,
      },
    }];
  },

  ec2_spot_instance_request: (sir, region) => {
    const id = field(sir, 'spotInstanceRequestId');
    if (!id) return [];
    const tags = tagsFromSet(sir);
    return [{
      resourceTypeKey: 'ec2_spot_instance_request', resourceId: id, region,
      state: field(sir, 'state') ?? undefined, tags,
      metadata: {
        spotPrice: field(sir, 'spotPrice'),
        type: field(sir, 'type'),
        createTime: field(sir, 'createTime'),
      },
      relationships: { instanceId: field(sir, 'instanceId') },
    }];
  },

  reserved_instance: (ri, region) => {
    const id = field(ri, 'reservedInstancesId');
    if (!id) return [];
    const tags = tagsFromSet(ri);
    return [{
      resourceTypeKey: 'reserved_instance', resourceId: id, region,
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
    }];
  },

  elastic_gpu: (gpu, region) => {
    const id = field(gpu, 'elasticGpuId');
    if (!id) return [];
    return [{
      resourceTypeKey: 'elastic_gpu', resourceId: id, region,
      state: field(gpu, 'elasticGpuState') ?? undefined,
      metadata: {
        elasticGpuType: field(gpu, 'elasticGpuType'),
        elasticGpuHealth: field(gpu, 'elasticGpuHealth'),
        availabilityZone: field(gpu, 'availabilityZone'),
      },
      relationships: { instanceId: field(gpu, 'instanceId') },
    }];
  },
};

/**
 * Production-grade EC2 discovery: instances, AMIs/key pairs, EBS
 * volumes/snapshots, and the VPC networking primitives, via raw Describe*
 * calls (aws4fetch, not the SDK — see awsApi.ts) parsed with the regex-based
 * extraction in xmlList.ts.
 *
 * Contract:
 * - Every Describe* operation reads EVERY page and says so when it could not
 *   (see the `termination` field on each operation). Pages are kept as pages
 *   and items are extracted from each one: the version before this one
 *   concatenated pages and then used `extractSection`, which returns only the
 *   FIRST matching section — so it fetched pages 2..N, threw them away, and
 *   the resources on them looked deleted to finalize.
 * - Retries, backoff, jitter, timeouts and throttling are the shared provider
 *   layer's job (awsApi.ts + awsErrors.ts), not this file's.
 * - A failed operation degrades coverage and is reported, then the scan
 *   continues with the operations that worked. It is NOT represented as an
 *   empty result, and it does NOT abort the other operations.
 * - Per-operation diagnostics are attached to the returned resources.
 *
 * The Promise<ScannedResource[]> contract is intentionally preserved so
 * discovery.ts and the rest of the provider pipeline need no breaking change.
 */
export async function scanEc2(ctx: ScannerContext): Promise<ScannedResource[]> {
  const startedAt = new Date().toISOString();
  const endpoint = `ec2.${ctx.region}.amazonaws.com`;

  /**
   * An incomplete walk (page cap, repeated token) has to degrade this
   * scanner's coverage. A failed page already reports itself through awsApi's
   * terminal-failure path; this sink is for the incomplete cases that arrive
   * with a 200 and would otherwise be recorded nowhere.
   */
  const onIncomplete = incompleteSink(ctx.creds);

  const walks = await mapWithConcurrency(OPERATIONS, OPERATION_CONCURRENCY, async (op) => {
    const walk = await paginateQueryApi<string, string>(
      ctx.creds,
      { service: 'ec2', region: ctx.region, host: endpoint, action: op.action, version: VERSION, params: op.params?.() },
      // Each page is carried through as itself; list extraction happens per
      // page below.
      (page) => [page],
      (page) => detectQueryTruncation(page),
      { onIncomplete },
    );
    // A page with no such section contributes nothing rather than aborting
    // the others: EC2 legitimately omits an empty result set container.
    const items = walk.items.flatMap((page) => extractListItems(extractSection(page, op.section)));
    return { op, walk, items };
  });

  const out: ScannedResource[] = [];
  const operations: Ec2ScanOperation[] = [];

  for (const { op, walk, items } of walks) {
    const build = BUILDERS[op.resourceType];
    let produced = 0;
    for (const item of items) {
      // One malformed item must not cost the rest of the operation.
      try {
        const rows = build(item, ctx.region);
        produced += rows.length;
        out.push(...rows);
      } catch (err) {
        console.error(`EC2 ${op.action} item could not be parsed in ${ctx.region}: ${err instanceof Error ? err.message : 'unknown error'}`);
      }
    }
    operations.push({
      action: op.action,
      status: walk.termination === 'complete' ? 'success' : 'partial',
      pages: walk.pages,
      // Derived from parsed resources, not guessed from response size.
      resources: produced,
      termination: walk.termination,
      detail: walk.detail,
    });
  }

  /**
   * 'partial' when any single operation did not read every page or failed.
   *
   * Derived from the walks rather than asserted, and carried on the resources
   * so the partial case is visible in the data itself rather than only in a
   * log line.
   */
  const diagnostics: Ec2ScanDiagnostics = {
    scanner: 'ec2',
    scanner_version: 'v2',
    region: ctx.region,
    status: operations.every((o) => o.termination === 'complete') ? 'success' : 'partial',
    startedAt,
    completedAt: new Date().toISOString(),
    operations,
  };

  for (const resource of out) {
    resource.metadata = { ...resource.metadata, ec2ScanDiagnostics: diagnostics };
  }

  return out;
}