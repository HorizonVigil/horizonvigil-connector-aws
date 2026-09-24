import { describe, it, expect, vi, beforeEach } from 'vitest';

/**
 * EC2 scanner contract tests.
 *
 * The load-bearing one is the two-page volume case. The previous EC2
 * implementation concatenated the page bodies and then extracted the list with
 * `extractSection`, which returns only the FIRST matching section — so it issued
 * the page-2 request, threw the response away, and reported the resources on it
 * as absent. Because finalize reads absence as deletion, that silently
 * tombstoned live infrastructure. Against that implementation this test fails
 * with only `vol-1`.
 */
const fetchMock = vi.fn();
vi.mock('aws4fetch', () => ({
  AwsClient: class {
    fetch(url: string, init?: RequestInit) {
      return fetchMock(url, init);
    }
  },
}));

import { EC2_ACTION_RESOURCE_TYPES, EC2_RESOURCE_TYPES, scanEc2 } from './ec2';
import type { ScannedResource } from './types';

type Failure = { action?: string; normalizedCode?: string };
type Diagnostics = { status: string; operations: { action: string; pages: number; termination: string; resources: number }[] };

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ctx = { creds, region: 'eu-west-1' };

/** Reads Action and NextToken out of one Query-protocol request body. */
function request(init?: RequestInit): { action: string; token: string | null } {
  const body = String(init?.body ?? '');
  return {
    action: /Action=([^&]*)/.exec(body)?.[1] ?? '',
    token: /NextToken=([^&]*)/.exec(body)?.[1] ?? null,
  };
}

function ok(body: string) {
  return Promise.resolve(new Response(body, { status: 200 }));
}

function denied() {
  return Promise.resolve(new Response('<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>no</Message></Error></Errors></Response>', { status: 403 }));
}

const empty = (action: string) => ok(`<${action}Response/>`);

/** Serves one canned body per action; every other Describe* comes back empty. */
function serveActions(bodies: Record<string, string>): void {
  fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
    const { action } = request(init);
    return bodies[action] !== undefined ? ok(bodies[action]) : empty(action);
  });
}

/** Volumes split across two pages; every other Describe* comes back empty. */
function serveTwoVolumePages(): void {
  fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
    const { action, token } = request(init);
    if (action === 'DescribeVolumes') {
      if (token === 'page-2') return ok('<DescribeVolumesResponse><volumeSet><item><volumeId>vol-2</volumeId></item></volumeSet></DescribeVolumesResponse>');
      return ok('<DescribeVolumesResponse><volumeSet><item><volumeId>vol-1</volumeId></item></volumeSet><NextToken>page-2</NextToken></DescribeVolumesResponse>');
    }
    return empty(action);
  });
}

const diagnosticsOf = (resources: ScannedResource[]) =>
  (resources[0].metadata as { ec2ScanDiagnostics: Diagnostics }).ec2ScanDiagnostics;

const ofType = (resources: ScannedResource[], type: string) => resources.filter((r) => r.resourceTypeKey === type);

beforeEach(() => {
  fetchMock.mockReset();
});

describe('scanEc2 pagination', () => {
  it('returns resources from EVERY page, not just the first', async () => {
    serveTwoVolumePages();

    const resources = await scanEc2(ctx);

    const volumes = ofType(resources, 'ebs_volume').map((r) => r.resourceId);
    expect(volumes.sort()).toEqual(['vol-1', 'vol-2']);
  });

  it('actually sends the continuation token back to AWS', async () => {
    serveTwoVolumePages();

    await scanEc2(ctx);

    const volumeCalls = fetchMock.mock.calls.filter((c: unknown[]) => request(c[1] as RequestInit).action === 'DescribeVolumes');
    expect(volumeCalls).toHaveLength(2);
    expect(request(volumeCalls[1][1] as RequestInit).token).toBe('page-2');
  });

  it('reports per-operation pages and a success termination when nothing is truncated', async () => {
    serveTwoVolumePages();

    const diagnostics = diagnosticsOf(await scanEc2(ctx));

    const volumes = diagnostics.operations.find((o) => o.action === 'DescribeVolumes');
    expect(volumes).toMatchObject({ pages: 2, termination: 'complete', resources: 2 });
    expect(diagnostics.status).toBe('success');
  });

  it('marks the scan partial and degrades coverage when a page is never reached', async () => {
    // AWS keeps handing out tokens (a page cap is reached): the types this
    // scanner covers must not be trusted to prove absence.
    const failures: Failure[] = [];
    fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
      const { action, token } = request(init);
      if (action === 'DescribeVolumes') {
        const n = token === null ? 1 : Number(token);
        return ok(`<DescribeVolumesResponse><volumeSet><item><volumeId>vol-${n}</volumeId></item></volumeSet><NextToken>${n + 1}</NextToken></DescribeVolumesResponse>`);
      }
      return empty(action);
    });

    const resources = await scanEc2({ creds: { ...creds, onCallFailure: (f: Failure) => failures.push(f) }, region: 'eu-west-1' });

    expect(diagnosticsOf(resources).status).toBe('partial');
    expect(failures.some((f) => f.normalizedCode === 'PAGINATION_TRUNCATED')).toBe(true);
  });

  it('records diagnostics in a fixed order, so identical scans produce identical evidence', async () => {
    serveTwoVolumePages();
    const first = diagnosticsOf(await scanEc2(ctx)).operations.map((o) => o.action);
    serveTwoVolumePages();
    const second = diagnosticsOf(await scanEc2(ctx)).operations.map((o) => o.action);

    expect(first).toEqual(second);
    expect(first[0]).toBe('DescribeInstances');
    expect(first).toHaveLength(EC2_RESOURCE_TYPES.length);
  });
});

describe('scanEc2 failure semantics', () => {
  it('keeps every other operation when one is AccessDenied', async () => {
    // A single denied optional API (DescribeElasticGpus is the common one) must
    // not cost the customer their whole EC2 and networking inventory.
    fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
      const { action } = request(init);
      if (action === 'DescribeElasticGpus') return denied();
      if (action === 'DescribeVpcs') return ok('<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-1</vpcId></item></vpcSet></DescribeVpcsResponse>');
      return empty(action);
    });

    const resources = await scanEc2(ctx);

    expect(resources.some((r: ScannedResource) => r.resourceTypeKey === 'vpc' && r.resourceId === 'vpc-1')).toBe(true);
  });

  it('reports the denied operation through the shared degraded-coverage sink', async () => {
    const failures: Failure[] = [];
    fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
      const { action } = request(init);
      if (action === 'DescribeElasticGpus') return denied();
      return empty(action);
    });

    await scanEc2({ creds: { ...creds, onCallFailure: (f: Failure) => failures.push(f) }, region: 'eu-west-1' });

    // This is what stops finalize from reading the missing elastic_gpu rows as
    // deleted resources.
    expect(failures.some((f) => f.normalizedCode === 'PERMISSION_DENIED')).toBe(true);
  });

  it('never reports a failed operation as a completed walk', async () => {
    // Even when the failure leaves no resources at all, the operation must not
    // read as 'complete' anywhere a tombstone decision could see it.
    fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
      const { action } = request(init);
      if (action === 'DescribeVpcs') return denied();
      if (action === 'DescribeVolumes') return ok('<DescribeVolumesResponse><volumeSet><item><volumeId>vol-1</volumeId></item></volumeSet></DescribeVolumesResponse>');
      return empty(action);
    });

    const diagnostics = diagnosticsOf(await scanEc2(ctx));

    expect(diagnostics.operations.find((o) => o.action === 'DescribeVpcs')?.termination).toBe('failed');
    expect(diagnostics.status).toBe('partial');
  });

  it('maps every Describe* action to exactly one of its declared resource types', () => {
    // discovery.ts uses this to degrade ONE type per failed action instead of
    // all 34. A type with no action here could never be proven present.
    const mapped = Object.values(EC2_ACTION_RESOURCE_TYPES).sort();
    expect(mapped).toEqual([...EC2_RESOURCE_TYPES].sort());
    expect(EC2_ACTION_RESOURCE_TYPES.DescribeElasticGpus).toBe('elastic_gpu');
  });
});

/**
 * AWS-16 / Blocker 6. The scanner used to store only `inboundRuleCount`, which
 * made open-ingress uncomputable across the whole estate. These assert the
 * EVIDENCE actually reaches the resource, because a correct normalizer that
 * nothing calls fixes nothing.
 */
describe('scanEc2 retains security-group rule evidence', () => {
  const sgResponse = (permissions: string) =>
    `<DescribeSecurityGroupsResponse><securityGroupInfo><item>` +
    `<groupId>sg-1</groupId><groupName>web</groupName><vpcId>vpc-1</vpcId>` +
    `<groupDescription>web tier</groupDescription>` +
    `<ipPermissions>${permissions}</ipPermissions>` +
    `<ipPermissionsEgress><item><ipProtocol>-1</ipProtocol><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item></ipPermissionsEgress>` +
    `</item></securityGroupInfo></DescribeSecurityGroupsResponse>`;

  const serveSg = (permissions: string) => serveActions({ DescribeSecurityGroups: sgResponse(permissions) });

  const sgFrom = (resources: ScannedResource[]) =>
    resources.find((r) => r.resourceTypeKey === 'security_group');

  it('stores the actual inbound rules, not just a count', async () => {
    serveSg('<item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort><toPort>22</toPort>' +
      '<ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item>');

    const sg = sgFrom(await scanEc2(ctx));
    const rules = sg?.metadata?.inboundRules as { protocol: string; fromPort: number }[];

    expect(rules).toHaveLength(1);
    expect(rules[0]).toMatchObject({ protocol: 'tcp', fromPort: 22 });
    // The old field stays correct for existing consumers.
    expect(sg?.metadata?.inboundRuleCount).toBe(1);
  });

  /**
   * The honesty property. A group with no ingress and a group whose rules were
   * never read both yield zero findings, and only one is safe — so the KEY must
   * be present even when the list is empty.
   */
  it('writes an empty inboundRules array rather than omitting the key', async () => {
    serveSg('');

    const sg = sgFrom(await scanEc2(ctx));

    expect(sg?.metadata).toHaveProperty('inboundRules');
    expect(sg?.metadata?.inboundRules).toEqual([]);
    expect(sg?.metadata?.rulesEvidenceVersion).toBe(1);
  });

  it('reports rules it could not normalize instead of silently dropping them', async () => {
    // A permission carrying a source but no protocol.
    serveSg('<item><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item>');

    const sg = sgFrom(await scanEc2(ctx));

    expect(sg?.metadata?.inboundRules).toEqual([]);
    expect(sg?.metadata?.unparsedInboundRuleCount).toBe(1);
  });

  it('keeps egress separate from ingress', async () => {
    serveSg('<item><ipProtocol>tcp</ipProtocol><fromPort>443</fromPort><toPort>443</toPort>' +
      '<ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item>');

    const sg = sgFrom(await scanEc2(ctx));
    const inbound = sg?.metadata?.inboundRules as { direction: string }[];
    const outbound = sg?.metadata?.outboundRules as { direction: string }[];

    expect(inbound.every((r) => r.direction === 'ingress')).toBe(true);
    expect(outbound.every((r) => r.direction === 'egress')).toBe(true);
  });
});

/**
 * Posture evidence the product's headline checks depend on. Each of these was
 * either never collected or (public IP) read from an element name EC2 does not
 * use, so the check could not fire.
 */
describe('scanEc2 retains posture evidence', () => {
  const instanceXml =
    '<DescribeInstancesResponse><reservationSet><item><reservationId>r-1</reservationId><instancesSet><item>' +
    '<instanceId>i-1</instanceId><imageId>ami-1</imageId><instanceState><code>16</code><name>running</name></instanceState>' +
    '<dnsName>ec2-54-1-2-3.eu-west-1.compute.amazonaws.com</dnsName><keyName>ops</keyName><instanceType>t3.micro</instanceType>' +
    '<placement><availabilityZone>eu-west-1a</availabilityZone></placement><monitoring><state>disabled</state></monitoring>' +
    '<subnetId>subnet-1</subnetId><vpcId>vpc-1</vpcId><privateIpAddress>10.0.0.5</privateIpAddress><ipAddress>54.1.2.3</ipAddress>' +
    '<groupSet><item><groupId>sg-1</groupId><groupName>web</groupName></item></groupSet>' +
    '<blockDeviceMapping><item><deviceName>/dev/xvda</deviceName><ebs><volumeId>vol-9</volumeId></ebs></item></blockDeviceMapping>' +
    '<iamInstanceProfile><arn>arn:aws:iam::111122223333:instance-profile/app</arn></iamInstanceProfile>' +
    '<metadataOptions><httpTokens>optional</httpTokens><httpPutResponseHopLimit>1</httpPutResponseHopLimit><httpEndpoint>enabled</httpEndpoint></metadataOptions>' +
    '</item></instancesSet></item></reservationSet></DescribeInstancesResponse>';

  it('reads the public IP from <ipAddress>, the element EC2 actually returns', async () => {
    serveActions({ DescribeInstances: instanceXml });

    const [instance] = ofType(await scanEc2(ctx), 'ec2_instance');

    expect(instance.metadata).toMatchObject({ publicIp: '54.1.2.3', privateIp: '10.0.0.5', publicDnsName: 'ec2-54-1-2-3.eu-west-1.compute.amazonaws.com' });
  });

  it('records IMDS configuration (IMDSv2 enforcement)', async () => {
    serveActions({ DescribeInstances: instanceXml });

    const [instance] = ofType(await scanEc2(ctx), 'ec2_instance');

    expect(instance.metadata).toMatchObject({ imdsHttpTokens: 'optional', imdsHttpPutResponseHopLimit: 1, imdsHttpEndpoint: 'enabled' });
  });

  it('keeps instance relationships for the resource graph', async () => {
    serveActions({ DescribeInstances: instanceXml });

    const [instance] = ofType(await scanEc2(ctx), 'ec2_instance');

    expect(instance.relationships).toMatchObject({
      vpcId: 'vpc-1', subnetId: 'subnet-1', securityGroupIds: ['sg-1'], volumeIds: ['vol-9'],
      instanceProfileArn: 'arn:aws:iam::111122223333:instance-profile/app',
    });
    expect(instance.state).toBe('running');
  });

  it('records whether a self-owned AMI is public', async () => {
    serveActions({ DescribeImages: '<DescribeImagesResponse><imagesSet><item><imageId>ami-1</imageId><imageState>available</imageState><isPublic>true</isPublic></item></imagesSet></DescribeImagesResponse>' });

    const [ami] = ofType(await scanEc2(ctx), 'ec2_ami');

    expect(ami.metadata?.isPublic).toBe(true);
  });

  it('records whether a subnet auto-assigns public IPs', async () => {
    serveActions({ DescribeSubnets: '<DescribeSubnetsResponse><subnetSet><item><subnetId>subnet-1</subnetId><vpcId>vpc-1</vpcId><mapPublicIpOnLaunch>true</mapPublicIpOnLaunch></item></subnetSet></DescribeSubnetsResponse>' });

    const [subnet] = ofType(await scanEc2(ctx), 'subnet');

    expect(subnet.metadata?.mapPublicIpOnLaunch).toBe(true);
  });

  it('keeps network ACL entries, not just a count', async () => {
    serveActions({
      DescribeNetworkAcls:
        '<DescribeNetworkAclsResponse><networkAclSet><item><networkAclId>acl-1</networkAclId><vpcId>vpc-1</vpcId><default>true</default>' +
        '<entrySet><item><ruleNumber>100</ruleNumber><protocol>6</protocol><ruleAction>allow</ruleAction><egress>false</egress>' +
        '<cidrBlock>0.0.0.0/0</cidrBlock><portRange><from>22</from><to>22</to></portRange></item></entrySet>' +
        '<associationSet><item><networkAclAssociationId>aclassoc-1</networkAclAssociationId><subnetId>subnet-1</subnetId></item></associationSet>' +
        '</item></networkAclSet></DescribeNetworkAclsResponse>',
    });

    const [acl] = ofType(await scanEc2(ctx), 'network_acl');

    expect(acl.metadata?.entryCount).toBe(1);
    expect((acl.metadata?.entries as unknown[])[0]).toMatchObject({ ruleNumber: 100, protocol: 'tcp', ruleAction: 'allow', egress: false, cidrBlock: '0.0.0.0/0', fromPort: 22, toPort: 22 });
    expect(acl.relationships?.subnetIds).toEqual(['subnet-1']);
  });

  it('keeps routes and flags an internet-gateway route', async () => {
    serveActions({
      DescribeRouteTables:
        '<DescribeRouteTablesResponse><routeTableSet><item><routeTableId>rtb-1</routeTableId><vpcId>vpc-1</vpcId>' +
        '<routeSet><item><destinationCidrBlock>10.0.0.0/16</destinationCidrBlock><gatewayId>local</gatewayId><state>active</state></item>' +
        '<item><destinationCidrBlock>0.0.0.0/0</destinationCidrBlock><gatewayId>igw-1</gatewayId><state>active</state></item></routeSet>' +
        '<associationSet><item><routeTableAssociationId>rtbassoc-1</routeTableAssociationId><subnetId>subnet-1</subnetId><main>false</main></item></associationSet>' +
        '</item></routeTableSet></DescribeRouteTablesResponse>',
    });

    const [rt] = ofType(await scanEc2(ctx), 'route_table');

    expect(rt.metadata).toMatchObject({ routeCount: 2, hasInternetGatewayRoute: true });
    expect(rt.relationships?.subnetIds).toEqual(['subnet-1']);
    expect(rt.isDefault).toBe(false);
  });

  it('marks an unassociated Elastic IP', async () => {
    serveActions({ DescribeAddresses: '<DescribeAddressesResponse><addressesSet><item><publicIp>3.3.3.3</publicIp><allocationId>eipalloc-1</allocationId><domain>vpc</domain></item></addressesSet></DescribeAddressesResponse>' });

    const [eip] = ofType(await scanEc2(ctx), 'elastic_ip');

    expect(eip.metadata?.associated).toBe(false);
  });
});