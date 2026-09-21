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

import { scanEc2 } from './ec2';
import type { ScannedResource } from './types';

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

beforeEach(() => {
  fetchMock.mockReset();
});

describe('scanEc2 pagination', () => {
  it('returns resources from EVERY page, not just the first', async () => {
    serveTwoVolumePages();

    const resources = await scanEc2(ctx);

    const volumes = resources.filter((r) => r.resourceTypeKey === 'ebs_volume').map((r) => r.resourceId);
    expect(volumes.sort()).toEqual(['vol-1', 'vol-2']);
  });

  it('actually sends the continuation token back to AWS', async () => {
    serveTwoVolumePages();

    await scanEc2(ctx);

    const volumeCalls = fetchMock.mock.calls.filter((c) => request(c[1] as RequestInit).action === 'DescribeVolumes');
    expect(volumeCalls).toHaveLength(2);
    expect(request(volumeCalls[1][1] as RequestInit).token).toBe('page-2');
  });

  it('reports per-operation pages and a success termination when nothing is truncated', async () => {
    serveTwoVolumePages();

    const resources = await scanEc2(ctx);

    const diagnostics = (resources[0].metadata as { ec2ScanDiagnostics: { status: string; operations: { action: string; pages: number; termination: string }[] } }).ec2ScanDiagnostics;
    const volumes = diagnostics.operations.find((o) => o.action === 'DescribeVolumes');
    expect(volumes).toMatchObject({ pages: 2, termination: 'complete' });
    expect(diagnostics.status).toBe('success');
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
    const failures: { action?: string; normalizedCode?: string }[] = [];
    fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
      const { action } = request(init);
      if (action === 'DescribeElasticGpus') return denied();
      return empty(action);
    });

    await scanEc2({ creds: { ...creds, onCallFailure: (f) => failures.push(f) }, region: 'eu-west-1' });

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

    const resources = await scanEc2(ctx);

    const diagnostics = (resources[0].metadata as { ec2ScanDiagnostics: { status: string; operations: { action: string; termination: string }[] } }).ec2ScanDiagnostics;
    expect(diagnostics.operations.find((o) => o.action === 'DescribeVpcs')?.termination).toBe('failed');
    expect(diagnostics.status).toBe('partial');
  });
});
  it('marks the scan partial and degrades coverage when a page is never reached', async () => {
    // AWS keeps handing out tokens (a page cap is reached): the types this
    // scanner covers must not be trusted to prove absence.
    const failures: { normalizedCode?: string }[] = [];
    fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
      const { action, token } = request(init);
      if (action === 'DescribeVolumes') {
        const n = token === null ? 1 : Number(token);
        return ok(`<DescribeVolumesResponse><volumeSet><item><volumeId>vol-${n}</volumeId></item></volumeSet><NextToken>${n + 1}</NextToken></DescribeVolumesResponse>`);
      }
      return empty(action);
    });

    const resources = await scanEc2({ creds: { ...creds, onCallFailure: (f) => failures.push(f) }, region: 'eu-west-1' });

    const diagnostics = (resources[0].metadata as { ec2ScanDiagnostics: { status: string } }).ec2ScanDiagnostics;
    expect(diagnostics.status).toBe('partial');
    expect(failures.some((f) => f.normalizedCode === 'PAGINATION_TRUNCATED')).toBe(true);
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

  const serveSg = (permissions: string) => {
    fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
      const { action } = request(init);
      if (action === 'DescribeSecurityGroups') return ok(sgResponse(permissions));
      return empty(action);
    });
  };

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
