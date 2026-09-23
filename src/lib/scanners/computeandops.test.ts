import { beforeEach, describe, expect, it, vi } from 'vitest';

/** Auto Scaling, CloudFormation, Backup, Batch, App Mesh. */
const fetchMock = vi.fn();
vi.mock('aws4fetch', () => ({
  AwsClient: class {
    fetch(url: string, init?: RequestInit) {
      return fetchMock(url, init);
    }
  },
}));

import { groupEvidence, launchConfigEvidence, scanAutoScaling } from './autoscaling';
import { scanCloudFormation, stackEvidence } from './cloudformation';
import { scanBackup } from './backup';
import { jobDefinitionEvidence, scanBatch } from './batch';
import { scanAppMesh } from './appmesh';
import { withoutSections } from './xmlShape';

type Failure = { action?: string; normalizedCode?: string };

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ctx = { creds, region: 'eu-west-1' };
const withSink = (failures: Failure[]) => ({ creds: { ...creds, onCallFailure: (f: Failure) => failures.push(f) }, region: 'eu-west-1' });
const xml = (body: string, status = 200) => Promise.resolve(new Response(body, { status }));
const json = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status }));
const actionOf = (init?: RequestInit) => /Action=([^&]*)/.exec(String(init?.body ?? ''))?.[1] ?? '';
const tokenOf = (init?: RequestInit) => /NextToken=([^&]*)/.exec(String(init?.body ?? ''))?.[1] ?? null;

beforeEach(() => { fetchMock.mockReset(); });

describe('xmlShape.withoutSections', () => {
  it('removes nested sections so top-level fields read correctly', () => {
    const doc = '<A><Name>top</Name><Kids><member><Name>kid</Name></member></Kids></A>';
    expect(withoutSections(doc, ['Kids'])).toBe('<A><Name>top</Name></A>');
  });
});

describe('Auto Scaling', () => {
  const asg = (name: string) =>
    `<member><AutoScalingGroupName>${name}</AutoScalingGroupName><AutoScalingGroupARN>arn:asg:${name}</AutoScalingGroupARN>` +
    `<LaunchTemplate><LaunchTemplateId>lt-1</LaunchTemplateId><Version>$Latest</Version></LaunchTemplate>` +
    `<MinSize>1</MinSize><MaxSize>3</MaxSize><DesiredCapacity>2</DesiredCapacity>` +
    `<AvailabilityZones><member>eu-west-1a</member></AvailabilityZones><HealthCheckType>EC2</HealthCheckType>` +
    `<Instances><member><InstanceId>i-1</InstanceId><LaunchConfigurationName>old-lc</LaunchConfigurationName></member></Instances>` +
    `<VPCZoneIdentifier>subnet-a,subnet-b</VPCZoneIdentifier></member>`;

  it('never reads an INSTANCE\'s launch configuration as the group\'s', () => {
    const e = groupEvidence(asg('g1'));
    expect(e.metadata).toMatchObject({ launchConfigurationName: null, usesLaunchConfiguration: false, launchTemplateId: 'lt-1', availabilityZoneCount: 1, healthCheckType: 'EC2' });
    expect(e.relationships).toMatchObject({ instanceIds: ['i-1'], subnetIds: ['subnet-a', 'subnet-b'] });
  });

  it('records launch-configuration exposure without storing user data', () => {
    const e = launchConfigEvidence('<LaunchConfigurationName>lc</LaunchConfigurationName><AssociatePublicIpAddress>true</AssociatePublicIpAddress>' +
      '<MetadataOptions><HttpTokens>optional</HttpTokens></MetadataOptions><UserData>c2VjcmV0PWh1bnRlcjI=</UserData>' +
      '<BlockDeviceMappings><member><DeviceName>/dev/xvda</DeviceName><Ebs><Encrypted>false</Encrypted></Ebs></member></BlockDeviceMappings>');
    expect(e).toMatchObject({ associatePublicIpAddress: true, imdsHttpTokens: 'optional', hasUserData: true, unencryptedEbsVolumeCount: 1 });
    expect(JSON.stringify(e).includes('c2VjcmV0')).toBe(false);
  });

  it('reads every page of groups', async () => {
    fetchMock.mockImplementation((_u: string, init?: RequestInit) => {
      if (actionOf(init) === 'DescribeAutoScalingGroups') {
        return tokenOf(init) === 't2'
          ? xml(`<R><AutoScalingGroups>${asg('g2')}</AutoScalingGroups></R>`)
          : xml(`<R><AutoScalingGroups>${asg('g1')}</AutoScalingGroups><NextToken>t2</NextToken></R>`);
      }
      return xml('<R/>');
    });
    const groups = (await scanAutoScaling(ctx)).filter((r) => r.resourceTypeKey === 'autoscaling_group');
    expect(groups.map((r) => r.resourceName)).toEqual(['g1', 'g2']);
  });
});

describe('CloudFormation', () => {
  const stack = (name: string, description = '') =>
    `<member><StackId>arn:stack/${name}</StackId><StackName>${name}</StackName>${description}` +
    `<Outputs><member><OutputKey>Pwd</OutputKey><OutputValue>s3cr3t</OutputValue><Description>output desc</Description></member></Outputs>` +
    `<StackStatus>CREATE_COMPLETE</StackStatus><EnableTerminationProtection>false</EnableTerminationProtection>` +
    `<Capabilities><member>CAPABILITY_IAM</member></Capabilities><RoleARN>arn:aws:iam::1:role/cfn</RoleARN></member>`;

  it('never takes an Output\'s Description as the stack\'s, and never stores output values', () => {
    const e = stackEvidence(stack('s1'));
    expect(e.metadata).toMatchObject({ description: null, terminationProtection: false, capabilities: ['CAPABILITY_IAM'], outputCount: 1 });
    expect(e.relationships.roleArn).toBe('arn:aws:iam::1:role/cfn');
    expect(JSON.stringify(e).includes('s3cr3t')).toBe(false);
  });

  it('reads every page of stacks', async () => {
    fetchMock.mockImplementation((_u: string, init?: RequestInit) => {
      if (actionOf(init) === 'DescribeStacks') {
        return tokenOf(init) === 't2'
          ? xml(`<R><Stacks>${stack('s2')}</Stacks></R>`)
          : xml(`<R><Stacks>${stack('s1')}</Stacks><NextToken>t2</NextToken></R>`);
      }
      return xml('<R/>');
    });
    const stacks = (await scanCloudFormation(ctx)).filter((r) => r.resourceTypeKey === 'cloudformation_stack');
    expect(stacks.map((r) => r.resourceName)).toEqual(['s1', 's2']);
  });
});

describe('Backup', () => {
  function serve(vaultCount: number, pointsNext?: string) {
    fetchMock.mockImplementation((url: string) => {
      if (url.includes('/backup/plans/')) return json({ BackupPlansList: [] });
      if (url.includes('/audit/report-plans/')) return json({ ReportPlans: [{ ReportPlanName: undefined }] });
      if (url.includes('/access-policy')) return json({}, 404);
      if (url.includes('/recovery-points/')) return json({ RecoveryPoints: [{ RecoveryPointArn: `${url}#rp`, IsEncrypted: true }], ...(pointsNext ? { NextToken: pointsNext } : {}) });
      if (url.includes('/backup-vaults/')) {
        return json({ BackupVaultList: Array.from({ length: vaultCount }, (_, i) => ({ BackupVaultName: `v${i}`, BackupVaultArn: `arn:v${i}`, Locked: i === 0 })) });
      }
      return json({}, 404);
    });
  }

  it('records Vault Lock and "no access policy" as facts', async () => {
    serve(1);
    const vault = (await scanBackup(ctx)).find((r) => r.resourceTypeKey === 'backup_vault');
    expect(vault?.metadata).toMatchObject({ locked: true, accessPolicyCollected: true, hasAccessPolicy: false });
  });

  it('REPORTS the recovery-point cap instead of silently tombstoning points', async () => {
    const failures: Failure[] = [];
    serve(12);
    await scanBackup(withSink(failures));
    expect(failures.some((f) => f.action === 'ListRecoveryPointsByBackupVault' && f.normalizedCode === 'PAGINATION_TRUNCATED')).toBe(true);
  });

  it('does not report truncation when every recovery point was read', async () => {
    const failures: Failure[] = [];
    serve(2);
    await scanBackup(withSink(failures));
    expect(failures.some((f) => f.action === 'ListRecoveryPointsByBackupVault')).toBe(false);
  });

  it('records a nameless report plan with an empty id (quarantined), not undefined', async () => {
    serve(1);
    const rp = (await scanBackup(ctx)).find((r) => r.resourceTypeKey === 'backup_report_plan');
    expect(rp?.resourceId).toBe('');
  });
});

describe('Batch', () => {
  it('records privileged / root containers and secret-like env NAMES, never values', () => {
    const e = jobDefinitionEvidence({
      jobDefinitionName: 'etl', revision: 3,
      containerProperties: { privileged: true, environment: [{ name: 'DB_PASSWORD', value: 'hunter2' }, { name: 'REGION', value: 'eu' }] },
    });
    expect(e).toMatchObject({ privileged: true, runsAsRoot: true, readonlyRootFilesystem: false, plaintextSecretLikeEnvNames: ['DB_PASSWORD'] });
    expect(JSON.stringify(e).includes('hunter2')).toBe(false);
  });

  it('reads every page of job definitions', async () => {
    fetchMock.mockImplementation((url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
      if (url.endsWith('/v1/describejobdefinitions')) {
        return body.nextToken === 't2'
          ? json({ jobDefinitions: [{ jobDefinitionName: 'b', jobDefinitionArn: 'arn:jd:b', revision: 1 }] })
          : json({ jobDefinitions: [{ jobDefinitionName: 'a', jobDefinitionArn: 'arn:jd:a', revision: 1 }], nextToken: 't2' });
      }
      return json({});
    });
    const defs = (await scanBatch(ctx)).filter((r) => r.resourceTypeKey === 'batch_job_definition');
    expect(defs.map((r) => r.resourceId)).toEqual(['arn:jd:a', 'arn:jd:b']);
  });
});

describe('App Mesh', () => {
  it('reports a failed ListMeshes (e.g. after end of support) instead of returning a silent []', async () => {
    const failures: Failure[] = [];
    fetchMock.mockImplementation(() => json({}, 400));
    expect(await scanAppMesh(withSink(failures))).toEqual([]);
    expect(failures.some((f) => f.action === 'ListMeshes')).toBe(true);
  });

  it('records the mesh egress filter', async () => {
    fetchMock.mockImplementation((url: string) => {
      if (/\/meshes\?/.test(url)) return json({ meshes: [{ meshName: 'm', arn: 'arn:mesh:m' }] });
      if (/\/meshes\/m(\?|$)/.test(url)) return json({ mesh: { spec: { egressFilter: { type: 'ALLOW_ALL' } } } });
      return json({ virtualNodes: [], virtualServices: [] });
    });
    const [mesh] = await scanAppMesh(ctx);
    expect(mesh.metadata).toMatchObject({ egressFilterCollected: true, egressFilter: 'ALLOW_ALL' });
  });
});