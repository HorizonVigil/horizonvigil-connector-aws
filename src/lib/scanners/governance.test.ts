import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * CloudHSM, CloudWatch, Cognito, Compute Optimizer, Config, Control Tower,
 * DataSync, Detective, Direct Connect, Directory Service, DMS.
 */
const callJsonApiMock = vi.fn();
const fetchMock = vi.fn();
vi.mock('aws4fetch', () => ({
  AwsClient: class {
    fetch(url: string, init?: RequestInit) {
      return fetchMock(url, init);
    }
  },
}));
vi.mock('../awsApi', async (importOriginal: () => Promise<Record<string, unknown>>) => ({
  ...(await importOriginal()),
  callJsonApi: (...args: unknown[]) => callJsonApiMock(...args),
}));

import { scanCloudHsm } from './cloudhsm';
import { alarmEvidence, extractMonitoringAlarmRows, scanCloudWatch } from './cloudwatch';
import { scanCognito } from './cognito';
import { isActionable, scanComputeOptimizer } from './computeoptimizer';
import { scanConfig } from './config';
import { scanControlTower } from './controltower';
import { locationType, scanDataSync } from './datasync';
import { scanDetective } from './detective';
import { scanDirectConnect } from './directconnect';
import { scanDirectoryService } from './directoryservice';
import { scanDms, taskLoggingEnabled } from './dms';

type Req = { target: string; body: Record<string, unknown> };
type Failure = { action?: string };

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ctx = { creds, region: 'eu-west-1' };
const withSink = (failures: Failure[]) => ({ creds: { ...creds, onCallFailure: (f: Failure) => failures.push(f) }, region: 'eu-west-1' });
const ok = (body: unknown) => Promise.resolve({ ok: true, status: 200, body });
const denied = () => Promise.resolve({ ok: false, status: 400, body: null, errorCode: 'AccessDeniedException' });
const op = (req: Req) => req.target.split('.').pop();
const json = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status }));
const xml = (body: string) => Promise.resolve(new Response(body, { status: 200 }));
const actionOf = (init?: RequestInit) => /Action=([^&]*)/.exec(String(init?.body ?? ''))?.[1] ?? '';

beforeEach(() => { callJsonApiMock.mockReset(); fetchMock.mockReset(); });

describe('CloudHSM', () => {
  it('reads every page and records single-AZ HSM placement', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => (req.body.NextToken === 't2'
      ? ok({ Clusters: [{ ClusterId: 'c2' }] })
      : ok({ Clusters: [{ ClusterId: 'c1', Hsms: [{ AvailabilityZone: 'a' }, { AvailabilityZone: 'a' }] }], NextToken: 't2' })));
    const out = await scanCloudHsm(ctx);
    expect(out.map((r) => r.resourceId)).toEqual(['c1', 'c2']);
    expect(out[0].metadata).toMatchObject({ hsmCount: 2, multiAz: false });
  });
});

describe('CloudWatch', () => {
  it('reads EVERY page of log groups (50 per page) and attaches metric filters', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'DescribeLogGroups') {
        return req.body.nextToken === 't2'
          ? ok({ logGroups: [{ logGroupName: 'b' }] })
          : ok({ logGroups: [{ logGroupName: 'ct', arn: 'arn:lg:ct:*', kmsKeyId: 'arn:kms' }], nextToken: 't2' });
      }
      return ok({ metricFilters: [{ filterName: 'root', logGroupName: 'ct', filterPattern: '{ $.userIdentity.type = "Root" }', metricTransformations: [{ metricName: 'RootUsage', metricNamespace: 'CIS' }] }] });
    });
    fetchMock.mockImplementation((_u: string, init?: RequestInit) => xml(`<${actionOf(init)}Response/>`));
    const groups = (await scanCloudWatch(ctx)).filter((r) => r.resourceTypeKey === 'cloudwatch_log_group');
    expect(groups.map((r) => r.resourceName)).toEqual(['ct', 'b']);
    expect(groups[0].metadata).toMatchObject({ encryptedWithKms: true, neverExpires: true, metricFilters: [{ name: 'root', metrics: [{ name: 'RootUsage', namespace: 'CIS' }] }] });
  });

  it('reads a metric-math alarm\'s OWN fields, not a nested metric\'s', () => {
    const e = alarmEvidence('<AlarmName>a</AlarmName><ActionsEnabled>true</ActionsEnabled><AlarmActions><member>arn:aws:sns:eu-west-1:1:t</member></AlarmActions>' +
      '<StateValue>OK</StateValue><Metrics><member><Id>m1</Id><MetricStat><Metric><Namespace>AWS/EC2</Namespace><MetricName>CPUUtilization</MetricName></Metric></MetricStat></member></Metrics>' +
      '<Threshold>80</Threshold><ComparisonOperator>GreaterThanThreshold</ComparisonOperator>');
    expect(e).toMatchObject({ metricName: null, namespace: null, isMetricMath: true, hasAlarmActions: true, threshold: '80' });
  });

  it('keeps the monitoring_alarms extraction working', () => {
    const rows = extractMonitoringAlarmRows([{ resourceTypeKey: 'cloudwatch_alarm', resourceId: 'x', resourceName: 'a', region: 'eu-west-1', state: 'ALARM', metadata: { threshold: '80', metricName: 'm', namespace: 'n' } }], 'conn');
    expect(rows[0]).toMatchObject({ threshold: 80, metric_name: 'm', state: 'ALARM' });
  });
});

describe('Cognito', () => {
  it('flags guest access on identity pools and self sign-up without MFA on user pools', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      switch (op(req)) {
        case 'ListUserPools': return ok({ UserPools: [{ Id: 'up-1', Name: 'users' }] });
        case 'ListIdentityPools': return ok({ IdentityPools: [{ IdentityPoolId: 'ip-1', IdentityPoolName: 'guests' }] });
        case 'DescribeUserPool': return ok({ UserPool: { MfaConfiguration: 'OFF', AdminCreateUserConfig: { AllowAdminCreateUserOnly: false } } });
        case 'DescribeIdentityPool': return ok({ AllowUnauthenticatedIdentities: true });
        default: return denied();
      }
    });
    const out = await scanCognito(ctx);
    expect(out.find((r) => r.resourceId === 'up-1')?.metadata).toMatchObject({ mfaConfiguration: 'OFF', selfSignUpEnabled: true, advancedSecurityMode: 'OFF' });
    expect(out.find((r) => r.resourceId === 'ip-1')?.metadata).toMatchObject({ allowUnauthenticatedIdentities: true });
  });
});

describe('Compute Optimizer', () => {
  it('excludes Optimized instances (AWS uses mixed case)', () => {
    expect(isActionable('Optimized')).toBe(false);
    expect(isActionable('Overprovisioned')).toBe(true);
  });

  it('reports a failed enrollment check but treats "not enrolled" as a settled answer', async () => {
    const failures: Failure[] = [];
    callJsonApiMock.mockImplementation(() => denied());
    await scanComputeOptimizer(withSink(failures));
    expect(failures).toHaveLength(1);

    const none: Failure[] = [];
    callJsonApiMock.mockImplementation(() => ok({ status: 'Inactive' }));
    expect(await scanComputeOptimizer(withSink(none))).toEqual([]);
    expect(none).toEqual([]);
  });
});

describe('Config', () => {
  it('does not call a recorder "stopped" when its status could not be read', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'DescribeConfigurationRecorders') return ok({ ConfigurationRecorders: [{ name: 'default', recordingGroup: { allSupported: true, includeGlobalResourceTypes: true } }] });
      if (op(req) === 'DescribeConfigurationRecorderStatus') return denied();
      return ok({});
    });
    const [rec] = (await scanConfig(ctx)).filter((r) => r.resourceTypeKey === 'config_recorder');
    expect(rec.state).toBeUndefined();
    expect(rec.metadata).toMatchObject({ statusCollected: false, recording: null, includeGlobalResourceTypes: true });
  });

  it('reads past the 25-rule first page', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'DescribeConfigRules') return req.body.NextToken === 't2' ? ok({ ConfigRules: [{ ConfigRuleName: 'r2' }] }) : ok({ ConfigRules: [{ ConfigRuleName: 'r1' }], NextToken: 't2' });
      return ok({});
    });
    const rules = (await scanConfig(ctx)).filter((r) => r.resourceTypeKey === 'config_rule');
    expect(rules.map((r) => r.resourceName)).toEqual(['r1', 'r2']);
  });
});

describe('Control Tower / Detective', () => {
  it('Control Tower records drift and an outdated landing zone', async () => {
    fetchMock.mockImplementation((url: string) => (url.endsWith('/list-landingzones')
      ? json({ landingZones: [{ arn: 'arn:lz' }] })
      : json({ landingZone: { status: 'ACTIVE', version: '3.2', latestAvailableVersion: '3.3', driftStatus: { status: 'DRIFTED' } } })));
    const [lz] = await scanControlTower(ctx);
    expect(lz.metadata).toMatchObject({ outdated: true, driftStatus: 'DRIFTED' });
  });

  it('Detective reports a real failure and survives an unparseable body', async () => {
    const failures: Failure[] = [];
    fetchMock.mockImplementation(() => Promise.resolve(new Response('<html>', { status: 200 })));
    expect(await scanDetective(withSink(failures))).toEqual([]);
    expect(failures.some((f) => f.action === 'ListGraphs')).toBe(true);
  });
});

describe('DataSync / Direct Connect / Directory Service / DMS', () => {
  it('DataSync no longer skips tasks when locations fail, and maps the data flow', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'ListLocations') return denied();
      if (op(req) === 'ListTasks') return ok({ Tasks: [{ TaskArn: 'arn:task', Name: 't' }] });
      return ok({ SourceLocationArn: 'arn:src', DestinationLocationArn: 'arn:dst' });
    });
    const [task] = await scanDataSync(ctx);
    expect(task.relationships).toMatchObject({ sourceLocationArn: 'arn:src', destinationLocationArn: 'arn:dst' });
    expect(task.metadata).toMatchObject({ loggingEnabled: false });
    expect(locationType('s3://bucket/x')).toBe('s3');
  });

  it('Direct Connect reports a failed VIF list and never stores BGP keys', async () => {
    const failures: Failure[] = [];
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => (op(req) === 'DescribeConnections'
      ? ok({ connections: [{ connectionId: 'dx-1', ownerAccount: '111122223333', macSecCapable: false }] })
      : denied()));
    const out = await scanDirectConnect(withSink(failures));
    expect(out).toHaveLength(1);
    expect(failures.some((f) => f.action === 'DescribeVirtualInterfaces')).toBe(true);

    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => (op(req) === 'DescribeConnections'
      ? ok({ connections: [] })
      : ok({ virtualInterfaces: [{ virtualInterfaceId: 'vif-1', virtualInterfaceType: 'public', bgpPeers: [{ authKey: 'SUPERSECRETKEY' }, {}] }] })));
    const [vif] = await scanDirectConnect(ctx);
    expect(vif.metadata).toMatchObject({ isPublic: true, bgpPeerCount: 2, bgpPeersWithoutAuthKey: 1 });
    expect(JSON.stringify(vif).includes('SUPERSECRETKEY')).toBe(false);
  });

  it('Directory Service reads every page and records log forwarding', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'ListLogSubscriptions') return ok({ LogSubscriptions: [{ DirectoryId: 'd-1', LogGroupName: '/ds/d-1' }] });
      return req.body.NextToken === 't2' ? ok({ DirectoryDescriptions: [{ DirectoryId: 'd-2' }] }) : ok({ DirectoryDescriptions: [{ DirectoryId: 'd-1', RadiusStatus: 'Completed' }], NextToken: 't2' });
    });
    const out = await scanDirectoryService(ctx);
    expect(out.map((r) => r.resourceId)).toEqual(['d-1', 'd-2']);
    expect(out[0].metadata).toMatchObject({ mfaEnabled: true, logForwardingEnabled: true });
    expect(out[1].metadata).toMatchObject({ logForwardingEnabled: false });
  });

  it('DMS follows Marker and attaches endpoint SSL mode and task logging', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'DescribeReplicationInstances') {
        return req.body.Marker === 'm2'
          ? ok({ ReplicationInstances: [{ ReplicationInstanceArn: 'arn:ri2', ReplicationInstanceIdentifier: 'b' }] })
          : ok({ ReplicationInstances: [{ ReplicationInstanceArn: 'arn:ri1', ReplicationInstanceIdentifier: 'a', PubliclyAccessible: true }], Marker: 'm2' });
      }
      if (op(req) === 'DescribeEndpoints') return ok({ Endpoints: [{ EndpointArn: 'arn:src', EngineName: 'mysql', SslMode: 'none' }] });
      return ok({ ReplicationTasks: [{ ReplicationTaskArn: 'arn:t', ReplicationTaskIdentifier: 't', SourceEndpointArn: 'arn:src', ReplicationTaskSettings: '{"Logging":{"EnableLogging":false}}' }] });
    });
    const out = await scanDms(ctx);
    expect(out.filter((r) => r.resourceTypeKey === 'dms_replication_instance')).toHaveLength(2);
    expect(out.find((r) => r.resourceId === 'arn:t')?.metadata).toMatchObject({ sourceSslMode: 'none', sourceEngine: 'mysql', loggingEnabled: false });
    expect(taskLoggingEnabled('not json')).toBeNull();
  });
});