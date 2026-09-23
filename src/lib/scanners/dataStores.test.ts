import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * DynamoDB, Firehose, DRS, FMS, EMR, EventBridge, ElastiCache, Elastic
 * Beanstalk, ELB, OpenSearch, EFS.
 */
const callJsonApiMock = vi.fn();
const callQueryApiMock = vi.fn();
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
  callQueryApi: (...args: unknown[]) => callQueryApiMock(...args),
}));

import { scanDynamoDb, siblingArn } from './dynamodb';
import { scanFirehose } from './firehose';
import { scanDrs } from './drs';
import { scanFms } from './fms';
import { scanEmr } from './emr';
import { scanEvents } from './events';
import { scanElastiCache } from './elasticache';
import { scanElasticBeanstalk } from './elasticbeanstalk';
import { classicEvidence, listenerEvidence, scanElb, v2AttributeEvidence } from './elb';
import { domainEvidence, scanOpenSearch } from './es';
import { accessPointEvidence, scanEfs } from './efs';
import { keyValueMembers } from './queryMarker';

type Req = { target: string; body: Record<string, unknown> };
type QReq = { action: string; version: string; params?: Record<string, string> };
type Failure = { action?: string; normalizedCode?: string };

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ctx = { creds, region: 'eu-west-1' };
const withSink = (failures: Failure[]) => ({ creds: { ...creds, onCallFailure: (f: Failure) => failures.push(f) }, region: 'eu-west-1' });
const ok = (body: unknown) => Promise.resolve({ ok: true, status: 200, body });
const fail = (status = 500, errorCode = 'InternalFailure', errorMessage = '') => Promise.resolve({ ok: false, status, body: null, errorCode, errorMessage });
const op = (req: Req) => req.target.split('.').pop();
const json = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status }));

beforeEach(() => { callJsonApiMock.mockReset(); callQueryApiMock.mockReset(); fetchMock.mockReset(); });

// ─────────────────────────────────────────────────────────────────────────────
describe('DynamoDB', () => {
  it('follows LastEvaluatedTableName and keeps ARN identity for a table whose describe failed', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      switch (op(req)) {
        case 'ListTables':
          return req.body.ExclusiveStartTableName === 'a' ? ok({ TableNames: ['b'] }) : ok({ TableNames: ['a'], LastEvaluatedTableName: 'a' });
        case 'DescribeTable':
          return req.body.TableName === 'a' ? ok({ Table: { TableName: 'a', TableArn: 'arn:aws:dynamodb:eu-west-1:1:table/a', TableStatus: 'ACTIVE' } }) : fail();
        default:
          return ok({});
      }
    });
    const tables = (await scanDynamoDb(ctx)).filter((r) => r.resourceTypeKey === 'dynamodb_table');
    expect(tables.map((t) => t.resourceId)).toEqual(['arn:aws:dynamodb:eu-west-1:1:table/a', 'arn:aws:dynamodb:eu-west-1:1:table/b']);
  });

  it('siblingArn', () => {
    expect(siblingArn('arn:aws:dynamodb:eu-west-1:1:table/a', ':table/', 'z')).toBe('arn:aws:dynamodb:eu-west-1:1:table/z');
    expect(siblingArn(undefined, ':table/', 'z')).toBeNull();
  });
});

describe('Firehose', () => {
  it('pages on HasMoreDeliveryStreams using the last name as the exclusive start', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'ListDeliveryStreams') {
        return req.body.ExclusiveStartDeliveryStreamName === 's1'
          ? ok({ DeliveryStreamNames: ['s2'], HasMoreDeliveryStreams: false })
          : ok({ DeliveryStreamNames: ['s1'], HasMoreDeliveryStreams: true });
      }
      const n = req.body.DeliveryStreamName as string;
      return ok({ DeliveryStreamDescription: { DeliveryStreamName: n, DeliveryStreamARN: `arn:aws:firehose:eu-west-1:1:deliverystream/${n}` } });
    });
    const out = await scanFirehose(ctx);
    expect(out.map((r) => r.resourceName)).toEqual(['s1', 's2']);
  });
});

describe('DRS / FMS', () => {
  it('DRS: an uninitialized account is a quiet empty result; other failures are reported', async () => {
    fetchMock.mockImplementation(() => json({ message: 'UninitializedAccountException: not initialized' }, 400));
    expect(await scanDrs(ctx)).toEqual([]);
    const failures: Failure[] = [];
    fetchMock.mockImplementation(() => json({ message: 'boom' }, 500));
    await scanDrs(withSink(failures));
    expect(failures.some((f) => f.action === 'DescribeSourceServers')).toBe(true);
  });

  it('FMS: "not the admin" is quiet; a transient failure is reported; every page is read', async () => {
    callJsonApiMock.mockImplementation(() => fail(400, 'InvalidOperationException', 'This operation is not supported: account is not the Firewall Manager administrator'));
    const failures: Failure[] = [];
    expect(await scanFms(withSink(failures))).toEqual([]);
    expect(failures).toHaveLength(0);

    callJsonApiMock.mockImplementation(() => fail(500, 'InternalErrorException'));
    await scanFms(withSink(failures));
    expect(failures.some((f) => f.action === 'ListPolicies')).toBe(true);

    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => (req.body.NextToken === 't2'
      ? ok({ PolicyList: [{ PolicyId: 'p2', PolicyArn: 'arn:p2' }] })
      : ok({ PolicyList: [{ PolicyId: 'p1', PolicyArn: 'arn:p1' }], NextToken: 't2' })));
    expect((await scanFms(ctx)).map((r) => r.resourceId)).toEqual(['arn:p1', 'arn:p2']);
  });
});

describe('EMR / EventBridge', () => {
  it('EMR follows Marker', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'ListClusters') return req.body.Marker === 'm2' ? ok({ Clusters: [{ Id: 'j-2', Name: 'b' }] }) : ok({ Clusters: [{ Id: 'j-1', Name: 'a' }], Marker: 'm2' });
      return ok({});
    });
    expect((await scanEmr(ctx)).map((r) => r.resourceId)).toEqual(['j-1', 'j-2']);
  });

  it('EventBridge pages buses and rules, and records cross-account targets', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      switch (op(req)) {
        case 'ListEventBuses': return ok({ EventBuses: [{ Name: 'default', Arn: 'arn:aws:events:eu-west-1:111111111111:event-bus/default' }] });
        case 'ListRules':
          return req.body.NextToken === 'r2'
            ? ok({ Rules: [{ Name: 'r2', Arn: 'arn:aws:events:eu-west-1:111111111111:rule/r2' }] })
            : ok({ Rules: [{ Name: 'r1', Arn: 'arn:aws:events:eu-west-1:111111111111:rule/r1' }], NextToken: 'r2' });
        case 'ListTargetsByRule': return ok({ Targets: [{ Id: 't', Arn: 'arn:aws:events:eu-west-1:999999999999:event-bus/other' }] });
        default: return ok({});
      }
    });
    const rules = (await scanEvents(ctx)).filter((r) => r.resourceTypeKey === 'eventbridge_rule');
    expect(rules.map((r) => r.resourceName)).toEqual(['r1', 'r2']);
    expect(rules[0].metadata).toMatchObject({ crossAccountTargetArns: ['arn:aws:events:eu-west-1:999999999999:event-bus/other'] });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe('Query-protocol scanners', () => {
  it('ElastiCache follows Marker and reads top-level fields only', async () => {
    callQueryApiMock.mockImplementation((_c: unknown, req: QReq) => {
      if (req.action !== 'DescribeCacheClusters') return ok(`<${req.action}Response/>`);
      return req.params?.Marker === 'm2'
        ? ok('<CacheClusters><CacheCluster><CacheClusterId>c2</CacheClusterId><ARN>arn:c2</ARN></CacheCluster></CacheClusters>')
        : ok('<CacheClusters><CacheCluster><CacheClusterId>c1</CacheClusterId><ARN>arn:c1</ARN></CacheCluster></CacheClusters><Marker>m2</Marker>');
    });
    const out = (await scanElastiCache(ctx)).filter((r) => r.resourceTypeKey === 'elasticache_cluster');
    expect(out.map((r) => r.resourceId)).toEqual(['arn:c1', 'arn:c2']);
  });

  it('Elastic Beanstalk pages environments and reports a failed DescribeApplications', async () => {
    const failures: Failure[] = [];
    callQueryApiMock.mockImplementation((_c: unknown, req: QReq) => {
      if (req.action === 'DescribeApplications') return fail(503);
      if (req.action === 'DescribeEnvironments') {
        return req.params?.NextToken === 'n2'
          ? ok('<Environments><member><EnvironmentId>e-2</EnvironmentId><EnvironmentName>b</EnvironmentName></member></Environments>')
          : ok('<Environments><member><EnvironmentId>e-1</EnvironmentId><EnvironmentName>a</EnvironmentName></member></Environments><NextToken>n2</NextToken>');
      }
      return ok(`<${req.action}Response/>`);
    });
    const envs = (await scanElasticBeanstalk(withSink(failures))).filter((r) => r.resourceTypeKey === 'elastic_beanstalk_environment');
    expect(envs.map((r) => r.resourceId)).toEqual(['e-1', 'e-2']);
    expect(failures.some((f) => f.action === 'DescribeApplications')).toBe(true);
  });

  it('ELB follows NextMarker (previously one page) and attaches listener/attribute evidence', async () => {
    callQueryApiMock.mockImplementation((_c: unknown, req: QReq) => {
      if (req.action === 'DescribeLoadBalancers' && req.version === '2015-12-01') {
        const lb = (n: string) => `<member><LoadBalancerArn>arn:lb/${n}</LoadBalancerArn><LoadBalancerName>${n}</LoadBalancerName><Type>application</Type><Scheme>internet-facing</Scheme></member>`;
        return req.params?.Marker === 'nm' ? ok(`<LoadBalancers>${lb('b')}</LoadBalancers>`) : ok(`<LoadBalancers>${lb('a')}</LoadBalancers><NextMarker>nm</NextMarker>`);
      }
      if (req.action === 'DescribeListeners') return ok('<Listeners><member><Protocol>HTTP</Protocol><Port>80</Port><DefaultActions><member><Type>forward</Type></member></DefaultActions></member></Listeners>');
      if (req.action === 'DescribeLoadBalancerAttributes') return ok('<Attributes><member><Key>deletion_protection.enabled</Key><Value>false</Value></member></Attributes>');
      return ok(`<${req.action}Response/>`);
    });
    const albs = (await scanElb(ctx)).filter((r) => r.resourceTypeKey === 'elb_alb');
    expect(albs.map((r) => r.resourceId)).toEqual(['arn:lb/a', 'arn:lb/b']);
    expect(albs[0].metadata).toMatchObject({ httpListenersWithoutRedirect: 1, deletionProtectionEnabled: false, internetFacing: true });
  });

  it('ELB evidence helpers', () => {
    expect(listenerEvidence(null)).toEqual({ listenersCollected: false });
    expect(listenerEvidence('<Listeners><member><Protocol>HTTP</Protocol><DefaultActions><member><Type>redirect</Type><RedirectConfig><Protocol>HTTPS</Protocol></RedirectConfig></member></DefaultActions></member></Listeners>'))
      .toMatchObject({ httpListenersWithoutRedirect: 0 });
    expect(v2AttributeEvidence('<Attributes><member><Key>access_logs.s3.enabled</Key><Value>true</Value></member></Attributes>')).toMatchObject({ accessLogsEnabled: true, deletionProtectionEnabled: null });
    expect(classicEvidence('<LoadBalancerName>c</LoadBalancerName><Scheme>internet-facing</Scheme><ListenerDescriptions><member><Listener><Protocol>HTTP</Protocol></Listener></member></ListenerDescriptions>', null))
      .toMatchObject({ plaintextListenerCount: 1, attributesCollected: false, accessLogsEnabled: null });
    expect(keyValueMembers('<Attributes><member><Key>a</Key><Value>1</Value></member></Attributes>')).toEqual({ a: '1' });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe('OpenSearch', () => {
  it('describes domains through the batch domain-info call and always keys rows by name', async () => {
    const posted: string[][] = [];
    fetchMock.mockImplementation((url: string, init?: RequestInit) => {
      if (url.endsWith('/2021-01-01/domain')) return json({ DomainNames: Array.from({ length: 6 }, (_, i) => ({ DomainName: `d${i}`, EngineType: 'OpenSearch' })) });
      if (url.endsWith('/opensearch/domain-info')) {
        const names = (JSON.parse(String(init?.body)) as { DomainNames: string[] }).DomainNames;
        posted.push(names);
        return json({ DomainStatusList: names.filter((n) => n !== 'd5').map((n) => ({ DomainName: n, ARN: `arn:aws:es:eu-west-1:1:domain/${n}`, AccessPolicies: '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"es:*"}]}' })) });
      }
      return json({}, 404);
    });
    const out = await scanOpenSearch(ctx);
    expect(posted.map((p) => p.length).sort()).toEqual([1, 5]);
    expect(out.map((r) => r.resourceId)).toEqual(['d0', 'd1', 'd2', 'd3', 'd4', 'd5']);
    expect(out[0].metadata).toMatchObject({ detailsCollected: true, inVpc: false, publiclyAccessible: true });
    expect(out[5].metadata).toMatchObject({ detailsCollected: false });
    expect(domainEvidence(undefined, 'OpenSearch')).toEqual({ detailsCollected: false, engineType: 'OpenSearch' });
  });

  it('reports a failed ListDomainNames', async () => {
    const failures: Failure[] = [];
    fetchMock.mockImplementation(() => json({}, 500));
    expect(await scanOpenSearch(withSink(failures))).toEqual([]);
    expect(failures.some((f) => f.action === 'ListDomainNames')).toBe(true);
  });
});

describe('EFS', () => {
  it('pages file systems (Marker) and access points (NextToken) and records backup status', async () => {
    fetchMock.mockImplementation((url: string) => {
      const u = new URL(url);
      if (u.pathname.endsWith('/file-systems')) {
        return u.searchParams.get('Marker') === 'm2'
          ? json({ FileSystems: [{ FileSystemId: 'fs-2' }] })
          : json({ FileSystems: [{ FileSystemId: 'fs-1' }], NextMarker: 'm2' });
      }
      if (u.pathname.endsWith('/access-points')) return json({ AccessPoints: [{ AccessPointId: 'ap-1', AccessPointArn: 'arn:ap-1', RootDirectory: { Path: '/' } }] });
      if (u.pathname.endsWith('/backup-policy')) return json({ message: 'PolicyNotFound' }, 404);
      if (u.pathname.endsWith('/policy')) return json({ message: 'PolicyNotFound' }, 404);
      return json({}, 404);
    });
    const out = await scanEfs(ctx);
    expect(out.filter((r) => r.resourceTypeKey === 'efs_file_system').map((r) => r.resourceId)).toEqual(['fs-1', 'fs-2']);
    expect(out[0].metadata).toMatchObject({ automaticBackupsStatus: 'DISABLED', hasResourcePolicy: false });
    expect(accessPointEvidence({ AccessPointId: 'a', PosixUser: { Uid: 0 } })).toMatchObject({ enforcesRootDirectory: false, enforcesUserIdentity: true, posixUserIsRoot: true });
  });
});
