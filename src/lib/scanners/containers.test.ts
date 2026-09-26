import { beforeEach, describe, expect, it, vi } from 'vitest';

/** ECS, EKS (AWS side), EKS workloads (Kubernetes side), EC2 CPU metrics. */
const callJsonApiMock = vi.fn();
const callQueryApiMock = vi.fn();
const fetchMock = vi.fn();
const k8sFetchMock = vi.fn();
vi.mock('aws4fetch', () => ({
  AwsClient: class {
    fetch(url: string, init?: RequestInit) {
      return fetchMock(url, init);
    }
  },
  AwsV4Signer: class {
    opts: { url: string; method?: string; headers?: HeadersInit };
    constructor(opts: { url: string; method?: string; headers?: HeadersInit }) { this.opts = opts; }
    async sign() {
      return { url: new URL(this.opts.url), method: this.opts.method ?? 'GET', headers: new Headers(this.opts.headers) };
    }
  },
}));
vi.mock('undici', () => ({
  fetch: (url: string, init?: unknown) => k8sFetchMock(String(url), init),
  Agent: class {
    closed = false;
    opts: unknown;
    constructor(opts: unknown) {
      this.opts = opts;
      const g = globalThis as { __undiciAgents?: Array<{ closed: boolean; opts: unknown }> };
      g.__undiciAgents = g.__undiciAgents ?? [];
      g.__undiciAgents.push(this);
    }
    close() { this.closed = true; return Promise.resolve(); }
  },
}));
vi.mock('../awsApi', async (importOriginal: () => Promise<Record<string, unknown>>) => ({
  ...(await importOriginal()),
  callJsonApi: (...args: unknown[]) => callJsonApiMock(...args),
  callQueryApi: (...args: unknown[]) => callQueryApiMock(...args),
}));

import { scanEcs, taskDefinitionEvidence } from './ecs';
import { clusterEvidence, nodegroupEvidence, scanEks } from './eks';
import {
  k8sListAll, parseAuthMapYaml, plaintextSecretEnvNames, podSecurityEvidence, redactContainer, REDACTED, scanEksWorkloads, tokenSource,
} from './eksWorkloads';
import { metricDataParams, metricWindow, parseMetricDataResults, scanEc2CpuMetrics } from './ec2Metrics';

type Req = { target: string; body: Record<string, unknown> };
type Failure = { action?: string; normalizedCode?: string };

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ctx = { creds, region: 'eu-west-1' };
const withSink = (failures: Failure[]) => ({ creds: { ...creds, onCallFailure: (f: Failure) => failures.push(f) }, region: 'eu-west-1' });
const ok = (body: unknown) => Promise.resolve({ ok: true, status: 200, body });
const op = (req: Req) => req.target.split('.').pop();
const json = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status }));

beforeEach(() => {
  callJsonApiMock.mockReset(); callQueryApiMock.mockReset(); fetchMock.mockReset(); k8sFetchMock.mockReset();
  (globalThis as { __undiciAgents?: unknown[] }).__undiciAgents = [];
});

// ─────────────────────────────────────────────────────────────────────────────
describe('ECS', () => {
  it('reads every page of clusters and describes them in chunks', async () => {
    const described: string[][] = [];
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      switch (op(req)) {
        case 'ListClusters':
          return req.body.nextToken === 't2' ? ok({ clusterArns: ['arn:c2'] }) : ok({ clusterArns: ['arn:c1'], nextToken: 't2' });
        case 'DescribeClusters':
          described.push(req.body.clusters as string[]);
          return ok({ clusters: (req.body.clusters as string[]).map((a) => ({ clusterArn: a, clusterName: a.slice(4), status: 'ACTIVE' })) });
        default:
          return ok({});
      }
    });
    const out = await scanEcs(ctx);
    expect(out.filter((r) => r.resourceTypeKey === 'ecs_cluster').map((r) => r.resourceId)).toEqual(['arn:c1', 'arn:c2']);
    expect(described).toEqual([['arn:c1', 'arn:c2']]);
  });

  it('reports a failed ListClusters instead of returning an empty inventory', async () => {
    const failures: Failure[] = [];
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => (op(req) === 'ListClusters'
      ? Promise.resolve({ ok: false, status: 500, body: null, errorCode: 'ServerException' })
      : ok({})));
    await scanEcs(withSink(failures));
    expect(failures.some((f) => f.action === 'ListClusters')).toBe(true);
  });

  it('task-definition evidence flags privileged containers and plaintext secrets without storing values', () => {
    const e = taskDefinitionEvidence({
      taskDefinitionArn: 'arn:td:1', family: 'web', revision: 1, networkMode: 'host',
      containerDefinitions: [{ name: 'app', image: 'nginx', privileged: true, environment: [{ name: 'DB_PASSWORD', value: 'hunter2' }] }],
    } as never);
    expect(JSON.stringify(e)).not.toContain('hunter2');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe('EKS (AWS side)', () => {
  const route = (overrides: Record<string, unknown> = {}) => (url: string) => {
    const u = new URL(url);
    const path = u.pathname;
    if (path in overrides) return overrides[path] as Promise<Response>;
    if (path === '/clusters') {
      return u.searchParams.get('nextToken') === 'p2' ? json({ clusters: ['b'] }) : json({ clusters: ['a'], nextToken: 'p2' });
    }
    if (path === '/cluster-versions') return json({ clusterVersions: [{ clusterVersion: '1.33', status: 'STANDARD_SUPPORT' }, { clusterVersion: '1.28', status: 'EXTENDED_SUPPORT' }] });
    if (/^\/clusters\/[^/]+$/.test(path)) {
      const name = path.split('/')[2];
      return json({ cluster: { name, arn: `arn:aws:eks:eu-west-1:111:cluster/${name}`, version: '1.28', resourcesVpcConfig: { endpointPublicAccess: true, publicAccessCidrs: ['0.0.0.0/0'] } } });
    }
    if (path.endsWith('/node-groups')) return json({ nodegroups: ['ng1'] });
    if (path.endsWith('/node-groups/ng1')) return json({ nodegroup: { nodegroupName: 'ng1', remoteAccess: { ec2SshKey: 'k' } } });
    if (path.endsWith('/access-entries')) return json({ accessEntries: ['arn:aws:iam::111:role/admin'] });
    if (path.includes('/access-entries/') && path.endsWith('/access-policies')) {
      return json({ associatedAccessPolicies: [{ policyArn: 'arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy', accessScope: { type: 'cluster' } }] });
    }
    if (path.includes('/access-entries/')) return json({ accessEntry: { principalArn: 'arn:aws:iam::111:role/admin' } });
    return json({});
  };

  it('reads every page of clusters (previously 10) and enumerates children for each', async () => {
    fetchMock.mockImplementation(route());
    const out = await scanEks(ctx);
    expect(out.filter((r) => r.resourceTypeKey === 'eks_cluster').map((r) => r.resourceName)).toEqual(['a', 'b']);
    expect(out.filter((r) => r.resourceTypeKey === 'eks_nodegroup').map((r) => r.resourceId)).toEqual(['a/ng1', 'b/ng1']);
    expect(out.filter((r) => r.resourceTypeKey === 'eks_access_entry')).toHaveLength(2);
  });

  it('records authoritative version support, world-open endpoint, SSH exposure and cluster-admin entries', async () => {
    fetchMock.mockImplementation(route());
    const out = await scanEks(ctx);
    const cluster = out.find((r) => r.resourceName === 'a');
    expect(cluster?.metadata).toMatchObject({ publicEndpointOpenToWorld: true, versionSupportStatus: 'EXTENDED_SUPPORT', latestStandardSupportVersion: '1.33' });
    expect(out.find((r) => r.resourceId === 'a/ng1')?.metadata).toMatchObject({ sshOpenToInternet: true });
    expect(out.find((r) => r.resourceTypeKey === 'eks_access_entry')?.metadata).toMatchObject({ grantsClusterAdmin: true });
  });

  it('keeps an ARN identity for a cluster whose GetCluster failed', async () => {
    fetchMock.mockImplementation(route({ '/clusters/b': json({ message: 'boom' }, 500) }));
    const out = await scanEks(ctx);
    expect(out.find((r) => r.resourceName === 'b' && r.resourceTypeKey === 'eks_cluster')?.resourceId).toBe('arn:aws:eks:eu-west-1:111:cluster/b');
  });

  it('pure evidence helpers', () => {
    expect(clusterEvidence({ name: 'x', resourcesVpcConfig: { endpointPublicAccess: true, publicAccessCidrs: ['10.0.0.0/8'] } }, new Map(), '1.33').publicEndpointOpenToWorld).toBe(false);
    expect(nodegroupEvidence({ nodegroupName: 'n', remoteAccess: { ec2SshKey: 'k', sourceSecurityGroups: ['sg-1'] } })).toMatchObject({ sshRemoteAccessEnabled: true, sshOpenToInternet: false });
    expect(nodegroupEvidence(undefined)).toEqual({ detailsCollected: false });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe('EKS workloads (Kubernetes side)', () => {
  const CA = Buffer.from('-----BEGIN CERTIFICATE-----').toString('base64');
  const eksRoutes = (clusters: string[]) => (url: string) => {
    const u = new URL(url);
    if (u.hostname.startsWith('eks.')) {
      if (u.pathname === '/clusters') return json({ clusters });
      const name = u.pathname.split('/')[2];
      return json({ cluster: { name, status: 'ACTIVE', endpoint: `https://${name}.k8s`, certificateAuthority: { data: CA } } });
    }
    return undefined;
  };

  const deployment = {
    metadata: { name: 'api', namespace: 'prod' },
    spec: {
      template: {
        spec: {
          containers: [{
            name: 'app', image: 'repo/api:latest',
            args: ['--db-password=hunter2', '--url', 'postgres://u:pw@db/x', '--api-token', 'tok123'],
            env: [{ name: 'DB_PASSWORD', value: 'hunter2' }, { name: 'LOG_LEVEL', value: 'info' }, { name: 'API_KEY', valueFrom: { secretKeyRef: { name: 's', key: 'k' } } }],
            securityContext: { privileged: true },
          }],
          hostNetwork: true,
          volumes: [{ name: 'root', hostPath: { path: '/' } }],
        },
      },
    },
  };

  const k8sRoutes = (per: (host: string, path: string, url: URL) => Promise<Response> | undefined = () => undefined) => (url: string) => {
    const u = new URL(url);
    const custom = per(u.hostname, u.pathname, u);
    if (custom) return custom;
    switch (u.pathname) {
      case '/api/v1/pods': return json({ items: [{ metadata: { name: 'p1', namespace: 'prod' }, spec: { containers: [{ name: 'c', image: 'i' }] } }] });
      case '/apis/apps/v1/deployments': return json({ items: [deployment] });
      case '/api/v1/namespaces': return json({ items: Array.from({ length: 25 }, (_, i) => ({ metadata: { name: `ns${i}` } })) });
      case '/api/v1/resourcequotas': return json({ items: [{ metadata: { name: 'q', namespace: 'ns24' }, status: { hard: { pods: '10' } } }] });
      case '/api/v1/nodes': return json({ items: [] });
      case '/apis/apps/v1/replicasets': return json({ items: [] });
      default: return json({}, 404);
    }
  };

  const wire = (clusters: string[], per?: Parameters<typeof k8sRoutes>[0]) => {
    const eks = eksRoutes(clusters);
    const k8s = k8sRoutes(per);
    k8sFetchMock.mockImplementation((url: string) => eks(url) ?? k8s(url));
  };

  it('never persists literal env values or secret-looking arguments', async () => {
    wire(['c1']);
    const out = await scanEksWorkloads(ctx);
    const dep = out.find((r) => r.resourceTypeKey === 'eks_deployment');
    const text = JSON.stringify(dep);
    expect(text).not.toContain('hunter2');
    expect(text).not.toContain('tok123');
    expect(text).not.toContain(':pw@');
    expect(dep?.metadata).toMatchObject({ plaintextSecretEnvVars: ['app:DB_PASSWORD'] });
    expect(dep?.metadata).toMatchObject({ podSecurity: { privilegedContainers: ['app'], hostNetwork: true, hostPathVolumes: ['/'] } });
  });

  it('emits every namespace (previously the first 20) with quotas from one cluster-wide list', async () => {
    wire(['c1']);
    const ns = (await scanEksWorkloads(ctx)).filter((r) => r.resourceTypeKey === 'eks_namespace');
    expect(ns).toHaveLength(25);
    expect(ns.find((r) => r.resourceName === 'ns24')?.metadata).toMatchObject({ resourceQuotas: [{ name: 'q', hard: { pods: '10' } }] });
  });

  it('follows the Kubernetes continue token', async () => {
    wire(['c1'], (_h, path, u) => (path === '/api/v1/pods'
      ? (u.searchParams.get('continue') === 'k2'
        ? json({ items: [{ metadata: { name: 'p2', namespace: 'a' } }] })
        : json({ items: [{ metadata: { name: 'p1', namespace: 'a' } }], metadata: { continue: 'k2' } }))
      : undefined));
    const pods = (await scanEksWorkloads(ctx)).filter((r) => r.resourceTypeKey === 'eks_pod');
    expect(pods.map((p) => p.resourceName)).toEqual(['p1', 'p2']);
  });

  it('keeps a mapped cluster\'s data when another cluster is forbidden, and reports the denied one', async () => {
    const failures: Failure[] = [];
    wire(['ok', 'denied'], (host) => (host === 'denied.k8s' ? json({ kind: 'Status' }, 403) : undefined));
    const out = await scanEksWorkloads(withSink(failures));
    expect(out.some((r) => r.resourceId.startsWith('eu-west-1/ok/'))).toBe(true);
    expect(failures.some((f) => f.action === 'k8s:ListPods' && f.normalizedCode === 'PERMISSION_DENIED')).toBe(true);
  });

  it('throws the actionable message when EVERY cluster is forbidden', async () => {
    wire(['denied'], () => json({}, 401));
    let message = '';
    try { await scanEksWorkloads(ctx); } catch (err) { message = (err as Error).message; }
    expect(message).toContain('not mapped to Kubernetes RBAC');
  });

  it('a non-JSON body or network error on one cluster is reported, not thrown', async () => {
    const failures: Failure[] = [];
    wire(['bad', 'good'], (host) => (host === 'bad.k8s' ? Promise.resolve(new Response('<html>502</html>', { status: 502 })) : undefined));
    const out = await scanEksWorkloads(withSink(failures));
    expect(out.some((r) => r.resourceId.startsWith('eu-west-1/good/'))).toBe(true);
    expect(failures.some((f) => f.action === 'k8s:ListPods')).toBe(true);
  });

  it('uses one Agent per cluster and closes it', async () => {
    wire(['c1', 'c2']);
    await scanEksWorkloads(ctx);
    const agents = (globalThis as { __undiciAgents?: { closed: boolean; opts: { headersTimeout?: number } }[] }).__undiciAgents ?? [];
    expect(agents).toHaveLength(2);
    expect(agents.every((a) => a.closed && typeof a.opts.headersTimeout === 'number')).toBe(true);
  });

  it('a failed ListClusters is reported rather than read as "no clusters"', async () => {
    const failures: Failure[] = [];
    k8sFetchMock.mockImplementation(() => json({ message: 'x' }, 500));
    expect(await scanEksWorkloads(withSink(failures))).toEqual([]);
    expect(failures.some((f) => f.action === 'ListClusters')).toBe(true);
    expect(failures.some((f) => f.action === 'k8s:ListPods')).toBe(true);
  });

  it('re-mints the bearer token before the 60 s presign window closes', async () => {
    let now = 0;
    let n = 0;
    const get = tokenSource(async () => `t${++n}`, () => now, 45_000);
    expect(await get()).toBe('t1');
    now = 30_000;
    expect(await get()).toBe('t1');
    now = 46_000;
    expect(await get()).toBe('t2');
  });

  it('k8sListAll marks a mid-walk failure as incomplete', async () => {
    const r = await k8sListAll<unknown>(async (p) => (p.includes('continue')
      ? { ok: false, status: 410, body: null }
      : { ok: true, status: 200, body: { items: [1], metadata: { continue: 'x' } } }), '/api/v1/pods');
    expect(r).toMatchObject({ ok: true, complete: false, items: [1] });
  });

  it('helpers: redaction, secret env names, pod security, aws-auth parsing', () => {
    const c = redactContainer({ name: 'a', image: 'i', env: [{ name: 'X', value: 'v' }], command: ['sh', '-c', 'run --password=abc'] });
    expect(c.env).toEqual([{ name: 'X', hasLiteralValue: true }]);
    expect(REDACTED).toBe('[REDACTED]');
    expect(plaintextSecretEnvNames([{ name: 'a', image: 'i', env: [{ name: 'AWS_SECRET_ACCESS_KEY', value: 'x' }, { name: 'PORT', value: '80' }] }])).toEqual(['a:AWS_SECRET_ACCESS_KEY']);
    const ps = podSecurityEvidence({ securityContext: { runAsNonRoot: true }, containers: [{ name: 'a', image: 'repo/x@sha256:1', securityContext: { allowPrivilegeEscalation: false } }] });
    expect(ps).toMatchObject({ containersMayRunAsRoot: [], containersAllowingPrivilegeEscalation: [], automountServiceAccountToken: true, imagesWithoutDigestOrWithLatest: [] });
    expect(parseAuthMapYaml('- rolearn: arn:aws:iam::1:role/a\n  username: a\n  groups:\n  - system:masters\n- rolearn: arn:aws:iam::1:role/b\n  groups: [view, edit]\n'))
      .toEqual([{ arn: 'arn:aws:iam::1:role/a', username: 'a', groups: ['system:masters'] }, { arn: 'arn:aws:iam::1:role/b', groups: ['view', 'edit'] }]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe('EC2 CPU metrics', () => {
  const instances = [{ dbId: 'db1', awsInstanceId: 'i-1' }, { dbId: 'db2', awsInstanceId: 'i-2' }];
  const result = (id: string, ts: string[], vals: string[], status = 'Complete') =>
    `<member><Id>${id}</Id><Label>CPUUtilization</Label><Timestamps>${ts.map((t) => `<member>${t}</member>`).join('')}</Timestamps>` +
    `<Values>${vals.map((v) => `<member>${v}</member>`).join('')}</Values><StatusCode>${status}</StatusCode></member>`;

  it('uses ONE GetMetricData call for many instances (previously one sequential call each)', async () => {
    callQueryApiMock.mockImplementation((_c: unknown, req: { action: string }) => {
      expect(req.action).toBe('GetMetricData');
      return ok(`<GetMetricDataResponse><GetMetricDataResult><MetricDataResults>${
        result('a0', ['2026-09-20T00:00:00Z'], ['12.5'])}${result('m0', ['2026-09-20T00:00:00Z'], ['80'])}${
        result('a1', ['2026-09-20T00:00:00Z'], ['3'])}${result('m1', [], [])}</MetricDataResults></GetMetricDataResult></GetMetricDataResponse>`);
    });
    const out = await scanEc2CpuMetrics(creds, 'eu-west-1', instances);
    expect(callQueryApiMock.mock.calls).toHaveLength(1);
    expect(out.map((m) => [m.resourceDbId, m.metricName, m.value, m.ts])).toEqual([
      ['db1', 'CPUUtilization', 12.5, '2026-09-20T00:00:00Z'],
      ['db1', 'CPUUtilizationMaximum', 80, '2026-09-20T00:00:00Z'],
      ['db2', 'CPUUtilization', 3, '2026-09-20T00:00:00Z'],
    ]);
  });

  it('falls back to per-instance GetMetricStatistics when GetMetricData fails', async () => {
    callQueryApiMock.mockImplementation((_c: unknown, req: { action: string }) => (req.action === 'GetMetricData'
      ? Promise.resolve({ ok: false, status: 400, body: '', errorCode: 'AccessDenied' })
      : ok('<Datapoints><member><Timestamp>2026-09-20T00:00:00Z</Timestamp><Average>5</Average><Maximum>9</Maximum><Unit>Percent</Unit></member></Datapoints>')));
    const out = await scanEc2CpuMetrics(creds, 'eu-west-1', instances);
    expect(out).toHaveLength(4);
  });

  it('floors the window start to UTC midnight so timestamps are stable run to run', () => {
    const { start } = metricWindow(new Date('2026-09-23T15:42:10Z'));
    expect(start.toISOString()).toBe('2026-09-09T00:00:00.000Z');
  });

  it('encodes queries and parses parallel Timestamps/Values with the NextToken outside results', () => {
    const p = metricDataParams([{ dbId: 'd', awsInstanceId: 'i-9' }], new Date(0), new Date(1000));
    expect(p['MetricDataQueries.member.1.Id']).toBe('a0');
    expect(p['MetricDataQueries.member.2.MetricStat.Stat']).toBe('Maximum');
    expect(p['MetricDataQueries.member.2.MetricStat.Metric.Dimensions.member.1.Value']).toBe('i-9');
    const parsed = parseMetricDataResults(`<MetricDataResults>${result('a0', ['t1', 't2'], ['1', '2'])}</MetricDataResults><NextToken>nx</NextToken>`);
    expect(parsed).toEqual({ series: [{ id: 'a0', statusCode: 'Complete', points: [{ ts: 't1', value: 1 }, { ts: 't2', value: 2 }] }], nextToken: 'nx' });
  });
});
