import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Shared REST/JSON-RPC plumbing and the JSON-RPC scanners built on it:
 * ACM PCA, Athena, App Runner, Cost Explorer, Budgets, AWS Config findings.
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

import { fetchJson, toIso, walkPages } from './restJson';
import { scanAcmPca } from './acmpca';
import { scanAthena } from './athena';
import { scanAppRunner } from './apprunner';
import { scanCostExplorer } from './ce';
import { scanBudgets } from './budgets';
import { scanAwsConfigFindings } from './awsConfigFindings';

type Req = { target: string; body: Record<string, unknown> };
type Failure = { action?: string; normalizedCode?: string };

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ok = (body: unknown) => Promise.resolve({ ok: true, status: 200, body });
const denied = () => Promise.resolve({ ok: false, status: 400, body: null, errorCode: 'AccessDeniedException' });
const op = (req: Req) => req.target.split('.').pop();

/** Two pages of `key`, split on NextToken (or a custom token name). */
const twoPages = (req: Req, key: string, first: unknown[], second: unknown[], token = 'NextToken') =>
  req.body[token] === 't2' ? ok({ [key]: second }) : ok({ [key]: first, [token]: 't2' });

beforeEach(() => { callJsonApiMock.mockReset(); fetchMock.mockReset(); });

describe('restJson helpers', () => {
  it('fetchJson never throws on an unparseable body', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(new Response('<html>oops', { status: 200 })));
    const { createAwsClient } = await import('../awsApi');
    const res = await fetchJson(createAwsClient(creds, 's', 'us-east-1'), 'https://x/');
    expect(res.ok).toBe(false);
    expect(String(res.error)).toContain('unparseable JSON');
  });

  it('walkPages stops on a repeated token and says so', async () => {
    const walk = await walkPages<number>(() => Promise.resolve({ ok: true, status: 200, body: { items: [1], next: 'same' } }), (b) => b.items, (b) => b.next);
    expect(walk).toMatchObject({ complete: false, pages: 2, error: 'repeated continuation token' });
    expect(walk.items).toEqual([1, 1]);
  });

  it('walkPages marks a first-page failure distinctly from a later one', async () => {
    const walk = await walkPages(() => Promise.resolve({ ok: false, status: 403, body: null }), (b) => b.items, (b) => b.next);
    expect(walk).toMatchObject({ complete: false, firstPageFailed: true, status: 403 });
  });

  it('toIso converts JSON 1.1 epoch seconds and passes ISO strings through', () => {
    expect(toIso(1790121600)).toBe('2026-09-23T00:00:00.000Z');
    expect(toIso('2026-09-23T00:00:00Z')).toBe('2026-09-23T00:00:00Z');
    expect(toIso(undefined)).toBeNull();
  });
});

describe('JSON-RPC scanners paginate and report', () => {
  const ctx = (failures?: Failure[]) => ({ creds: failures ? { ...creds, onCallFailure: (f: Failure) => failures.push(f) } : creds, region: 'eu-west-1' });

  it('ACM PCA reads every page and records revocation evidence', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => twoPages(req, 'CertificateAuthorities',
      [{ Arn: 'arn:ca:1', Status: 'ACTIVE', RevocationConfiguration: { CrlConfiguration: { Enabled: true, S3ObjectAcl: 'PUBLIC_READ' } } }],
      [{ Arn: 'arn:ca:2', Status: 'ACTIVE' }]));
    const out = await scanAcmPca(ctx());
    expect(out.map((r) => r.resourceId)).toEqual(['arn:ca:1', 'arn:ca:2']);
    expect(out[0].metadata).toMatchObject({ crlEnabled: true, crlS3ObjectAcl: 'PUBLIC_READ', ocspEnabled: false });
  });

  it('ACM PCA reports a failed list instead of returning a silent []', async () => {
    const failures: Failure[] = [];
    callJsonApiMock.mockImplementation(() => denied());
    expect(await scanAcmPca(ctx(failures))).toEqual([]);
    expect(failures.some((f) => f.action === 'ListCertificateAuthorities')).toBe(true);
  });

  it('Athena reads every page and records workgroup encryption', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'ListWorkGroups') return twoPages(req, 'WorkGroups', [{ Name: 'primary' }], [{ Name: 'analytics' }]);
      if (op(req) === 'ListDataCatalogs') return ok({ DataCatalogsSummary: [{ CatalogName: 'AwsDataCatalog', Type: 'GLUE' }] });
      if (op(req) === 'GetWorkGroup') {
        return ok({ WorkGroup: { Configuration: req.body.WorkGroup === 'primary'
          ? { ResultConfiguration: { EncryptionConfiguration: { EncryptionOption: 'SSE_KMS' } }, EnforceWorkGroupConfiguration: true }
          : { ResultConfiguration: {} } } });
      }
      return denied();
    });
    const out = await scanAthena(ctx());
    const wg = out.filter((r) => r.resourceTypeKey === 'athena_workgroup');
    expect(wg.map((r) => r.resourceId)).toEqual(['primary', 'analytics']);
    expect(wg[0].metadata).toMatchObject({ resultsEncrypted: true, enforceWorkGroupConfiguration: true });
    expect(wg[1].metadata).toMatchObject({ resultsEncrypted: false });
  });

  it('App Runner records public ingress and reads every page', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'ListServices') return twoPages(req, 'ServiceSummaryList', [{ ServiceArn: 'arn:svc:1', ServiceName: 'a' }], [{ ServiceArn: 'arn:svc:2', ServiceName: 'b' }]);
      if (op(req) === 'ListConnections') return ok({ ConnectionSummaryList: [] });
      if (op(req) === 'DescribeService') return ok({ Service: { NetworkConfiguration: { IngressConfiguration: { IsPubliclyAccessible: true } } } });
      return denied();
    });
    const out = await scanAppRunner(ctx());
    expect(out.map((r) => r.resourceId)).toEqual(['arn:svc:1', 'arn:svc:2']);
    expect(out[0].metadata).toMatchObject({ detailsCollected: true, publiclyAccessible: true, customerManagedKms: false });
  });

  it('Cost Explorer follows NextPageToken for anomaly monitors', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'ListCostCategoryDefinitions') return ok({ CostCategoryReferences: [] });
      return twoPages(req, 'AnomalyMonitors', [{ MonitorArn: 'arn:m:1', MonitorName: 'a' }], [{ MonitorArn: 'arn:m:2', MonitorName: 'b' }], 'NextPageToken');
    });
    const out = await scanCostExplorer(ctx());
    expect(out.map((r) => r.resourceId)).toEqual(['arn:m:1', 'arn:m:2']);
  });

  it('Budgets reports an unresolved account id rather than returning a silent []', async () => {
    const failures: Failure[] = [];
    fetchMock.mockImplementation(() => Promise.resolve(new Response('<Error/>', { status: 403 })));
    expect(await scanBudgets(ctx(failures))).toEqual([]);
    expect(failures.some((f) => f.action === 'DescribeBudgets')).toBe(true);
  });

  it('Budgets keeps the old strings and adds comparable numbers', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(new Response('<GetCallerIdentityResponse><GetCallerIdentityResult><Account>111122223333</Account></GetCallerIdentityResult></GetCallerIdentityResponse>', { status: 200 })));
    callJsonApiMock.mockImplementation(() => ok({ Budgets: [{ BudgetName: 'monthly', BudgetLimit: { Amount: '100.0', Unit: 'USD' }, CalculatedSpend: { ForecastedSpend: { Amount: '150.0', Unit: 'USD' } } }] }));
    const [b] = await scanBudgets(ctx());
    expect(b.resourceId).toBe('111122223333:monthly');
    expect(b.metadata).toMatchObject({ limit: '100.0 USD', limitAmount: 100, forecastedSpendAmount: 150, forecastExceedsLimit: true });
  });

  it('AWS Config findings carry an ISO discoveredAt, not an epoch number', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'DescribeComplianceByConfigRule') return ok({ ComplianceByConfigRules: [{ ConfigRuleName: 'restricted-ssh', Compliance: { ComplianceType: 'NON_COMPLIANT' } }] });
      return ok({ EvaluationResults: [{ EvaluationResultIdentifier: { EvaluationResultQualifier: { ConfigRuleName: 'restricted-ssh', ResourceType: 'AWS::EC2::SecurityGroup', ResourceId: 'sg-1' } }, ResultRecordedTime: 1790121600 }] });
    });
    const [f] = await scanAwsConfigFindings(ctx());
    expect(f.discoveredAt).toBe('2026-09-23T00:00:00.000Z');
    expect(f.awsFindingId).toBe('restricted-ssh/AWS::EC2::SecurityGroup/sg-1');
  });

  it('AWS Config reads every page of non-compliant rules', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'DescribeComplianceByConfigRule') {
        return twoPages(req, 'ComplianceByConfigRules',
          [{ ConfigRuleName: 'r1', Compliance: { ComplianceType: 'NON_COMPLIANT' } }],
          [{ ConfigRuleName: 'r2', Compliance: { ComplianceType: 'NON_COMPLIANT' } }]);
      }
      const rule = req.body.ConfigRuleName as string;
      return ok({ EvaluationResults: [{ EvaluationResultIdentifier: { EvaluationResultQualifier: { ConfigRuleName: rule, ResourceType: 'AWS::S3::Bucket', ResourceId: `b-${rule}` } } }] });
    });
    const out = await scanAwsConfigFindings(ctx());
    expect(out.map((f) => f.resourceArn).sort()).toEqual(['b-r1', 'b-r2']);
  });
});