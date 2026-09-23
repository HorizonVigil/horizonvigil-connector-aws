import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * IAM scanner behaviour tests (iamFailureSemantics.test.ts pins the source;
 * these drive the scanner end to end through a mocked callQueryApi).
 */
const callQueryApiMock = vi.fn();
vi.mock('../awsApi', async (importOriginal: () => Promise<Record<string, unknown>>) => ({
  ...(await importOriginal()),
  callQueryApi: (...args: unknown[]) => callQueryApiMock(...args),
}));

import { nullIfNA, parseAccountSummary, parsePasswordPolicy, scanIam } from './iam';
import type { ScannedResource } from './types';

type Req = { action: string; params?: Record<string, string> };
type Diag = { status: string; operations: { action: string; status: string }[] };

const ACCOUNT = '111122223333';
const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ctx = { creds, region: 'us-east-1' };
const ok = (body: string) => Promise.resolve({ ok: true, status: 200, body });
const fail = (status: number, errorCode: string) => Promise.resolve({ ok: false, status, body: '', errorCode, normalizedCode: errorCode === 'AccessDenied' ? 'PERMISSION_DENIED' : undefined });

const trust = (statement: unknown) => encodeURIComponent(JSON.stringify({ Version: '2012-10-17', Statement: [statement] }));

const role = (id: string, name: string, path: string, trustDoc: string) =>
  `<member><RoleId>${id}</RoleId><RoleName>${name}</RoleName><Path>${path}</Path>` +
  `<Arn>arn:aws:iam::${ACCOUNT}:role${path}${name}</Arn><AssumeRolePolicyDocument>${trustDoc}</AssumeRolePolicyDocument></member>`;

const REPORT_CSV = [
  'user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date',
  `<root_account>,arn:aws:iam::${ACCOUNT}:root,2020-01-01T00:00:00+00:00,not_supported,2026-09-01T00:00:00+00:00,not_supported,not_supported,false,true,2020-01-01T00:00:00+00:00,2026-09-01T00:00:00+00:00,false,N/A,N/A`,
  `alice,arn:aws:iam::${ACCOUNT}:user/alice,2024-01-01T00:00:00+00:00,true,no_information,2024-01-01T00:00:00+00:00,N/A,true,false,N/A,N/A,false,N/A,N/A`,
].join('\n');

function serve(overrides: Record<string, (req: Req) => Promise<unknown>> = {}) {
  let reportPolls = 0;
  const base: Record<string, (req: Req) => Promise<unknown>> = {
    ListUsers: () => ok(`<ListUsersResponse><ListUsersResult><IsTruncated>false</IsTruncated><Users><member><UserId>AIDA1</UserId><UserName>alice</UserName><Arn>arn:aws:iam::${ACCOUNT}:user/alice</Arn></member></Users></ListUsersResult></ListUsersResponse>`),
    ListRoles: () => ok(`<ListRolesResponse><ListRolesResult><IsTruncated>false</IsTruncated><Roles>` +
      role('AROA1', 'open-role', '/', trust({ Effect: 'Allow', Principal: { AWS: '*' }, Action: 'sts:AssumeRole' })) +
      role('AROA2', 'vendor-role', '/', trust({ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::444455556666:root' }, Action: 'sts:AssumeRole' })) +
      role('AROA3', 'AWSServiceRoleForSupport', '/aws-service-role/support.amazonaws.com/', trust({ Effect: 'Allow', Principal: { Service: 'support.amazonaws.com' } })) +
      `</Roles></ListRolesResult></ListRolesResponse>`),
    GenerateCredentialReport: () => ok('<GenerateCredentialReportResponse><GenerateCredentialReportResult><State>STARTED</State></GenerateCredentialReportResult></GenerateCredentialReportResponse>'),
    // Not ready on the first poll, ready on the second -- the normal shape.
    GetCredentialReport: () => (reportPolls++ === 0
      ? fail(410, 'ReportInProgress')
      : ok(`<GetCredentialReportResponse><GetCredentialReportResult><Content>${btoa(REPORT_CSV)}</Content><GeneratedTime>2026-09-23T00:00:00Z</GeneratedTime></GetCredentialReportResult></GetCredentialReportResponse>`)),
    GetAccountSummary: () => ok('<GetAccountSummaryResponse><GetAccountSummaryResult><SummaryMap>' +
      '<entry><key>AccountMFAEnabled</key><value>0</value></entry><entry><key>AccountAccessKeysPresent</key><value>1</value></entry>' +
      '</SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>'),
    GetAccountPasswordPolicy: () => fail(404, 'NoSuchEntity'),
  };
  const handlers = { ...base, ...overrides };
  callQueryApiMock.mockImplementation((_c: unknown, req: Req) => {
    const h = handlers[req.action];
    return h ? h(req) : ok(`<${req.action}Response/>`);
  });
}

const byName = (out: ScannedResource[], name: string) => out.find((r) => r.resourceName === name);
const report = (out: ScannedResource[]) => out.find((r) => r.resourceTypeKey === 'iam_credential_report');
const diagnostics = (out: ScannedResource[]) => (out[0].metadata as { iamScanDiagnostics: Diag }).iamScanDiagnostics;

beforeEach(() => { callQueryApiMock.mockReset(); });

describe('IAM role trust evidence', () => {
  it('flags a role anyone on AWS can assume', async () => {
    serve();
    const r = byName(await scanIam(ctx), 'open-role');
    expect(r?.metadata).toMatchObject({ trustAllowsAnonymous: true, trustPolicy: { parsed: true } });
  });

  it('records the external account a role trusts, and whether it demands an ExternalId', async () => {
    serve();
    const r = byName(await scanIam(ctx), 'vendor-role');
    expect(r?.metadata).toMatchObject({ trustExternalAccountIds: ['444455556666'], trustRequiresExternalId: false });
  });

  it('skips privilege analysis for AWS-owned service-linked roles, and says so', async () => {
    serve();
    const r = byName(await scanIam(ctx), 'AWSServiceRoleForSupport');
    expect(r?.metadata).toMatchObject({ serviceLinked: true, privilegeAnalysisStatus: 'skipped', privilegeAnalysisSkipReason: 'service_linked_role' });
  });
});

describe('IAM account-level evidence', () => {
  it('reports the root user separately from IAM users', async () => {
    serve();
    const row = report(await scanIam(ctx));
    expect(row?.metadata).toMatchObject({
      status: 'available', totalUsers: 1,
      root: { mfaActive: false, accessKey1Active: true, accessKey2Active: false },
    });
  }, 15000);

  it('records "no password policy" as a real answer, not missing evidence', async () => {
    serve();
    const row = report(await scanIam(ctx));
    expect(row?.metadata).toMatchObject({ passwordPolicy: { collected: true, configured: false } });
  }, 15000);

  it('records root MFA and root access keys from the account summary', async () => {
    serve();
    const row = report(await scanIam(ctx));
    expect(row?.metadata).toMatchObject({ accountSummary: { collected: true, accountMfaEnabled: false, accountAccessKeysPresent: true } });
  }, 15000);

  it('merges per-user MFA from the credential report', async () => {
    serve();
    const alice = byName(await scanIam(ctx), 'alice');
    expect(alice?.metadata).toMatchObject({ mfaActive: true, passwordEnabled: true, credentialReportPasswordLastUsed: null });
  }, 15000);

  it('does not mark a healthy scan partial just because the report needed a second poll', async () => {
    serve();
    const d = diagnostics(await scanIam(ctx));
    expect(d.operations.some((o) => o.action === 'GetCredentialReport')).toBe(false);
    expect(d.status).toBe('success');
  }, 15000);

  it('still writes the account row when the report never becomes ready', async () => {
    serve({ GetCredentialReport: () => fail(410, 'ReportInProgress') });
    const row = report(await scanIam(ctx));
    expect(row?.metadata).toMatchObject({ status: 'not_ready', totalUsers: null, root: null, passwordPolicy: { configured: false } });
  }, 15000);
});

describe('IAM fail-closed behaviour', () => {
  it('throws when a REQUIRED list call is denied, instead of publishing zero users', async () => {
    serve({ ListUsers: () => fail(403, 'AccessDenied') });
    let error: unknown = null;
    try {
      await scanIam(ctx);
    } catch (err) {
      error = err;
    }
    expect(String(error)).toContain('IAM ListUsers failed');
  });
});

describe('IAM parsing helpers', () => {
  it('normalizes every credential-report sentinel to null', () => {
    expect(nullIfNA('N/A')).toBeNull();
    expect(nullIfNA('not_supported')).toBeNull();
    expect(nullIfNA('no_information')).toBeNull();
    expect(nullIfNA('2026-01-01T00:00:00+00:00')).toBe('2026-01-01T00:00:00+00:00');
  });

  it('parses a password policy', () => {
    const p = parsePasswordPolicy('<GetAccountPasswordPolicyResult><PasswordPolicy><MinimumPasswordLength>14</MinimumPasswordLength><RequireSymbols>true</RequireSymbols><PasswordReusePrevention>24</PasswordReusePrevention></PasswordPolicy></GetAccountPasswordPolicyResult>');
    expect(p).toMatchObject({ collected: true, configured: true, minimumPasswordLength: 14, requireSymbols: true, passwordReusePrevention: 24, requireNumbers: null });
  });

  it('reports an unreadable account summary as not collected', () => {
    expect(parseAccountSummary(null).collected).toBe(false);
    expect(parseAccountSummary('<x/>').collected).toBe(false);
  });
});