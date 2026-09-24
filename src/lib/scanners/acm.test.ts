import { beforeEach, describe, expect, it, vi } from 'vitest';

const callJsonApiMock = vi.fn();
vi.mock('../awsApi', async (importOriginal: () => Promise<Record<string, unknown>>) => ({
  ...(await importOriginal()),
  callJsonApi: (...args: unknown[]) => callJsonApiMock(...args),
}));

import { ALL_KEY_TYPES, certificateMetadata, scanAcm, toIsoTimestamp } from './acm';

type Req = { target: string; body: Record<string, unknown> };

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ctx = { creds, region: 'us-east-1' };
const ok = (body: unknown) => Promise.resolve({ ok: true, status: 200, body });

const cert = (arn: string, extra: Record<string, unknown> = {}) => ({ CertificateArn: arn, DomainName: 'example.com', Status: 'ISSUED', ...extra });

beforeEach(() => { callJsonApiMock.mockReset(); });

describe('scanAcm', () => {
  it('asks for EVERY key algorithm, not the RSA-only default', async () => {
    callJsonApiMock.mockImplementation(() => ok({ CertificateSummaryList: [] }));
    await scanAcm(ctx);
    const body = (callJsonApiMock.mock.calls[0][1] as Req).body as { Includes?: { keyTypes?: string[] } };
    expect(body.Includes?.keyTypes).toEqual([...ALL_KEY_TYPES]);
    expect(ALL_KEY_TYPES).toContain('EC_prime256v1');
  });

  it('reads every page', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => req.body.NextToken === 't2'
      ? ok({ CertificateSummaryList: [cert('arn:2')] })
      : ok({ CertificateSummaryList: [cert('arn:1')], NextToken: 't2' }));
    expect((await scanAcm(ctx)).map((r) => r.resourceId)).toEqual(['arn:1', 'arn:2']);
  });

  it('drops a summary without an ARN and de-duplicates repeats', async () => {
    callJsonApiMock.mockImplementation(() => ok({ CertificateSummaryList: [cert(''), cert('arn:1'), cert('arn:1')] }));
    expect((await scanAcm(ctx)).map((r) => r.resourceId)).toEqual(['arn:1']);
  });
});

describe('certificate evidence', () => {
  it('normalizes epoch-second dates but keeps the raw notAfter for existing consumers', () => {
    const md = certificateMetadata(cert('arn:1', { NotAfter: 1790121600 }));
    expect(md.notAfter).toBe(1790121600);
    expect(md.notAfterIso).toBe('2026-09-23T00:00:00.000Z');
    expect(toIsoTimestamp(undefined)).toBeNull();
  });

  it('records key algorithm, renewal eligibility and wildcard scope', () => {
    const md = certificateMetadata(cert('arn:1', { KeyAlgorithm: 'EC-prime256v1', RenewalEligibility: 'INELIGIBLE', SubjectAlternativeNameSummaries: ['*.example.com'] }));
    expect(md).toMatchObject({ keyAlgorithm: 'EC-prime256v1', renewalEligibility: 'INELIGIBLE', isWildcard: true });
  });

  it('stores no value that changes every day on its own', () => {
    const md = certificateMetadata(cert('arn:1', { NotAfter: 1790121600 })) as Record<string, unknown>;
    expect(Object.keys(md).some((k) => /days/i.test(k))).toBe(false);
  });
});