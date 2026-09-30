import { afterEach, describe, expect, it, vi } from 'vitest';
import { validateConnectionCandidate } from './connectionValidation';

const env = {
  SUPABASE_URL: 'https://example.supabase.co', SUPABASE_ANON_KEY: 'anon',
  ALLOWED_ORIGIN: 'https://horizonvigil.com', DB_SCHEMA: 'public', ENCRYPTION_KEY: 'key',
};

afterEach(() => vi.restoreAllMocks());

describe('connection admission validation', () => {
  it('accepts access keys only when STS proves the claimed account', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      '<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::604179600483:user/test</Arn><Account>604179600483</Account><UserId>u</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>',
      { status: 200 },
    )));
    await expect(validateConnectionCandidate(env, {
      method: 'access_key', accountId: '604179600483', accessKeyId: 'AKIAEXAMPLE', secretAccessKey: 'secret',
    })).resolves.toMatchObject({ ok: true, accountId: '604179600483' });
  });

  it('rejects valid credentials for a different account', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      '<GetCallerIdentityResponse><GetCallerIdentityResult><Account>111122223333</Account></GetCallerIdentityResult></GetCallerIdentityResponse>',
      { status: 200 },
    )));
    await expect(validateConnectionCandidate(env, {
      method: 'access_key', accountId: '604179600483', accessKeyId: 'AKIAEXAMPLE', secretAccessKey: 'secret',
    })).resolves.toMatchObject({ ok: false, code: 'aws_account_mismatch' });
  });

  /**
   * 503 is for OUR infrastructure being unconfigured — no Google metadata
   * server to mint a workload identity token AND no platform AWS key. The
   * customer can do nothing about it, so it must not be reported as their
   * mistake.
   *
   * `fetchImpl` is injected rather than relying on a global stub: the
   * metadata probe is the first network call this path makes, and leaving it
   * to whatever a previous test stubbed made the outcome depend on test order.
   */
  // A FACTORY, not a shared constant: afterEach(vi.restoreAllMocks) strips the
  // implementation off a vi.fn() created at describe scope, so a shared mock
  // silently starts returning undefined for every test after the first.
  const noMetadata = () => ({ fetchImpl: vi.fn().mockRejectedValue(new Error('ENOTFOUND metadata.google.internal')) as unknown as typeof fetch });

  it('fails closed with 503 when neither assume-role mechanism is available', async () => {
    await expect(validateConnectionCandidate(env, {
      method: 'cross_account_role', accountId: '604179600483',
      roleArn: 'arn:aws:iam::604179600483:role/HorizonVigilRead', externalId: 'external',
    }, noMetadata())).resolves.toMatchObject({ ok: false, status: 503, code: 'assume_role_platform_unavailable' });
  });

  /**
   * The distinction that matters on Cloud Run, where the metadata server
   * always answers: a trust policy that does not match is the CUSTOMER's to
   * fix, so it is a 400 naming the trust policy — not a 503 that reads as
   * "HorizonVigil is down".
   */
  it('reports a refused role assumption as a 400 against the trust policy, not a 503', async () => {
    const onGoogle = {
      fetchImpl: vi.fn(async (input: RequestInfo | URL) => {
        if (String(input).includes('metadata.google.internal')) {
          return new Response('eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig', { status: 200 });
        }
        return new Response(
          '<ErrorResponse><Error><Code>AccessDenied</Code><Message>Not authorized</Message></Error></ErrorResponse>',
          { status: 403 },
        );
      }) as unknown as typeof fetch,
    };

    const result = await validateConnectionCandidate(env, {
      method: 'cross_account_role', accountId: '604179600483',
      roleArn: 'arn:aws:iam::604179600483:role/HorizonVigilRead', externalId: 'external',
    }, onGoogle);

    expect(result).toMatchObject({ ok: false, status: 400, code: 'assume_role_failed' });
    expect('message' in result && result.message).toMatch(/trust policy/i);
  });
});
