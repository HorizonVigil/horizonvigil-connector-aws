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

  it('fails closed when the platform identity needed for AssumeRole is unavailable', async () => {
    await expect(validateConnectionCandidate(env, {
      method: 'cross_account_role', accountId: '604179600483',
      roleArn: 'arn:aws:iam::604179600483:role/HorizonVigilRead', externalId: 'external',
    })).resolves.toMatchObject({ ok: false, status: 503, code: 'assume_role_platform_unavailable' });
  });
});
