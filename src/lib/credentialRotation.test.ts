import { describe, it, expect, vi } from 'vitest';
import { validateCandidate } from './credentialRotation';
import type { Env } from '../env';

/**
 * AWS-P0-03: the credential dialog saved new keys FIRST, reset the connection
 * to pending, and relied on a later validation. A typo therefore took a
 * working connection down, and the credential that worked was already gone.
 */
vi.mock('./permissionChecks', () => ({
  checkCallerIdentity: vi.fn(),
}));
// Static import: vitest hoists vi.mock above it, so the module is already
// mocked. A top-level `await import` works at runtime but tsc rejects it
// under this project's module target.
import { checkCallerIdentity } from './permissionChecks';
const env = { ENCRYPTION_KEY: 'k' } as unknown as Env;
const creds = { accessKeyId: 'AKIAEXAMPLE', secretAccessKey: 'secret-value-not-logged' };

describe('validateCandidate', () => {
  it('rejects credentials AWS will not authenticate', async () => {
    vi.mocked(checkCallerIdentity).mockResolvedValue({
      result: { service: 'sts', label: 'STS', status: 'denied', detail: 'InvalidClientTokenId', verified: true },
      identity: null,
    });
    const r = await validateCandidate(env, creds, '111111111111');
    expect(r.ok).toBe(false);
    expect(r.code).toBe('candidate_authentication_failed');
  });

  it('rejects a credential for a DIFFERENT AWS account', async () => {
    // These authenticate perfectly well. Accepting them would silently
    // repoint the connection at another estate while every screen kept the
    // original account's name and history.
    vi.mocked(checkCallerIdentity).mockResolvedValue({
      result: { service: 'sts', label: 'STS', status: 'granted', detail: 'ok', verified: true },
      identity: { arn: 'arn:aws:iam::999999999999:user/x', accountId: '999999999999', userId: 'AID' },
    });
    const r = await validateCandidate(env, creds, '111111111111');
    expect(r.ok).toBe(false);
    expect(r.code).toBe('candidate_account_mismatch');
    expect(r.message).toContain('999999999999');
  });

  it('accepts a credential for the right account', async () => {
    vi.mocked(checkCallerIdentity).mockResolvedValue({
      result: { service: 'sts', label: 'STS', status: 'granted', detail: 'ok', verified: true },
      identity: { arn: 'arn:aws:iam::111111111111:user/ok', accountId: '111111111111', userId: 'AID' },
    });
    const r = await validateCandidate(env, creds, '111111111111');
    expect(r.ok).toBe(true);
    expect(r.identityArn).toContain('111111111111');
  });

  it('never echoes the secret in a failure message', async () => {
    vi.mocked(checkCallerIdentity).mockResolvedValue({
      result: { service: 'sts', label: 'STS', status: 'denied', detail: 'SignatureDoesNotMatch', verified: true },
      identity: null,
    });
    const r = await validateCandidate(env, creds, '111111111111');
    expect(JSON.stringify(r)).not.toContain('secret-value-not-logged');
  });
});
