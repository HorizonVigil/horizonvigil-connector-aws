import type { Env } from '../env';
import { assumeConnectionRole } from './assumeRole';
import { checkAccountBinding } from './accountBinding';
import { checkCallerIdentity } from './permissionChecks';
import type { AwsCreds } from './awsApi';

export type ConnectionCandidate =
  | { method: 'access_key'; accountId: string; accessKeyId: string; secretAccessKey: string }
  | { method: 'cross_account_role'; accountId: string; roleArn: string; externalId: string };

export type ConnectionValidation =
  | { ok: true; accountId: string; arn: string | null }
  | { ok: false; status: 400 | 503; code: string; message: string };

/**
 * Proves that a proposed connection authenticates to the account it claims
 * before any credential material or connection row is persisted.
 */
export async function validateConnectionCandidate(env: Env, candidate: ConnectionCandidate): Promise<ConnectionValidation> {
  let creds: AwsCreds;
  if (candidate.method === 'access_key') {
    creds = { accessKeyId: candidate.accessKeyId, secretAccessKey: candidate.secretAccessKey };
  } else {
    const assumed = await assumeConnectionRole(
      { accessKeyId: env.PLATFORM_AWS_ACCESS_KEY_ID, secretAccessKey: env.PLATFORM_AWS_SECRET_ACCESS_KEY },
      candidate.roleArn,
      candidate.externalId,
    );
    if (!assumed.ok || !assumed.credentials) {
      const platformMissing = !env.PLATFORM_AWS_ACCESS_KEY_ID || !env.PLATFORM_AWS_SECRET_ACCESS_KEY;
      return {
        ok: false,
        status: platformMissing ? 503 : 400,
        code: platformMissing ? 'assume_role_platform_unavailable' : 'assume_role_failed',
        message: assumed.reason ?? 'HorizonVigil could not assume the supplied role.',
      };
    }
    creds = assumed.credentials;
  }

  const identity = await checkCallerIdentity(creds);
  if (identity.result.status !== 'granted' || !identity.identity) {
    return { ok: false, status: 400, code: 'aws_credentials_invalid', message: identity.result.detail };
  }
  const binding = checkAccountBinding(candidate.accountId, identity.identity.accountId);
  if (binding.state === 'mismatched') {
    return { ok: false, status: 400, code: 'aws_account_mismatch', message: binding.message };
  }
  if (binding.state === 'unverified') {
    return { ok: false, status: 400, code: 'aws_account_unverified', message: 'AWS authenticated the connection but did not return an account identifier.' };
  }
  return { ok: true, accountId: binding.accountId, arn: identity.identity.arn };
}
