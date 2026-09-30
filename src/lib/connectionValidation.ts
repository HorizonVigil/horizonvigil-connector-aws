import type { Env } from '../env';
import { assumeConnectionRole } from './assumeRole';
import type { WebIdentityDeps } from './webIdentity';
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
export async function validateConnectionCandidate(
  env: Env,
  candidate: ConnectionCandidate,
  deps: WebIdentityDeps = {},
): Promise<ConnectionValidation> {
  let creds: AwsCreds;
  if (candidate.method === 'access_key') {
    creds = { accessKeyId: candidate.accessKeyId, secretAccessKey: candidate.secretAccessKey };
  } else {
    const assumed = await assumeConnectionRole(
      { accessKeyId: env.PLATFORM_AWS_ACCESS_KEY_ID, secretAccessKey: env.PLATFORM_AWS_SECRET_ACCESS_KEY },
      candidate.roleArn,
      candidate.externalId,
      deps,
    );
    if (!assumed.ok || !assumed.credentials) {
      // 503 only when no mechanism existed to try -- that is OUR infrastructure
      // being unconfigured, and the customer can do nothing about it. Once a
      // mechanism ran and AWS refused, it is a 400 and the message points at
      // the trust policy, which is the thing they can fix. Keying this off
      // "are platform keys set" (as it did before workload identity existed)
      // now reports every trust-policy mismatch on Cloud Run as a 503 outage.
      return {
        ok: false,
        status: assumed.unavailable ? 503 : 400,
        code: assumed.unavailable ? 'assume_role_platform_unavailable' : 'assume_role_failed',
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
