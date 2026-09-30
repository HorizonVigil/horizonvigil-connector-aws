import { callQueryApi, extractXmlField, type AwsCreds } from './awsApi';
import { assumeRoleWithWebIdentity, fetchGoogleIdToken, type WebIdentityDeps } from './webIdentity';

export interface AssumeRoleOutcome {
  ok: boolean;
  credentials?: AwsCreds;
  reason?: string;
  /** Which mechanism produced (or failed to produce) the credentials. */
  method?: 'web_identity' | 'platform_key';
  /**
   * True only when NEITHER mechanism was available to try — an infrastructure
   * state on our side, not a customer misconfiguration. Callers map this to
   * 503; every other failure means a mechanism ran and AWS refused, which is
   * a 400 pointing at the customer's trust policy.
   */
  unavailable?: boolean;
}

const SESSION_NAME = 'horizonvigil';

/**
 * Obtains temporary credentials for a cross-account-role connection.
 *
 * TWO MECHANISMS, PREFERRED ORDER
 *
 * 1. WEB IDENTITY (no AWS credential exists anywhere). Cloud Run's metadata
 *    server mints a Google-signed OIDC token; AWS trusts `accounts.google.com`
 *    natively and AssumeRoleWithWebIdentity is unsigned, so nothing has to be
 *    stored, rotated or revoked. See webIdentity.ts.
 *
 * 2. PLATFORM KEY (sts:AssumeRole). Requires HorizonVigil to hold its own
 *    long-lived AWS access key. Kept because it is the model customers'
 *    security teams already recognise, and because it is the only option if
 *    this service ever runs somewhere that is not Google infrastructure.
 *
 * WHY THE ORDER MATTERS, AND WHY FALLBACK IS NARROW
 *
 * Falling through on ANY web-identity failure would be wrong. Once a token has
 * been minted we know we are running on Google infrastructure and web identity
 * is the intended path, so an STS rejection there is a real, actionable fault
 * -- nearly always a trust-policy condition that does not match. Retrying with
 * platform keys would replace that precise diagnosis with "platform
 * credentials are not configured", sending the operator to fix the wrong
 * thing.
 *
 * So the fallback happens only when there is no metadata server at all, which
 * is the honest signal for "not running on Google infrastructure".
 */
export async function assumeConnectionRole(
  platformCreds: { accessKeyId?: string; secretAccessKey?: string },
  roleArn: string,
  externalId: string,
  deps: WebIdentityDeps = {},
): Promise<AssumeRoleOutcome> {
  // The external ID travels as the token's audience, so the customer's trust
  // policy can pin this request to their connection and no other.
  const minted = await fetchGoogleIdToken(externalId, deps);

  if (minted && 'error' in minted) {
    return { ok: false, method: 'web_identity', reason: minted.error };
  }

  if (minted) {
    const result = await assumeRoleWithWebIdentity(roleArn, minted.token, SESSION_NAME, deps);
    return { ...result, method: 'web_identity' };
  }

  // No metadata server: not on Google infrastructure. Fall back.
  if (!platformCreds.accessKeyId || !platformCreds.secretAccessKey) {
    return {
      ok: false,
      unavailable: true,
      reason:
        'Cross-account role access is not available here. This service is not running on Google infrastructure ' +
        '(no metadata server), so it cannot mint a workload identity token, and no platform AWS credentials ' +
        '(PLATFORM_AWS_ACCESS_KEY_ID / PLATFORM_AWS_SECRET_ACCESS_KEY) are configured as an alternative.',
    };
  }

  return assumeViaPlatformKey(platformCreds as { accessKeyId: string; secretAccessKey: string }, roleArn, externalId);
}

/**
 * The signed sts:AssumeRole path, using the platform's own AWS credentials.
 *
 * Uses the common signed-call helper rather than a raw client so this
 * security-sensitive request inherits the same abort deadline, retry policy and
 * response normalization as every other AWS call in the connector.
 */
async function assumeViaPlatformKey(
  platformCreds: { accessKeyId: string; secretAccessKey: string },
  roleArn: string,
  externalId: string,
): Promise<AssumeRoleOutcome> {
  const result = await callQueryApi(
    { accessKeyId: platformCreds.accessKeyId, secretAccessKey: platformCreds.secretAccessKey },
    {
      service: 'sts', region: 'us-east-1', host: 'sts.amazonaws.com',
      action: 'AssumeRole', version: '2011-06-15',
      params: { RoleArn: roleArn, RoleSessionName: `${SESSION_NAME}-validation`, ExternalId: externalId, DurationSeconds: '900' },
    },
  );
  const text = typeof result.body === 'string' ? result.body : '';
  if (!result.ok) {
    return {
      ok: false,
      method: 'platform_key',
      reason: extractXmlField(text, 'Message') ?? result.errorMessage ?? `AssumeRole failed (${extractXmlField(text, 'Code') ?? result.errorCode ?? result.status})`,
    };
  }
  const accessKeyId = extractXmlField(text, 'AccessKeyId');
  const secretAccessKey = extractXmlField(text, 'SecretAccessKey');
  const sessionToken = extractXmlField(text, 'SessionToken');
  if (!accessKeyId || !secretAccessKey || !sessionToken) {
    return { ok: false, method: 'platform_key', reason: 'AssumeRole succeeded but the response was missing expected credential fields.' };
  }
  return { ok: true, method: 'platform_key', credentials: { accessKeyId, secretAccessKey, sessionToken } };
}
