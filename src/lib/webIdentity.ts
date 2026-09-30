import { extractXmlField, type AwsCreds } from './awsApi';

/**
 * Cross-account access WITHOUT any long-lived AWS credential, anywhere.
 *
 * THE PROBLEM WITH THE ORIGINAL DESIGN
 *
 * assumeRole.ts calls sts:AssumeRole, which is a SIGNED request — so it needs
 * the platform's own AWS access key and secret. That trades one long-lived
 * credential for another and concentrates the risk: a single key pair that can
 * assume into every customer account is a far better target than any one
 * customer's read-only keys. It also requires HorizonVigil to own an AWS
 * account, which it does not; PLATFORM_AWS_ACCESS_KEY_ID has never been
 * provisioned, which is why the cross-account option is switched off in the
 * connect wizard.
 *
 * THE MECHANISM THAT REMOVES IT
 *
 * This connector runs on Cloud Run, and AWS accepts Google as a native
 * federated principal — `"Principal": {"Federated": "accounts.google.com"}` —
 * with no IAM OIDC provider resource to create. AWS states plainly that
 * "Calling AssumeRoleWithWebIdentity does not require the use of AWS security
 * credentials": the call is unsigned, and the caller's identity is established
 * by a token the identity provider signed.
 *
 * So: Cloud Run's metadata server mints a Google-signed OIDC token for this
 * service account, STS validates it against the customer's trust policy, and
 * returns temporary credentials. There is no AWS key to store, rotate, leak or
 * revoke — on our side or the customer's.
 *
 * WHAT BINDS A TOKEN TO ONE CUSTOMER
 *
 * The same service account assumes every customer's role, so `sub` alone would
 * let a token minted for one customer be presented to another's role. The
 * audience closes that: the token is minted with the connection's external ID
 * as its audience, and the customer's trust policy requires
 * `accounts.google.com:oaud` to equal that same value. That is the external-ID
 * guarantee, carried by a signed claim instead of a request parameter.
 *
 * Conditioning on `oaud` rather than `aud` is deliberate. AWS maps the `aud`
 * condition key from the token's `azp` claim when `azp` is set and from `aud`
 * when it is not — and Google sets `azp` for service-account tokens. `oaud`
 * always maps from `aud`, so it means the same thing either way.
 */

/** Cloud Run / GCE metadata server. Only reachable from inside Google infrastructure. */
const METADATA_IDENTITY_URL =
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity';

const STS_ENDPOINT = 'https://sts.amazonaws.com/';

export interface WebIdentityOutcome {
  ok: boolean;
  credentials?: AwsCreds;
  reason?: string;
}

export interface WebIdentityDeps {
  /** Injected so the metadata server and STS can both be exercised without either. */
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/**
 * Mints a Google-signed OIDC token for this workload, bound to `audience`.
 *
 * Returns null — not an error — when the metadata server is simply not there,
 * because that is the ordinary case off Google infrastructure (a workstation,
 * a CI runner) and the caller falls back to the platform-credential path. A
 * metadata server that answers but REFUSES is a different thing and is
 * reported.
 */
export async function fetchGoogleIdToken(
  audience: string,
  deps: WebIdentityDeps = {},
): Promise<{ token: string } | { error: string } | null> {
  const doFetch = deps.fetchImpl ?? fetch;
  const url = `${METADATA_IDENTITY_URL}?audience=${encodeURIComponent(audience)}&format=full`;

  let res: Response;
  try {
    res = await doFetch(url, {
      headers: { 'Metadata-Flavor': 'Google' },
      signal: AbortSignal.timeout(deps.timeoutMs ?? 5_000),
    });
  } catch {
    // No metadata server on this host. Not an error in itself.
    return null;
  }

  if (!res.ok) {
    return {
      error:
        `The Cloud Run metadata server refused to issue an identity token (HTTP ${res.status}). ` +
        `The service account needs the iam.serviceAccounts.getOpenIdToken permission on itself.`,
    };
  }

  const token = (await res.text()).trim();
  // A JWT has three dot-separated segments. The metadata server returns the
  // bare token, so anything else means we are talking to something that is not
  // the metadata server -- a captive portal or proxy, for instance -- and
  // handing that to STS would produce a confusing InvalidIdentityToken.
  if (token.split('.').length !== 3) {
    return { error: 'The metadata server returned something that is not a JWT; refusing to present it to AWS STS.' };
  }
  return { token };
}

/**
 * Exchanges a Google OIDC token for temporary AWS credentials.
 *
 * Unsigned by design — see the file header. `ProviderId` is deliberately NOT
 * sent: AWS documents it as "Do not specify this value for an OpenID Connect
 * identity provider", and sending it makes STS treat the token as an OAuth 2.0
 * access token instead of an OIDC ID token.
 */
export async function assumeRoleWithWebIdentity(
  roleArn: string,
  webIdentityToken: string,
  sessionName: string,
  deps: WebIdentityDeps = {},
): Promise<WebIdentityOutcome> {
  const doFetch = deps.fetchImpl ?? fetch;
  const body = new URLSearchParams({
    Action: 'AssumeRoleWithWebIdentity',
    Version: '2011-06-15',
    RoleArn: roleArn,
    RoleSessionName: sessionName,
    WebIdentityToken: webIdentityToken,
    DurationSeconds: '900',
  }).toString();

  let res: Response;
  let text: string;
  try {
    res = await doFetch(STS_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(deps.timeoutMs ?? 10_000),
    });
    text = await res.text();
  } catch (err) {
    return { ok: false, reason: `Could not reach AWS STS: ${err instanceof Error ? err.message : 'network error'}` };
  }

  if (!res.ok) {
    const code = extractXmlField(text, 'Code');
    const message = extractXmlField(text, 'Message');
    return { ok: false, reason: explainStsFailure(code, message, res.status) };
  }

  const accessKeyId = extractXmlField(text, 'AccessKeyId');
  const secretAccessKey = extractXmlField(text, 'SecretAccessKey');
  const sessionToken = extractXmlField(text, 'SessionToken');
  if (!accessKeyId || !secretAccessKey || !sessionToken) {
    return { ok: false, reason: 'AWS STS accepted the identity token but returned no credentials.' };
  }
  return { ok: true, credentials: { accessKeyId, secretAccessKey, sessionToken } };
}

/**
 * Turns STS's error codes into the thing the operator actually has to change.
 *
 * `AccessDenied` here almost always means the trust policy's conditions did not
 * match, and saying "access denied" alone sends people to look at the
 * permission policy, which is the wrong file.
 */
function explainStsFailure(code: string | null, message: string | null, status: number): string {
  switch (code) {
    case 'AccessDenied':
      return (
        `AWS refused the role assumption. The role exists, but its trust policy did not match this request — ` +
        `check that it allows Principal "accounts.google.com" for sts:AssumeRoleWithWebIdentity, and that its ` +
        `accounts.google.com:sub and accounts.google.com:oaud conditions match the values HorizonVigil presents. ` +
        `(STS said: ${message ?? 'no detail'})`
      );
    case 'InvalidIdentityToken':
      return `AWS could not validate the Google identity token. It may have expired in transit; retrying usually resolves it. (STS said: ${message ?? 'no detail'})`;
    case 'IDPRejectedClaim':
      return `AWS rejected a claim in the Google identity token — most often the audience does not match the trust policy's accounts.google.com:oaud condition. (STS said: ${message ?? 'no detail'})`;
    case 'ExpiredToken':
      return 'The Google identity token expired before AWS validated it. Retry.';
    default:
      return `AssumeRoleWithWebIdentity failed (${code ?? `HTTP ${status}`}): ${message ?? 'no detail'}`;
  }
}

/**
 * The `sub` claim of a Google identity token.
 *
 * Deliberately does NOT verify the signature: AWS does that, and the only use
 * of this value here is to DISPLAY which workload identity a customer should
 * pin in their trust policy. Reading it from a freshly minted token rather
 * than from configuration is what stops the published number drifting from
 * the identity actually presented to AWS.
 */
export function googleSubjectOf(token: string): string | null {
  const payload = token.split('.')[1];
  if (!payload) return null;
  try {
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    const sub = (JSON.parse(json) as { sub?: unknown }).sub;
    return typeof sub === 'string' && sub ? sub : null;
  } catch {
    return null;
  }
}
