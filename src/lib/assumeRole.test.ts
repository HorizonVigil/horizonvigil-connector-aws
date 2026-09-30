import { describe, it, expect, vi, afterEach } from 'vitest';
import { assumeConnectionRole } from './assumeRole';

const ROLE_ARN = 'arn:aws:iam::123456789012:role/horizonvigil-readonly';
const EXTERNAL_ID = 'ext-abc123';

/**
 * Simulates a host with no Google metadata server — a workstation, a CI
 * runner, or this service deployed somewhere that is not Google
 * infrastructure. That is what selects the platform-key path.
 */
const noMetadata = () => ({ fetchImpl: vi.fn().mockRejectedValue(new Error('ENOTFOUND metadata.google.internal')) as unknown as typeof fetch });

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('assumeConnectionRole falls back to the platform key off Google infrastructure', () => {
  it('returns an honest ok:false when neither mechanism is available, without calling STS', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    const result = await assumeConnectionRole({}, ROLE_ARN, EXTERNAL_ID, noMetadata());

    expect(result.ok).toBe(false);
    // Names BOTH mechanisms, because "not configured" alone does not tell the
    // operator which of the two they were expected to have set up.
    expect(result.reason).toMatch(/metadata server/i);
    expect(result.reason).toMatch(/PLATFORM_AWS_ACCESS_KEY_ID/);
    // The global fetch is what callQueryApi signs and sends. Never reached:
    // signing an STS call with absent credentials is not a thing to attempt.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('returns an honest ok:false when only one of the two credential fields is set', async () => {
    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST' }, ROLE_ARN, EXTERNAL_ID, noMetadata());
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/PLATFORM_AWS_ACCESS_KEY_ID/);
  });

  it('surfaces the AWS error Code/Message when STS returns a non-ok response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      '<ErrorResponse><Error><Code>AccessDenied</Code><Message>User is not authorized to perform sts:AssumeRole</Message></Error></ErrorResponse>',
      { status: 403 },
    )));

    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST', secretAccessKey: 'secret' }, ROLE_ARN, EXTERNAL_ID, noMetadata());

    expect(result.ok).toBe(false);
    expect(result.method).toBe('platform_key');
    expect(result.reason).toBe('User is not authorized to perform sts:AssumeRole');
  });

  it('falls back to the Code and HTTP status when the error response has no Message', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      '<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>',
      { status: 403 },
    )));

    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST', secretAccessKey: 'secret' }, ROLE_ARN, EXTERNAL_ID, noMetadata());

    expect(result.ok).toBe(false);
    expect(result.reason).toBe('AssumeRole failed (AccessDenied)');
  });

  it('returns ok:false when the response is 200 but missing expected credential fields', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      '<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>AKIAABC</AccessKeyId></Credentials></AssumeRoleResult></AssumeRoleResponse>',
      { status: 200 },
    )));

    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST', secretAccessKey: 'secret' }, ROLE_ARN, EXTERNAL_ID, noMetadata());

    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/missing expected credential fields/);
  });

  it('returns the temporary credentials on a well-formed success response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      '<AssumeRoleResponse><AssumeRoleResult><Credentials>' +
      '<AccessKeyId>AKIAABC</AccessKeyId><SecretAccessKey>secretXYZ</SecretAccessKey><SessionToken>tok123</SessionToken>' +
      '</Credentials></AssumeRoleResult></AssumeRoleResponse>',
      { status: 200 },
    )));

    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST', secretAccessKey: 'secret' }, ROLE_ARN, EXTERNAL_ID, noMetadata());

    expect(result.ok).toBe(true);
    expect(result.method).toBe('platform_key');
    expect(result.credentials).toEqual({ accessKeyId: 'AKIAABC', secretAccessKey: 'secretXYZ', sessionToken: 'tok123' });
  });

  it('returns an honest ok:false when the request itself throws', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network unreachable')));

    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST', secretAccessKey: 'secret' }, ROLE_ARN, EXTERNAL_ID, noMetadata());

    expect(result.ok).toBe(false);
    expect(result.reason).toBe('network unreachable');
  });
});

/**
 * On Cloud Run the metadata server answers, and that is the whole point: no
 * AWS credential is involved on either side.
 */
describe('assumeConnectionRole prefers workload identity on Google infrastructure', () => {
  const JWT = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMTExMTExMTExIn0.sig';

  /** Routes the metadata call and the STS call to separate canned responses. */
  function onGoogle(sts: Response) {
    return {
      fetchImpl: vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes('metadata.google.internal')) return new Response(JWT, { status: 200 });
        return sts;
      }) as unknown as typeof fetch,
    };
  }

  it('exchanges a Google token for credentials with no AWS key anywhere', async () => {
    const deps = onGoogle(new Response(
      '<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>' +
      '<AccessKeyId>ASIAWEB</AccessKeyId><SecretAccessKey>websecret</SecretAccessKey><SessionToken>webtok</SessionToken>' +
      '</Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>',
      { status: 200 },
    ));
    const globalFetch = vi.fn();
    vi.stubGlobal('fetch', globalFetch);

    // Platform credentials ARE supplied, to prove they are not what gets used.
    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST', secretAccessKey: 'secret' }, ROLE_ARN, EXTERNAL_ID, deps);

    expect(result.ok).toBe(true);
    expect(result.method).toBe('web_identity');
    expect(result.credentials).toEqual({ accessKeyId: 'ASIAWEB', secretAccessKey: 'websecret', sessionToken: 'webtok' });
    // The signed sts:AssumeRole path was never taken.
    expect(globalFetch).not.toHaveBeenCalled();
  });

  it('mints the token with the external ID as its audience', async () => {
    // This is what binds a token to ONE connection. Without it, the same
    // service account's token would satisfy every customer's trust policy.
    const deps = onGoogle(new Response('<x/>', { status: 500 }));
    await assumeConnectionRole({}, ROLE_ARN, EXTERNAL_ID, deps);

    const metadataCall = vi.mocked(deps.fetchImpl).mock.calls.find((c) => String(c[0]).includes('metadata.google.internal'));
    expect(metadataCall).toBeDefined();
    expect(String(metadataCall?.[0])).toContain(`audience=${EXTERNAL_ID}`);
  });

  it('sends no ProviderId, which AWS forbids for OIDC ID tokens', async () => {
    const deps = onGoogle(new Response('<x/>', { status: 500 }));
    await assumeConnectionRole({}, ROLE_ARN, EXTERNAL_ID, deps);

    const stsCall = vi.mocked(deps.fetchImpl).mock.calls.find((c) => String(c[0]).includes('sts.amazonaws.com'));
    const body = String((stsCall?.[1] as RequestInit | undefined)?.body ?? '');
    expect(body).toContain('Action=AssumeRoleWithWebIdentity');
    expect(body).toContain('WebIdentityToken=');
    // "Do not specify this value for an OpenID Connect identity provider" --
    // sending it makes STS treat the ID token as an OAuth 2.0 access token.
    expect(body).not.toContain('ProviderId');
  });

  it('does NOT fall back to the platform key when STS rejects the token', async () => {
    // Once a token is minted we know we are on Google infrastructure and web
    // identity is the intended path. Retrying with platform keys would replace
    // an actionable trust-policy diagnosis with "credentials not configured"
    // and send the operator to fix the wrong thing.
    const deps = onGoogle(new Response(
      '<ErrorResponse><Error><Code>AccessDenied</Code><Message>Not authorized to perform sts:AssumeRoleWithWebIdentity</Message></Error></ErrorResponse>',
      { status: 403 },
    ));
    const globalFetch = vi.fn();
    vi.stubGlobal('fetch', globalFetch);

    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST', secretAccessKey: 'secret' }, ROLE_ARN, EXTERNAL_ID, deps);

    expect(result.ok).toBe(false);
    expect(result.method).toBe('web_identity');
    // Points at the trust policy, which is the file that is actually wrong.
    expect(result.reason).toMatch(/trust policy/i);
    expect(result.reason).toContain('accounts.google.com');
    expect(globalFetch).not.toHaveBeenCalled();
  });

  it('reports a refusing metadata server instead of silently falling back', async () => {
    // A metadata server that answers 403 is a real misconfiguration (the
    // service account lacks iam.serviceAccounts.getOpenIdToken on itself).
    // Treating it as "not on Google" would hide it behind a credentials
    // message that has nothing to do with the cause.
    const deps = {
      fetchImpl: vi.fn().mockResolvedValue(new Response('forbidden', { status: 403 })) as unknown as typeof fetch,
    };
    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST', secretAccessKey: 'secret' }, ROLE_ARN, EXTERNAL_ID, deps);

    expect(result.ok).toBe(false);
    expect(result.method).toBe('web_identity');
    expect(result.reason).toMatch(/getOpenIdToken/);
  });
});
