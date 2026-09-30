import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { assumeRoleWithWebIdentity, fetchGoogleIdToken, googleSubjectOf } from './webIdentity';

/** Builds a JWT-shaped string with the given payload. Signature is never checked here — AWS does that. */
function jwt(payload: Record<string, unknown>): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64({ alg: 'RS256' })}.${b64(payload)}.signature`;
}

describe('minting the workload identity token', () => {
  it('asks the metadata server for the requested audience, with the required header', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(jwt({ sub: '123' }), { status: 200 }));
    await fetchGoogleIdToken('ext-abc', { fetchImpl: fetchImpl as unknown as typeof fetch });

    const [url, init] = fetchImpl.mock.calls[0];
    expect(String(url)).toContain('metadata.google.internal');
    expect(String(url)).toContain('audience=ext-abc');
    // Without this header the metadata server refuses, as an SSRF guard.
    expect((init as RequestInit).headers).toMatchObject({ 'Metadata-Flavor': 'Google' });
  });

  it('url-encodes an audience containing reserved characters', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(jwt({ sub: '1' }), { status: 200 }));
    await fetchGoogleIdToken('a/b c&d', { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(String(fetchImpl.mock.calls[0][0])).toContain('audience=a%2Fb%20c%26d');
  });

  /**
   * null, not an error: no metadata server is the ordinary state off Google
   * infrastructure, and the caller uses it to choose the platform-key path.
   * Reporting it as a failure would make every workstation run look broken.
   */
  it('returns null when there is no metadata server at all', async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error('ENOTFOUND'));
    expect(await fetchGoogleIdToken('aud', { fetchImpl: fetchImpl as unknown as typeof fetch })).toBeNull();
  });

  /**
   * A metadata server that ANSWERS but refuses is a real misconfiguration on
   * our side, and must not be collapsed into the null case above — that would
   * hide it behind a message about AWS credentials.
   */
  it('reports a refusing metadata server, naming the permission needed', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response('denied', { status: 403 }));
    const result = await fetchGoogleIdToken('aud', { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result).toHaveProperty('error');
    expect((result as { error: string }).error).toContain('getOpenIdToken');
  });

  it('refuses to forward something that is not a JWT', async () => {
    // A captive portal or proxy answering 200 with HTML would otherwise reach
    // STS and come back as a confusing InvalidIdentityToken.
    const fetchImpl = vi.fn().mockResolvedValue(new Response('<html>login</html>', { status: 200 }));
    const result = await fetchGoogleIdToken('aud', { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result).toHaveProperty('error');
    expect((result as { error: string }).error).toMatch(/not a JWT/);
  });
});

describe('exchanging the token for AWS credentials', () => {
  const ROLE = 'arn:aws:iam::123456789012:role/HorizonVigilRead';

  it('posts an unsigned form body with no Authorization header', async () => {
    // The entire point: AWS states "Calling AssumeRoleWithWebIdentity does not
    // require the use of AWS security credentials". If this ever started
    // signing, it would need a platform AWS key again.
    const fetchImpl = vi.fn().mockResolvedValue(new Response('<x/>', { status: 500 }));
    await assumeRoleWithWebIdentity(ROLE, 'a.b.c', 'session', { fetchImpl: fetchImpl as unknown as typeof fetch });

    const [url, init] = fetchImpl.mock.calls[0];
    expect(String(url)).toBe('https://sts.amazonaws.com/');
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(Object.keys(headers).map((k) => k.toLowerCase())).not.toContain('authorization');
    expect(String((init as RequestInit).body)).toContain('Action=AssumeRoleWithWebIdentity');
  });

  it('omits ProviderId, which AWS forbids for OIDC ID tokens', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response('<x/>', { status: 500 }));
    await assumeRoleWithWebIdentity(ROLE, 'a.b.c', 'session', { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(String((fetchImpl.mock.calls[0][1] as RequestInit).body)).not.toContain('ProviderId');
  });

  it('returns the temporary credentials from a well-formed response', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(
      '<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>' +
      '<AccessKeyId>ASIA1</AccessKeyId><SecretAccessKey>sec</SecretAccessKey><SessionToken>tok</SessionToken>' +
      '</Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>',
      { status: 200 },
    ));
    const result = await assumeRoleWithWebIdentity(ROLE, 'a.b.c', 'session', { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result.ok).toBe(true);
    expect(result.credentials).toEqual({ accessKeyId: 'ASIA1', secretAccessKey: 'sec', sessionToken: 'tok' });
  });

  it('does not report success when STS returns 200 with no credentials', async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response('<AssumeRoleWithWebIdentityResponse/>', { status: 200 }));
    const result = await assumeRoleWithWebIdentity(ROLE, 'a.b.c', 'session', { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/returned no credentials/);
  });

  /**
   * Each STS error names the thing the operator has to change. "AccessDenied"
   * alone sends people to the permission policy, when the trust policy is
   * what is wrong in nearly every real case.
   */
  it.each([
    ['AccessDenied', /trust policy/i],
    ['IDPRejectedClaim', /audience/i],
    ['InvalidIdentityToken', /could not validate/i],
    ['ExpiredToken', /expired/i],
  ])('explains %s in terms of what to fix', async (code, expected) => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(
      `<ErrorResponse><Error><Code>${code}</Code><Message>detail</Message></Error></ErrorResponse>`,
      { status: 403 },
    ));
    const result = await assumeRoleWithWebIdentity(ROLE, 'a.b.c', 'session', { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(expected);
  });
});

describe('reading the subject a customer must pin', () => {
  it('extracts sub from a token', () => {
    expect(googleSubjectOf(jwt({ sub: '103548712345678901234', aud: 'ext-1' }))).toBe('103548712345678901234');
  });

  it('handles base64url payloads containing - and _', () => {
    // Real Google tokens routinely produce these; decoding with plain base64
    // would throw and the subject would silently read as null.
    const token = jwt({ sub: '1', email: 'svc+a/b?c@project.iam.gserviceaccount.com' });
    expect(googleSubjectOf(token)).toBe('1');
  });

  it('returns null rather than a guess for a token with no subject', () => {
    expect(googleSubjectOf(jwt({ aud: 'x' }))).toBeNull();
  });

  it('returns null for malformed input instead of throwing', () => {
    expect(googleSubjectOf('not-a-jwt')).toBeNull();
    expect(googleSubjectOf('a.!!!notbase64!!!.c')).toBeNull();
    expect(googleSubjectOf('')).toBeNull();
  });
});

/**
 * The endpoint that publishes the subject must not be shadowed by
 * `/accounts/:id`, which would match "aws-trust-identity" as an id and return
 * 404 for a connection that does not exist — a confusing failure for something
 * that is not a connection at all.
 */
describe('the trust-identity endpoint is reachable', () => {
  const ACCOUNTS = readFileSync('src/routes/accounts.ts', 'utf8');

  it('is registered before the /accounts/:id wildcard', () => {
    const specific = ACCOUNTS.indexOf("accountsRoutes.get('/accounts/aws-trust-identity'");
    const wildcard = ACCOUNTS.indexOf("accountsRoutes.get('/accounts/:id'");
    expect(specific).toBeGreaterThan(-1);
    expect(wildcard).toBeGreaterThan(-1);
    expect(specific).toBeLessThan(wildcard);
  });

  it('never returns the token itself, only the subject', () => {
    const route = ACCOUNTS.slice(
      ACCOUNTS.indexOf("accountsRoutes.get('/accounts/aws-trust-identity'"),
      ACCOUNTS.indexOf("accountsRoutes.get('/accounts'"),
    );
    expect(route).toContain('googleSubject');
    // The token is a live credential for an hour and must never leave the
    // server. Asserted as "no response property named token" — matching the
    // WORD `token` instead would trip on the honest prose in the unavailable
    // message ("cannot mint a workload identity token"), which is exactly the
    // kind of false positive that gets a guard weakened later.
    expect(route).not.toMatch(/\btoken:\s/);
    expect(route).not.toContain('idToken');
  });
});
