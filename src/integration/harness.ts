/**
 * Phase 1A — the real integration harness.
 *
 * WHAT IS AND IS NOT MOCKED
 *
 * Nothing in the request path is mocked. `app.fetch(request, env)` is the
 * exact entrypoint `server.ts` hands to `@hono/node-server`, so a test
 * request traverses the same middleware stack a production request does:
 *
 *   Request -> CORS/security headers -> X-Request-Id / Traceparent
 *           -> getAuthContext (real JWT)
 *           -> requireOrgId (real X-Org-Id)
 *           -> requireMenuPermission / getOrgConnectionIds (real grants)
 *           -> Db -> PostgREST -> Postgres RLS
 *           -> Response
 *
 * The tokens are genuine: the harness signs in through the project's real
 * `/auth/v1/token` endpoint and receives a JWT signed by the project's own
 * secret. Nothing here forges a token or stubs `auth.uid()`, because a
 * forged token would prove nothing about the boundary that actually runs.
 *
 * WHY NOT A LISTENING SERVER
 *
 * `serve()` only adapts `app.fetch` to a socket. Calling `app.fetch`
 * directly exercises identical code with no port to allocate and no
 * teardown to leak, which matters for a suite CI runs in parallel.
 *
 * WHY A SEPARATE DATABASE
 *
 * The suite runs against the `horizonvigil-scanner-platform` Supabase
 * project (idle since the scanner work was decommissioned; already paid
 * for, so no new spend). Supabase branching would have been cleaner but
 * requires the Pro plan.
 *
 * Its schema and RLS policies were generated FROM production's own catalog
 * rather than hand-written, so the predicates under test are byte-identical
 * to the ones that run in production. A hand-approximated policy would let
 * this suite pass against a boundary the real system does not have -- worse
 * than having no test at all.
 *
 * FAILING CLOSED
 *
 * §1J: "A test that cannot connect to the real service/database MUST fail,
 * not skip." `requireIntegrationEnv()` throws. There is deliberately no
 * `describe.skipIf` anywhere in this suite: a silently skipped isolation
 * test reports green while proving nothing, which is the exact failure mode
 * this phase exists to remove.
 */
import app from '../index';

export interface IntegrationEnv extends Record<string, string> {
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
  DB_SCHEMA: string;
  ALLOWED_ORIGIN: string;
}

/** Fixed IDs so assertions can name exactly which tenant's data must not appear. */
export const FIXTURES = {
  tenantA: {
    orgId: 'aaaaaaaa-0000-0000-0000-000000000001',
    userId: '11111111-1111-1111-1111-111111111111',
    email: 'tenant-a@integration.test',
    connScopeA: 'aaaaaaaa-0000-0000-0000-00000000c0a1',
    connScopeB: 'aaaaaaaa-0000-0000-0000-00000000c0a2',
    resourceScopeA: 'aaaaaaaa-0000-0000-0000-00000000e0a1',
    runId: 'aaaaaaaa-0000-0000-0000-0000000000c1',
    projectScopeA: 'aaaaaaaa-0000-0000-0000-0000000000a1',
    projectScopeB: 'aaaaaaaa-0000-0000-0000-0000000000a2',
  },
  tenantB: {
    orgId: 'bbbbbbbb-0000-0000-0000-000000000001',
    userId: '22222222-2222-2222-2222-222222222222',
    email: 'tenant-b@integration.test',
    connId: 'bbbbbbbb-0000-0000-0000-00000000c0b1',
    resourceId: 'bbbbbbbb-0000-0000-0000-00000000e0b1',
    runId: 'bbbbbbbb-0000-0000-0000-0000000000c1',
    recommendationId: 'bbbbbbbb-0000-0000-0000-0000000000d1',
    awsAccountId: '999999999999',
    /**
     * Strings that must never appear in a Tenant A response body.
     *
     * Asserting on the BODY, not just the status code, is the point:
     * a 200 with an empty list and a 200 that leaked a name are both 200.
     */
    secretMarkers: [
      'bbbbbbbb-0000-0000-0000',
      'i-TENANT-B-SECRET',
      'B-secret-res',
      // Deliberately unambiguous: an earlier marker of 'B-conn' was a
      // SUBSTRING of Tenant A's own 'A-scope-B-conn' and flagged legitimate
      // data as a leak. The scan is a substring search on purpose -- so a
      // leaked id inside a nested field is caught -- which only works if
      // every marker is unique to Tenant B.
      'TENANT-B-ONLY-CONNECTION',
      'TENANT-B-ONLY-ALERT',
      '999999999999',
      'B SECRET idle',
      'B-SECRET-AUDIT',
      // Phase 2 lineage evidence. A provider request id is not an
      // authorization credential, but it IS Tenant B's operational data and
      // must never appear in Tenant A's response (§20).
      'REQ-TENANT-B-ONLY-REQUESTID',
      'i-TENANT-B-SECRET-OBS',
      'i-TENANT-B-QUARANTINE-SECRET',
    ],
  },
  scopedUser: {
    userId: '33333333-3333-3333-3333-333333333333',
    email: 'scoped-a@integration.test',
  },
  password: 'IntegrationTest!2026',
} as const;

export function requireIntegrationEnv(): IntegrationEnv {
  const url = process.env.INTEGRATION_SUPABASE_URL;
  const anon = process.env.INTEGRATION_SUPABASE_ANON_KEY;
  if (!url || !anon) {
    throw new Error(
      'Integration tests require INTEGRATION_SUPABASE_URL and INTEGRATION_SUPABASE_ANON_KEY. ' +
        'They FAIL rather than skip when unset: a skipped isolation test reports green while proving nothing.',
    );
  }
  return {
    SUPABASE_URL: url,
    SUPABASE_ANON_KEY: anon,
    DB_SCHEMA: process.env.INTEGRATION_DB_SCHEMA ?? 'public',
    ALLOWED_ORIGIN: 'https://horizonvigil.test',
  };
}

const tokenCache = new Map<string, string>();

/** Signs in through the real Auth endpoint. Never forges a token. */
export async function signIn(env: IntegrationEnv, email: string): Promise<string> {
  const cached = tokenCache.get(email);
  if (cached) return cached;

  const res = await fetch(`${env.SUPABASE_URL}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { apikey: env.SUPABASE_ANON_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: FIXTURES.password }),
  });
  const body = (await res.json()) as { access_token?: string; msg?: string };
  if (!res.ok || !body.access_token) {
    throw new Error(`Integration sign-in failed for ${email}: ${res.status} ${body.msg ?? JSON.stringify(body)}`);
  }
  tokenCache.set(email, body.access_token);
  return body.access_token;
}

export interface ApiResult {
  status: number;
  /** Raw text, so assertions can search for leaked identifiers the parsed shape might hide. */
  raw: string;
  json: unknown;
  headers: Headers;
}

/**
 * Drives the real application.
 *
 * `orgId` is sent as `X-Org-Id` exactly as a browser would. That header is
 * attacker-controlled in production, which is the whole reason the isolation
 * tests below set it to a tenant the caller does not belong to.
 */
export async function callApi(
  env: IntegrationEnv,
  opts: { method?: string; path: string; token: string; orgId: string; body?: unknown; headers?: Record<string, string> },
): Promise<ApiResult> {
  const request = new Request(`https://connector-aws.test${opts.path}`, {
    method: opts.method ?? 'GET',
    headers: {
      Authorization: `Bearer ${opts.token}`,
      'X-Org-Id': opts.orgId,
      'Content-Type': 'application/json',
      ...(opts.headers ?? {}),
    },
    ...(opts.body === undefined ? {} : { body: JSON.stringify(opts.body) }),
  });

  const response = await app.fetch(request, env);
  const raw = await response.text();
  let json: unknown = null;
  try {
    json = raw ? JSON.parse(raw) : null;
  } catch {
    // Non-JSON (a file download) is legitimate; `raw` still carries it.
  }
  return { status: response.status, raw, json, headers: response.headers };
}

/**
 * The assertion that matters most in this suite.
 *
 * A response can be a perfectly ordinary 200 and still have leaked another
 * tenant's account id inside a nested field, an error message, or a count.
 * Searching the raw body catches all three, and names the marker it found
 * so a failure says what leaked rather than that something did.
 */
export function assertNoTenantBData(result: ApiResult, context: string): void {
  /**
   * The RFC 9457 `instance` member echoes the request path, which contains
   * the id the CALLER supplied. Reflecting it back discloses nothing they
   * did not already know, and omitting it would break the Problem Details
   * contract, so it is excluded from the leak scan.
   *
   * This is a principled exclusion of one field, not a relaxation of the
   * check: every other part of the body -- including error text, nested
   * objects and counts -- is still searched for Tenant B's markers.
   */
  const body = result.raw.replace(/"instance":"[^"]*"/g, '"instance":"<redacted-for-scan>"');

  for (const marker of FIXTURES.tenantB.secretMarkers) {
    if (body.includes(marker)) {
      throw new Error(
        `TENANT LEAK in ${context}: response contained Tenant B marker ${JSON.stringify(marker)}.\n` +
          `status=${result.status} body=${result.raw.slice(0, 400)}`,
      );
    }
  }
}
