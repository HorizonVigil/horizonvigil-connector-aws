import { describe, it, expect, beforeAll } from 'vitest';
import { requireIntegrationEnv, signIn, callApi, assertNoTenantBData, FIXTURES, type IntegrationEnv } from './harness';

/**
 * Phase 1B/1C/1D — tenant, scope and job isolation, proven at runtime.
 *
 * Every assertion here goes through the real application: real JWT, real
 * X-Org-Id, real RBAC, real PostgREST, real RLS. Nothing is mocked, and
 * these are the first tests in this repository that touch a database.
 *
 * Two things this suite deliberately does NOT do:
 *
 *  - It never asserts only on a status code. A 200 with an empty list and a
 *    200 that leaked a resource name are both 200. Every isolation check
 *    also greps the raw body for Tenant B's markers.
 *
 *  - It never skips. If the database is unreachable the suite FAILS, per
 *    §1J. A skipped isolation test reports green while proving nothing.
 */
let env: IntegrationEnv;
let tokenA = '';
let tokenB = '';
let tokenScoped = '';

beforeAll(async () => {
  env = requireIntegrationEnv();
  [tokenA, tokenB, tokenScoped] = await Promise.all([
    signIn(env, FIXTURES.tenantA.email),
    signIn(env, FIXTURES.tenantB.email),
    signIn(env, FIXTURES.scopedUser.email),
  ]);
});

describe('the harness is actually reaching the real stack', () => {
  it('rejects an unauthenticated request', async () => {
    const res = await callApi(env, { path: '/api/aws-accounts/accounts', token: '', orgId: FIXTURES.tenantA.orgId });
    expect(res.status).toBe(401);
  });

  it('rejects a request with no organization context', async () => {
    // Fails closed when tenant context is missing (non-negotiable rule 9).
    const res = await callApi(env, { path: '/api/aws-accounts/accounts', token: tokenA, orgId: '' });
    expect(res.status).toBe(400);
  });

  it('returns the caller their own data, so a pass is not vacuous', async () => {
    // Without this, every isolation assertion below could pass simply
    // because the endpoint returns nothing to anyone.
    const res = await callApi(env, { path: '/api/aws-accounts/accounts', token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect(res.status).toBe(200);
    expect(res.raw).toContain('A-scope-A-conn');
  });

  it('carries the §14.6 correlation headers on a real response', async () => {
    const res = await callApi(env, { path: '/api/aws-accounts/accounts', token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect(res.headers.get('x-request-id')).toBeTruthy();
    expect(res.headers.get('traceparent')).toBeTruthy();
  });
});

describe('Tenant A cannot reach Tenant B', () => {
  const B = FIXTURES.tenantB;

  it('listing accounts returns only Tenant A', async () => {
    const res = await callApi(env, { path: '/api/aws-accounts/accounts', token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect(res.status).toBe(200);
    assertNoTenantBData(res, 'accounts list');
  });

  it('fetching a Tenant B connection BY ID does not reveal it', async () => {
    // The IDOR case: a valid id belonging to someone else. A 404 is correct
    // and a 403 would confirm the object exists.
    const res = await callApi(env, { path: `/api/aws-accounts/accounts/${B.connId}`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect([403, 404]).toContain(res.status);
    assertNoTenantBData(res, 'connection by id');
  });

  it('spoofing X-Org-Id to Tenant B is refused', async () => {
    // The header is attacker-controlled. Membership is what authorises.
    const res = await callApi(env, { path: '/api/aws-accounts/accounts', token: tokenA, orgId: B.orgId });
    expect([200, 403]).toContain(res.status);
    assertNoTenantBData(res, 'X-Org-Id spoof');
  });

  it('resource listing excludes Tenant B resources', async () => {
    const res = await callApi(env, { path: `/api/aws-accounts/accounts/${B.connId}/resources`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    assertNoTenantBData(res, 'resources by tenant B connection');
  });

  it('recommendations cannot be reached across tenants', async () => {
    const res = await callApi(env, { path: `/api/aws-accounts/accounts/${B.connId}/recommendations`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    assertNoTenantBData(res, 'recommendations');
  });

  it('a Tenant B job cannot be inspected by Tenant A', async () => {
    const res = await callApi(env, { path: `/api/aws-accounts/collection-runs/${B.runId}`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect([403, 404]).toContain(res.status);
    assertNoTenantBData(res, 'collection run by id');
  });

  it('a Tenant B job cannot be cancelled by Tenant A', async () => {
    const res = await callApi(env, {
      method: 'POST', path: `/api/aws-accounts/collection-runs/${B.runId}/cancel`,
      token: tokenA, orgId: FIXTURES.tenantA.orgId, body: {},
    });
    expect([403, 404]).toContain(res.status);
    assertNoTenantBData(res, 'collection run cancel');
  });

  it('a job cannot be STARTED against a Tenant B connection', async () => {
    // The most consequential direction: not a read leak but an attempt to
    // make our worker touch another tenant's cloud account.
    const res = await callApi(env, {
      method: 'POST', path: `/api/aws-accounts/accounts/${B.connId}/collection-runs`,
      token: tokenA, orgId: FIXTURES.tenantA.orgId, body: {},
    });
    expect([403, 404, 409]).toContain(res.status);
    assertNoTenantBData(res, 'start collection run on tenant B connection');
  });

  it('permission snapshots cannot be read across tenants', async () => {
    const res = await callApi(env, { path: `/api/aws-accounts/accounts/${B.connId}/permissions`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    assertNoTenantBData(res, 'permissions');
  });

  it('health cannot be read across tenants', async () => {
    const res = await callApi(env, { path: `/api/aws-accounts/accounts/${B.connId}/health`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    assertNoTenantBData(res, 'health');
  });

  it('and the reverse direction holds too', async () => {
    // Asymmetric isolation is a real failure mode -- a filter applied on one
    // read path and forgotten on another.
    const res = await callApi(env, { path: '/api/aws-accounts/accounts', token: tokenB, orgId: FIXTURES.tenantB.orgId });
    expect(res.status).toBe(200);
    expect(res.raw).toContain('TENANT-B-ONLY-CONNECTION');
    expect(res.raw).not.toContain('A-scope-A-conn');
    expect(res.raw).not.toContain('aaaaaaaa-0000-0000-0000');
  });
});

describe('aggregates never count another tenant', () => {
  it('the dashboard totals exclude Tenant B', async () => {
    // A count is a leak with the identifiers stripped: "you have 3 accounts"
    // when you have 2 discloses that someone else has one.
    const res = await callApi(env, { path: '/api/aws-accounts/dashboard', token: tokenA, orgId: FIXTURES.tenantA.orgId });
    assertNoTenantBData(res, 'dashboard aggregate');
    if (res.status === 200) {
      const totals = JSON.stringify(res.json);
      expect(totals).not.toContain('999999999999');
    }
  });
});

describe('disjoint scopes inside one tenant', () => {
  /**
   * `scoped-a` is a member of Tenant A, so tenant isolation alone does not
   * protect Scope B from them -- the scope predicate does. This is the case
   * the earlier all-cloud audit found broken, where a restricted folder
   * scope still returned organization-wide resources.
   */
  it('a scope-restricted user still sees their own scope', async () => {
    const res = await callApi(env, {
      path: '/api/aws-accounts/accounts', token: tokenScoped, orgId: FIXTURES.tenantA.orgId,
      headers: { 'X-Scope-Type': 'project', 'X-Scope-Id': FIXTURES.tenantA.projectScopeA },
    });
    expect(res.status).toBe(200);
    expect(res.raw).toContain('A-scope-A-conn');
  });

  it('and does not see the other scope in the same tenant', async () => {
    const res = await callApi(env, {
      path: '/api/aws-accounts/accounts', token: tokenScoped, orgId: FIXTURES.tenantA.orgId,
      headers: { 'X-Scope-Type': 'project', 'X-Scope-Id': FIXTURES.tenantA.projectScopeA },
    });
    expect(res.raw).not.toContain('A-scope-B-conn');
  });

  it('cannot reach a Scope B connection by id while scoped to Scope A', async () => {
    const res = await callApi(env, {
      path: `/api/aws-accounts/accounts/${FIXTURES.tenantA.connScopeB}`, token: tokenScoped, orgId: FIXTURES.tenantA.orgId,
      headers: { 'X-Scope-Type': 'project', 'X-Scope-Id': FIXTURES.tenantA.projectScopeA },
    });
    expect([403, 404]).toContain(res.status);
    expect(res.raw).not.toContain('A-scope-B-conn');
  });
});
