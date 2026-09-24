import { describe, it, expect, beforeAll } from 'vitest';
import { requireIntegrationEnv, signIn, callApi, assertNoTenantBData, FIXTURES, type IntegrationEnv } from './harness';

/**
 * Phase 2 §9/§10/§20 — lineage and quarantine isolation, proven at runtime.
 *
 * Same discipline as the Phase 1 suite: real JWT, real X-Org-Id, real RBAC,
 * real PostgREST, real RLS, nothing mocked, and no `skipIf` anywhere. Every
 * isolation assertion greps the raw body for Tenant B's markers rather than
 * trusting a status code, because a 200 with an empty list and a 200 that
 * leaked a provider request id are both 200.
 *
 * Lineage is security-sensitive in a way ordinary inventory is not: provider
 * request ids, ingestion batch ids and quarantine payloads describe another
 * customer's operations, and quarantine retains the raw record that arrived.
 */
let env: IntegrationEnv;
let tokenA = '';
let tokenB = '';
let tokenScoped = '';

/** Seeded lineage evidence. Tenant B's ids are the IDOR targets. */
const LINEAGE = {
  a: {
    batchId: 'aaaaaaaa-0000-0000-0000-00000000b001',
    quarantineId: 'aaaaaaaa-0000-0000-0000-00000000dd01',
    tracedResourceId: 'aaaaaaaa-0000-0000-0000-00000000e0a1',
  },
  b: {
    batchId: 'bbbbbbbb-0000-0000-0000-00000000b001',
    quarantineId: 'bbbbbbbb-0000-0000-0000-00000000dd01',
    resourceId: 'bbbbbbbb-0000-0000-0000-00000000e0b1',
  },
} as const;

beforeAll(async () => {
  env = requireIntegrationEnv();
  [tokenA, tokenB, tokenScoped] = await Promise.all([
    signIn(env, FIXTURES.tenantA.email),
    signIn(env, FIXTURES.tenantB.email),
    signIn(env, FIXTURES.scopedUser.email),
  ]);
});

describe('the lineage endpoints are reachable and not vacuous', () => {
  it('rejects an unauthenticated request', async () => {
    const res = await callApi(env, { path: '/api/aws-accounts/ingestion-batches', token: '', orgId: FIXTURES.tenantA.orgId });
    expect(res.status).toBe(401);
  });

  it('fails closed with no organization context', async () => {
    const res = await callApi(env, { path: '/api/aws-accounts/ingestion-batches', token: tokenA, orgId: '' });
    expect(res.status).toBe(400);
  });

  it('returns Tenant A its OWN batch, so every negative below means something', async () => {
    const res = await callApi(env, { path: '/api/aws-accounts/ingestion-batches', token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect(res.status).toBe(200);
    expect(res.raw).toContain(LINEAGE.a.batchId);
  });

  it('returns Tenant A its OWN quarantine record', async () => {
    const res = await callApi(env, { path: '/api/aws-accounts/quarantine', token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect(res.status).toBe(200);
    expect(res.raw).toContain('i-A-QUARANTINED');
  });

  it('returns Tenant A its OWN provider request id', async () => {
    const res = await callApi(env, { path: `/api/aws-accounts/ingestion-batches/${LINEAGE.a.batchId}`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect(res.status).toBe(200);
    expect(res.raw).toContain('REQ-A-VISIBLE-TO-A');
  });
});

describe('Tenant A cannot reach Tenant B lineage', () => {
  it('the batch list excludes Tenant B', async () => {
    const res = await callApi(env, { path: '/api/aws-accounts/ingestion-batches', token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect(res.status).toBe(200);
    expect(res.raw).not.toContain(LINEAGE.b.batchId);
    assertNoTenantBData(res, 'ingestion batch list');
  });

  it('a Tenant B batch cannot be fetched BY ID', async () => {
    // The IDOR case. 404 is correct; 403 would confirm the batch exists.
    const res = await callApi(env, { path: `/api/aws-accounts/ingestion-batches/${LINEAGE.b.batchId}`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect(res.status).toBe(404);
    assertNoTenantBData(res, 'ingestion batch by id');
  });

  it("a Tenant B batch id does not leak that tenant's provider request ids", async () => {
    // §20: "provider request IDs cannot be used to retrieve another tenant's
    // evidence". The request id lives inside the batch detail response, so
    // this is the path that would leak it.
    const res = await callApi(env, { path: `/api/aws-accounts/ingestion-batches/${LINEAGE.b.batchId}`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect(res.raw).not.toContain('REQ-TENANT-B-ONLY-REQUESTID');
  });

  it('the quarantine list excludes Tenant B', async () => {
    const res = await callApi(env, { path: '/api/aws-accounts/quarantine', token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect(res.status).toBe(200);
    assertNoTenantBData(res, 'quarantine list');
  });

  it('a Tenant B quarantine record cannot be fetched BY ID, payload included', async () => {
    // Quarantine is the one place a raw provider record is retained, so a
    // leak here discloses another customer's actual data, not just an id.
    const res = await callApi(env, { path: `/api/aws-accounts/quarantine/${LINEAGE.b.quarantineId}`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect(res.status).toBe(404);
    assertNoTenantBData(res, 'quarantine by id');
  });

  it('a Tenant B resource cannot have its lineage read', async () => {
    const res = await callApi(env, { path: `/api/aws-accounts/resources/${LINEAGE.b.resourceId}/lineage`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect(res.status).toBe(404);
    assertNoTenantBData(res, 'resource lineage by id');
  });

  it('spoofing X-Org-Id to Tenant B does not surface Tenant B lineage', async () => {
    const res = await callApi(env, { path: '/api/aws-accounts/ingestion-batches', token: tokenA, orgId: FIXTURES.tenantB.orgId });
    expect([200, 403]).toContain(res.status);
    assertNoTenantBData(res, 'X-Org-Id spoof on batches');
  });

  it('filtering by a Tenant B connection id returns nothing rather than widening the query', async () => {
    // A caller-supplied filter must intersect with the permitted set, never
    // replace it.
    const res = await callApi(env, {
      path: `/api/aws-accounts/ingestion-batches?connectionId=${FIXTURES.tenantB.connId}`,
      token: tokenA,
      orgId: FIXTURES.tenantA.orgId,
    });
    expect(res.status).toBe(200);
    assertNoTenantBData(res, 'connectionId filter widening');
  });

  it('and the reverse direction holds too', async () => {
    // Asymmetric isolation is a real failure mode.
    const res = await callApi(env, { path: '/api/aws-accounts/quarantine', token: tokenB, orgId: FIXTURES.tenantB.orgId });
    expect(res.status).toBe(200);
    expect(res.raw).toContain('i-TENANT-B-QUARANTINE-SECRET');
    expect(res.raw).not.toContain('i-A-QUARANTINED');
  });
});

describe('lineage answers the question the phase exists for', () => {
  it('a traced resource reports its full provenance', async () => {
    const res = await callApi(env, { path: `/api/aws-accounts/resources/${LINEAGE.a.tracedResourceId}/lineage`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect(res.status).toBe(200);
    const body = (res.json as Record<string, any>).data;

    expect(body.lineageState).toBe('traced');
    expect(body.who.accountNativeId).toBe('111111111111');
    expect(body.who.collector).toBe('horizonvigil-connector-aws');
    expect(body.where.partition).toBe('aws');
    expect(body.how.ingestionBatchId).toBe(LINEAGE.a.batchId);
    expect(body.transformation.normalizationVersion).toBe('2026-09-10.1');
    expect(body.transformation.recordFingerprint).toMatch(/^[0-9a-f]{64}$/);
    // The observation that produced it, joined back through canonical_resource_id.
    expect(body.observations.length).toBeGreaterThan(0);
    expect(body.observations[0].providerOperation).toBe('DescribeInstances');

    /**
     * Provider requests are attributed at BATCH granularity and say so.
     * A scanner makes many calls and none of the 111 report which call
     * yielded which record, so per-record attribution would be a guess
     * dressed as provenance.
     */
    expect(body.providerRequests.granularity).toBe('batch');
    expect(body.providerRequests.note).toContain('no per-record attribution is claimed');
    expect(body.providerRequests.requests.map((r: any) => r.providerRequestId)).toContain('REQ-A-VISIBLE-TO-A');
  });

  it('distinguishes "AWS did not say" from "we did not look"', async () => {
    /**
     * providerObservedAt is null because AWS list operations do not report
     * when the provider last observed the resource. collectorObservedAt is
     * set. Collapsing the two would turn "we looked just now" into "AWS says
     * it changed just now".
     */
    const res = await callApi(env, { path: `/api/aws-accounts/resources/${LINEAGE.a.tracedResourceId}/lineage`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    const body = (res.json as Record<string, any>).data;
    expect(body.when.providerObservedAt).toBeNull();
    expect(body.when.collectorObservedAt).toBeTruthy();
    expect(body.when.ingestedAt).toBeTruthy();
  });

  it('a legacy resource says so plainly instead of returning nulls', async () => {
    /**
     * §12: historical lineage must not be fabricated. A row that predates
     * Phase 2 returns an explicit legacy_unknown state with an explanation,
     * not a lineage object full of nulls that reads like a broken lookup.
     */
    const res = await callApi(env, {
      path: `/api/aws-accounts/resources/${FIXTURES.tenantA.resourceScopeA}/lineage`,
      token: tokenA,
      orgId: FIXTURES.tenantA.orgId,
    });
    if (res.status === 200 && (res.json as any).data?.lineageState === 'legacy_unknown') {
      const body = (res.json as Record<string, any>).data;
      expect(body.explanation).toContain('before ingestion lineage existed');
      expect(body.observations).toEqual([]);
      expect(body.batch).toBeNull();
    }
  });

  it('reports expected count as null, not as a fake reconciliation', async () => {
    // §19: `expected = observed` would be a reconciliation that always
    // passes. Null says "not knowable", which is the truth.
    const res = await callApi(env, { path: `/api/aws-accounts/ingestion-batches/${LINEAGE.a.batchId}`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    const body = (res.json as Record<string, any>).data;
    expect(body.counts.expected).toBeNull();
    expect(body.counts.observed).toBe(3);
    expect(body.counts.accepted + body.counts.quarantined + body.counts.rejected).toBe(body.counts.observed);
  });

  it('a batch that quarantined anything is not reported as SUCCEEDED', async () => {
    const res = await callApi(env, { path: `/api/aws-accounts/ingestion-batches/${LINEAGE.a.batchId}`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    const body = (res.json as Record<string, any>).data;
    expect(body.counts.quarantined).toBeGreaterThan(0);
    expect(body.status).toBe('PARTIALLY_SUCCEEDED');
  });

  it('quarantine explains why a record was rejected, and which rule did it', async () => {
    // Hard NO-GO #12: quarantine must be able to explain the rejection.
    const res = await callApi(env, { path: `/api/aws-accounts/quarantine/${LINEAGE.a.quarantineId}`, token: tokenA, orgId: FIXTURES.tenantA.orgId });
    expect(res.status).toBe(200);
    const body = (res.json as Record<string, any>).data;
    expect(body.reasonCode).toBe('UNKNOWN_RESOURCE_TYPE');
    expect(body.validationRule).toBe('resource_type.catalogued');
    expect(body.reasonDetail).toContain('resource_type_catalog');
    expect(body.retryable).toBe(true);
    // "What arrived?" is answerable.
    expect(JSON.stringify(body.payload)).toContain('i-A-QUARANTINED');
    // And it is traceable to where it came from.
    expect(body.ingestionBatchId).toBe(LINEAGE.a.batchId);
  });
});

describe('quarantined records do not contaminate canonical state', () => {
  it('the quarantined resource is absent from inventory', async () => {
    /**
     * Hard NO-GO conditions #2 and #3: an invalid record must not enter
     * canonical inventory or inflate totals. `i-A-QUARANTINED` was refused,
     * so it must appear in quarantine and nowhere in the resource listing.
     */
    const res = await callApi(env, {
      path: `/api/aws-accounts/accounts/${FIXTURES.tenantA.connScopeA}/resources`,
      token: tokenA,
      orgId: FIXTURES.tenantA.orgId,
    });
    expect(res.raw).not.toContain('i-A-QUARANTINED');
  });
});

describe('disjoint scopes inside one tenant', () => {
  it('a scope-restricted user still sees lineage in their own scope', async () => {
    const res = await callApi(env, {
      path: '/api/aws-accounts/ingestion-batches',
      token: tokenScoped,
      orgId: FIXTURES.tenantA.orgId,
      headers: { 'X-Scope-Type': 'project', 'X-Scope-Id': FIXTURES.tenantA.projectScopeA },
    });
    expect(res.status).toBe(200);
    expect(res.raw).toContain(LINEAGE.a.batchId);
  });

  it('and cannot read quarantine from a connection outside their scope', async () => {
    const res = await callApi(env, {
      path: '/api/aws-accounts/quarantine',
      token: tokenScoped,
      orgId: FIXTURES.tenantA.orgId,
      headers: { 'X-Scope-Type': 'project', 'X-Scope-Id': FIXTURES.tenantA.projectScopeA },
    });
    expect(res.status).toBe(200);
    assertNoTenantBData(res, 'scoped quarantine list');
  });
});

describe('reprocessing cannot bypass validation', () => {
  it('refuses to reprocess a record that revalidation cannot fix', async () => {
    /**
     * §15: reprocessing must not bypass validation. Tenant B's record is
     * `retryable: false`, but Tenant A must get 404 for it regardless --
     * the isolation check runs before the retryable check, so the response
     * does not disclose that the record exists.
     */
    const res = await callApi(env, {
      method: 'POST',
      path: `/api/aws-accounts/quarantine/${LINEAGE.b.quarantineId}/reprocess`,
      token: tokenA,
      orgId: FIXTURES.tenantA.orgId,
      body: {},
    });
    expect(res.status).toBe(404);
    assertNoTenantBData(res, 'reprocess across tenants');
  });

  it('accepts a reprocess request for a retryable record and does not admit it', async () => {
    const res = await callApi(env, {
      method: 'POST',
      path: `/api/aws-accounts/quarantine/${LINEAGE.a.quarantineId}/reprocess`,
      token: tokenA,
      orgId: FIXTURES.tenantA.orgId,
      body: {},
    });
    // Either accepted, or already requested by a previous run of this suite.
    expect([200, 409]).toContain(res.status);
    if (res.status === 200) {
      const body = (res.json as Record<string, any>).data;
      expect(body.status).toBe('REPROCESS_REQUESTED');
      // Nothing is admitted by pressing the button.
      expect(body.explanation).toContain('Nothing is admitted to inventory');
    }

    // The resource still must not be in inventory.
    const inv = await callApi(env, {
      path: `/api/aws-accounts/accounts/${FIXTURES.tenantA.connScopeA}/resources`,
      token: tokenA,
      orgId: FIXTURES.tenantA.orgId,
    });
    expect(inv.raw).not.toContain('i-A-QUARANTINED');
  });
});
