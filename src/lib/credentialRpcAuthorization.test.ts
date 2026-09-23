import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

/**
 * AWS-I3. Credential rollback must not be reachable by an unauthorised org
 * member through the Supabase RPC.
 *
 * THE ESCALATION. `rollback_aws_access_key` and `rotate_aws_access_key` are
 * SECURITY DEFINER and granted to `authenticated`. They guarded themselves
 * with `fn_is_org_member` — ORG MEMBERSHIP — while the API route that calls
 * them requires `cloud:write` plus a permitted-connection check, a rate limit
 * and an audit log. So a `viewer` or `billing_admin` could POST directly to
 * `/rest/v1/rpc/rollback_aws_access_key` and revert a credential rotation,
 * bypassing every one of those controls, with no secret material.
 *
 * The fix does NOT weaken the API to match the RPC. It raises the RPC to
 * match the API: both now require the same effective `cloud` menu level.
 *
 * These are the source-level guards. The behavioural proof is a direct RPC
 * test against production, recorded in the migration header and in
 * V1/aws/AWS_V1_PRODUCTION_BASELINE_AUDIT.md — eight role/override
 * combinations, each run as the real user via `request.jwt.claims` inside a
 * rolled-back transaction.
 */
const MIGRATION = readFileSync(
  '../supabase/migrations/20260922160000_close_credential_rotation_rpc_escalation.sql',
  'utf8',
);
const ACCOUNTS = readFileSync('src/routes/accounts.ts', 'utf8');

describe('the RPCs require the same privilege the API requires', () => {
  it('rollback checks the effective cloud menu level, not just membership', () => {
    const fn = MIGRATION.slice(MIGRATION.indexOf('create or replace function public.rollback_aws_access_key'));
    expect(fn).toContain("fn_effective_menu_level(auth.uid(), v_org_id, 'cloud')");
    expect(fn).toMatch(/not in \('write', 'admin'\)/);
  });

  it('rotate checks it too — the sibling must not be the way around', () => {
    const fn = MIGRATION.slice(MIGRATION.indexOf('create or replace function public.rotate_aws_access_key'));
    expect(fn).toContain("fn_effective_menu_level(auth.uid(), p_org_id, 'cloud')");
    expect(fn).toMatch(/not in \('write', 'admin'\)/);
  });

  it('keeps the membership check as well, rather than replacing it', () => {
    // Membership is still necessary; it was simply never sufficient.
    expect(MIGRATION).toContain('fn_is_org_member(auth.uid()');
  });

  it('refuses a null auth.uid() — an unauthenticated caller is not a member', () => {
    expect(MIGRATION).toMatch(/auth\.uid\(\) is null or not public\.fn_is_org_member/);
  });

  it('fails closed with 42501, the authorization error code', () => {
    expect(MIGRATION).toMatch(/errcode = '42501'/);
  });
});

describe('the SECURITY DEFINER surface stays safe', () => {
  it('every function the migration defines pins search_path', () => {
    const defs = MIGRATION.match(/create or replace function[\s\S]*?language \w+/g) ?? [];
    expect(defs.length).toBeGreaterThanOrEqual(3);
    for (const d of defs) {
      const body = MIGRATION.slice(MIGRATION.indexOf(d));
      expect(body.slice(0, 600)).toMatch(/set search_path to 'public'/);
    }
  });

  /**
   * The helper answers questions about OTHER users' permissions. Reachable
   * over REST it would be an enumeration primitive, so it is executable only
   * by postgres and service_role — never by `authenticated` or `anon`.
   */
  it('the permission helper is not callable over the REST API', () => {
    expect(MIGRATION).toMatch(/revoke execute on function public\.fn_effective_menu_level\(uuid, uuid, text\) from authenticated/);
    expect(MIGRATION).toMatch(/revoke execute on function public\.fn_effective_menu_level\(uuid, uuid, text\) from anon/);
  });

  it('neither credential RPC is reachable anonymously', () => {
    expect(MIGRATION).toMatch(/revoke execute on function public\.rollback_aws_access_key\(uuid, uuid\) from anon/);
    expect(MIGRATION).toMatch(/revoke execute on function public\.rotate_aws_access_key\([^)]*\) from anon/);
  });

  /**
   * A CREATE OR REPLACE that changes a signature creates a NEW function
   * identity which inherits no grants or revokes — this schema has already
   * been bitten by that on the vulnerability RPCs. The signatures here are
   * unchanged, and the revokes are re-asserted rather than assumed.
   */
  it('re-asserts the revokes rather than assuming they survived', () => {
    const revokes = MIGRATION.match(/^revoke execute/gm) ?? [];
    expect(revokes.length).toBeGreaterThanOrEqual(6);
  });
});

/**
 * The API path is not weakened to accommodate the RPC — it keeps every
 * control it had, and gains the one it was missing.
 */
describe('the API path keeps all four controls', () => {
  const route = ACCOUNTS.slice(
    ACCOUNTS.indexOf("accountsRoutes.post('/accounts/:id/credentials/rollback'"),
    ACCOUNTS.indexOf("accountsRoutes.put('/accounts/:id/role'"),
  );

  it('requires cloud:write', () => {
    expect(route).toContain("requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write')");
  });

  it('requires the connection to be in the caller permitted set', () => {
    expect(route).toContain('requirePermittedConnection(');
  });

  it('writes an audit log entry naming the action', () => {
    expect(route).toContain("action: 'aws_account.credential_rollback'");
  });

  /**
   * Rollback had NO rate limit while rotation did. The audit described the
   * API as enforcing one here; it did not. Rollback SWAPS THE LIVE
   * CREDENTIAL, so an authorised but careless or malicious editor could flip
   * a connection between versions repeatedly, each flip a real write to
   * cloud_connections plus two to credential_versions.
   */
  it('rate limits, on the same budget as rotation', () => {
    expect(route).toContain('enforceRateLimit(db, `aws-account:rollback-credentials:${orgId}`, 30, 3600)');
  });

  it('runs authorization BEFORE doing any work', () => {
    const authzAt = route.indexOf('requireMenuPermission');
    const workAt = route.indexOf('rollbackToPrevious');
    expect(authzAt).toBeGreaterThan(-1);
    expect(authzAt).toBeLessThan(workAt);
  });
});
