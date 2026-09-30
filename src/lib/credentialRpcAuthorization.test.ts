import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * AWS-I3. Credential rollback must not be reachable by an unauthorised org
 * member through the Supabase RPC.
 *
 * THE ESCALATION. `rollback_aws_access_key` and `rotate_aws_access_key` are
 * SECURITY DEFINER and granted to `authenticated`. They guarded themselves
 * with `fn_is_org_member` -- ORG MEMBERSHIP -- while the API route that calls
 * them requires `cloud:write` plus a permitted-connection check, a rate limit
 * and an audit log. So a `viewer` or `billing_admin` could POST directly to
 * `/rest/v1/rpc/rollback_aws_access_key` and revert a credential rotation,
 * bypassing every one of those controls, with no secret material.
 *
 * The fix does NOT weaken the API to match the RPC. It raises the RPC to
 * match the API: both now require the same effective `cloud` menu level.
 *
 * WHERE THE SQL HALF OF THIS GUARD LIVES, AND WHY IT IS NOT HERE
 *
 * This file also read the migration itself, by the relative path
 * `..` + `/supabase/migrations/20260922160000_close_...sql`. That resolves on
 * a workstation holding every repository side by side, and resolves NOWHERE
 * in CI, which checks out connector-aws alone. The suite therefore failed
 * with ENOENT on every CI run while reporting green locally -- the worst
 * available failure ordering, because the signal arrives only after a push.
 * connector-aws vendors no SQL at all; the read was reaching across a
 * repository boundary for a file this repo does not own.
 *
 * The assertion was NOT dropped. It moved to the repository that owns the
 * migration -- `supabase`, `tests/credential_rpc_authorization.sql`, wired
 * into that repo's `Schema drift` workflow -- where it is also strictly
 * stronger: it exercises the DEPLOYED functions against a real database
 * instead of grepping a file that may never have been applied.
 *
 * What remains here is the half connector-aws genuinely owns: the API
 * route's four controls, asserted against this repo's own source.
 */
const ACCOUNTS = readFileSync('src/routes/accounts.ts', 'utf8');

/**
 * The API path is not weakened to accommodate the RPC -- it keeps every
 * control it had, and gains the one it was missing.
 */
describe('the API path keeps all four controls', () => {
  const route = ACCOUNTS.slice(
    ACCOUNTS.indexOf("accountsRoutes.post('/accounts/:id/credentials/rollback'"),
    ACCOUNTS.indexOf("accountsRoutes.put('/accounts/:id/role'"),
  );

  it('locates the rollback route at all', () => {
    // Without this the slice above could silently be '' and every assertion
    // below would fail for the wrong reason -- or, worse, a future `.includes`
    // style check would pass vacuously on an empty string.
    expect(route.length).toBeGreaterThan(0);
  });

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
    expect(workAt).toBeGreaterThan(-1);
    expect(authzAt).toBeLessThan(workAt);
  });
});

/**
 * The CLASS fix for the ENOENT described above, so the next fixture that
 * wants a file from a sibling repository fails here -- on a workstation,
 * where it is cheap -- instead of only in CI after a push.
 *
 * Scope is deliberately narrow: a bare string literal starting with `../` as
 * the first argument. That form is resolved against the process working
 * directory, which is this repository's root, so it can only mean "leave the
 * repo". A path built with `join(__dirname, ...)` is a different thing and is
 * not matched.
 */
describe('no test reaches outside this repository for a fixture', () => {
  const walk = (dir: string): string[] =>
    readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
      e.name === 'node_modules'
        ? []
        : e.isDirectory()
          ? walk(join(dir, e.name))
          : [join(dir, e.name)],
    );

  /** Comment lines stripped, so prose naming the old path cannot trip this. */
  const code = (src: string) =>
    src
      .split('\n')
      .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
      .join('\n');

  /**
   * The pattern captures the path literal without describing the separator,
   * and the classification happens in plain JavaScript afterwards.
   *
   * That split is deliberate. The first version of this guard expressed the
   * separator as a character class holding a backslash. One backslash was
   * lost on the way to disk, the class stopped closing, and the literal
   * silently became a regex that matched nothing -- so the guard reported a
   * clean repository while a cross-repo read sat two directories away. A
   * character comparison has no escaping layer left to lose. 47 and 92 are
   * '/' and the backslash, named by code for the same reason.
   */
  const escapingReads = (src: string) =>
    [...code(src).matchAll(/readFileSync\(\s*['"]([^'"]+)['"]/g)]
      .map((m) => m[1])
      .filter((p) => p.startsWith('..')
        && (p.length === 2 || p.charCodeAt(2) === 47 || p.charCodeAt(2) === 92));

  it('fires on a cross-repo read, so a dead pattern cannot read as a clean repo', () => {
    // Built by concatenation: spelled out in one piece, this sample would be
    // a cross-repo read in this very file and the guard would flag itself.
    const outside = 'readFileSync(' + JSON.stringify('../supabase/migrations/x.sql') + ')';
    const inside = 'readFileSync(' + JSON.stringify('src/routes/accounts.ts') + ')';
    expect(escapingReads(outside)).toEqual(['../supabase/migrations/x.sql']);
    expect(escapingReads(inside)).toEqual([]);
  });

  it('every readFileSync path literal resolves inside the repo', () => {
    const offenders: string[] = [];
    for (const file of walk('src').filter((f) => f.endsWith('.ts'))) {
      for (const p of escapingReads(readFileSync(file, 'utf8'))) {
        offenders.push(`${file} -> ${p}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('actually scanned the tree, rather than finding nothing because it walked nothing', () => {
    // A guard whose file list is empty passes forever. Pin that it sees this
    // very file, which is the one that introduced the problem.
    const files = walk('src').filter((f) => f.endsWith('.ts'));
    expect(files.length).toBeGreaterThan(50);
    expect(files.some((f) => f.endsWith('credentialRpcAuthorization.test.ts'))).toBe(true);
  });
});
