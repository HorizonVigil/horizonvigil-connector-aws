import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The account list and account detail routes must read the PERMITTED set, not
 * the org.
 *
 * Filtering `cloud_connections` on `org_id` alone made these two endpoints
 * bypass both controls that are supposed to bound them:
 *
 *  - resource grants (Phase 0.7) -- a user with no grants gets no connections
 *    from getOrgConnectionIds, yet still saw every account in the org here,
 *    and could fetch any one of them by id;
 *  - the active folder/project scope (Phase 1) -- selecting a folder left the
 *    full global account list on screen, which is one of the exact symptoms
 *    the 2026-09-08 production-readiness audits reported.
 *
 * Asserted at source level because these are Hono route handlers whose real
 * behaviour needs the whole PostgREST/auth stack to observe; the same
 * technique the frontend uses in v2Isolation.test.ts. What matters is that the
 * permitted-set filter cannot be quietly dropped without a test failing.
 */
const src = readFileSync(join(__dirname, 'accounts.ts'), 'utf8')
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/^\s*\/\/.*$/gm, '');

describe('GET /accounts is bounded by the permitted connection set', () => {
  it('resolves the permitted ids from grants + active scope', () => {
    expect(src).toMatch(/getOrgConnectionIds\(db, orgId, auth\.userId, getActiveScope\(c\.req\.raw, orgId\)\)/);
  });

  it('filters the listing on those ids, not org_id alone', () => {
    expect(src).toMatch(/id: inFilter\(permittedIds\)/);
  });

  it('never lists cloud_connections on org_id + provider alone', () => {
    // The exact shape of the original defect.
    expect(src).not.toMatch(/filters: Record<string, string> = \{ org_id: `eq\.\$\{orgId\}`, provider:/);
  });
});

describe('GET /accounts/:id is bounded by the permitted connection set', () => {
  it('rejects an id outside the permitted set before reading it', () => {
    expect(src).toMatch(/if \(!permittedIds\.includes\(id\)\) return errJson\(404, 'Account not found'\)/);
  });

  it('answers 404, not 403, so the response does not confirm the id exists', () => {
    const detail = src.slice(src.indexOf("accountsRoutes.get('/accounts/:id'"));
    expect(detail).not.toMatch(/errJson\(403/);
  });
});
