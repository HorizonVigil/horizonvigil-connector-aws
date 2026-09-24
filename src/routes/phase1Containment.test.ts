import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { isAssumeRoleEnabled } from '../lib/capabilities';

/**
 * Phase 1 containment, 2026-09-08 AWS connector audit.
 *
 * AWS-P0-02: cross-account role was default-selected, badged "Recommended"
 * and submittable, on a screen that admitted live sts:AssumeRole scanning was
 * not wired up.
 *
 * AWS-P0-03: a duplicate create was converted into a credential rotation --
 * the client matched the raw unique-constraint name and called
 * updateAccountCredentials/updateAccountRole, so a second "Add account"
 * submit silently replaced an existing connection's credentials.
 */
/** Comments are stripped so a doc comment naming the old constraint isn't mistaken for the code still using it. */
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

const accounts = readFileSync(join(__dirname, 'accounts.ts'), 'utf8');
const accountsCode = code(accounts);
const bulk = readFileSync(join(__dirname, 'bulkImport.ts'), 'utf8');

describe('AssumeRole gate is fail-closed', () => {
  it('is off unless the flag is exactly "true"', () => {
    expect(isAssumeRoleEnabled({})).toBe(false);
    expect(isAssumeRoleEnabled({ ASSUME_ROLE_ENABLED: 'TRUE' })).toBe(false);
    expect(isAssumeRoleEnabled({ ASSUME_ROLE_ENABLED: '1' })).toBe(false);
    expect(isAssumeRoleEnabled(null)).toBe(false);
    expect(isAssumeRoleEnabled({ ASSUME_ROLE_ENABLED: 'true' })).toBe(true);
  });

  it('refuses to CREATE a cross-account-role connection', () => {
    // Gating only the wizard would leave the endpoint callable, so a customer
    // could still be onboarded into a connection that can never collect.
    expect(accounts).toMatch(/body\.connectionMethod === 'cross_account_role' && !isAssumeRoleEnabled\(c\.env\)/);
  });

  it('refuses to UPDATE an existing connection into that method', () => {
    const roleRoute = accounts.slice(accounts.indexOf("accountsRoutes.put('/accounts/:id/role'"));
    expect(roleRoute).toMatch(/if \(!isAssumeRoleEnabled\(c\.env\)\) return assumeRoleDisabledResponse\(\)/);
  });

  it('refuses bulk onboarding, which depends on the same path', () => {
    expect(bulk).toMatch(/if \(!isAssumeRoleEnabled\(c\.env\)\) return assumeRoleDisabledResponse\(\)/);
  });
});

describe('duplicate create is a conflict, never a credential rotation', () => {
  it('checks for an existing connection before inserting', () => {
    expect(accounts).toMatch(/const existingRows = await db\.select[\s\S]{0,200}aws_account_id: `eq\.\$\{body\.awsAccountId\}`/);
  });

  it('returns 409 with a stable machine code', () => {
    expect(accounts).toMatch(/code: 'connection_already_exists'/);
    expect(accounts).toMatch(/\},\s*409,\s*\)/);
  });

  it('names the existing connection so the client can link to it', () => {
    expect(accounts).toMatch(/existingConnection: \{ id: existing\.id, name: existing\.connection_name, status: existing\.status \}/);
  });

  it('distinguishes a disconnected connection, which still holds the unique key', () => {
    // Disconnect is a soft status flip, so "already connected" would be wrong
    // and confusing for a connection the user deliberately disconnected.
    expect(accounts).toMatch(/existing\.status === 'disconnected'/);
  });

  it('never leaks the raw constraint name that the client used to parse', () => {
    // The name may appear in a comment explaining the old bug; what must not
    // exist is code that emits or depends on it.
    expect(accountsCode).not.toMatch(/cloud_connections_org_id_aws_account_id_key/);
  });
});
