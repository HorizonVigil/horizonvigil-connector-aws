import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * §12.2 — the disconnect impact preview.
 *
 * Source-level assertions, matching the convention the other route guards in
 * this repo use (accountsScope.test.ts, lineageWritePath.test.ts). The
 * behaviour worth pinning is what the preview REFUSES to do, and each of
 * these would be an honesty regression rather than a crash.
 */
const src = readFileSync(join(__dirname, 'disconnectImpact.ts'), 'utf8');

describe('the preview keeps the two actions distinct', () => {
  it('reports disconnect as reversible and permanent delete as not', () => {
    // Collapsing them is the failure mode: a customer who thinks Disconnect
    // deletes their history will not use it, and one who thinks permanent
    // delete is reversible will lose everything.
    expect(src).toMatch(/disconnect:\s*\{\s*\n\s*reversible: true/);
    expect(src).toMatch(/permanentDelete:\s*\{\s*\n\s*reversible: false/);
  });

  it('states what disconnect retains, not only what it stops', () => {
    expect(src).toContain('retains:');
    expect(src).toContain('All audit and activity history');
  });
});

describe('the preview cannot overstate availability', () => {
  it('reads the purge gate live rather than hardcoding it', () => {
    // A preview claiming permanent delete is available while the server
    // returns 403 is the same false-capability problem in a new place.
    expect(src).toContain('available: isConnectionPurgeEnabled(c.env)');
    expect(src).not.toMatch(/available:\s*true/);
  });

  it('gives a reason when it is unavailable', () => {
    expect(src).toContain('unavailableReason');
  });
});

describe('the preview cannot understate the loss', () => {
  it('reports the full cascade breadth alongside the itemised list', () => {
    // Ten labelled tables out of 29 must not read as the whole story.
    expect(src).toContain('cascadeTableCount: 29');
  });

  it('distinguishes "could not count" from "none"', () => {
    /**
     * countRows returns null on failure, never 0. A table that failed to
     * count showing 0 would tell someone they are about to lose nothing.
     */
    expect(src).toContain('return null;');
    expect(src).toContain('uncountedTables');
    expect(src).toContain('countIsComplete');
  });

  it('surfaces the FKs that do NOT cascade', () => {
    /**
     * Verified against the live schema: incidents and verification_runs are
     * NO ACTION, so a permanent delete with rows in either FAILS on a
     * foreign-key violation rather than completing. Learning that from the
     * preview beats learning it from a database error.
     */
    expect(src).toContain("BLOCKING_TABLES");
    expect(src).toContain("'incidents'");
    expect(src).toContain("'verification_runs'");
    expect(src).toContain('wouldFail');
  });
});

describe('authorization', () => {
  it('authorizes the connection before reading anything about it', () => {
    const authIdx = src.indexOf('await requirePermittedConnection(');
    const readIdx = src.indexOf("db.select<{ aws_account_id");
    expect(authIdx).toBeGreaterThan(-1);
    expect(readIdx).toBeGreaterThan(authIdx);
  });

  it('scopes the permission check to the caller active scope', () => {
    expect(src).toContain('getActiveScope(c.req.raw, orgId)');
  });
});
