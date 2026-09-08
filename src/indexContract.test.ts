import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * API contract invariants (connector spec §23).
 *
 * Asserted at source level because these are Hono mount statements whose real
 * behaviour needs the whole auth/PostgREST stack to observe — the same
 * technique the frontend uses in v2Isolation.test.ts. What matters is that
 * the versioned prefix cannot silently diverge from the legacy one, and that
 * the V1 mutation gate cannot be bypassed by calling the new URL.
 */
const src = readFileSync(join(__dirname, 'index.ts'), 'utf8');

function mountedUnder(prefix: string): string[] {
  return [...src.matchAll(new RegExp(`app\\.route\\('${prefix.replace('/', '\\/')}', (\\w+)\\);`, 'g'))].map((m) => m[1]);
}

describe('versioned API alias', () => {
  it('exposes every legacy route group under /api/v1/aws as well', () => {
    // A versioned prefix that covers only some routes is worse than none: it
    // makes the new contract look complete while quietly missing endpoints.
    const legacy = mountedUnder('/api/aws-accounts');
    const versioned = mountedUnder('/api/v1/aws');
    expect(legacy.length).toBeGreaterThan(15);
    for (const group of legacy) {
      expect(versioned, `${group} is missing from /api/v1/aws`).toContain(group);
    }
  });

  it('keeps the legacy prefix, which 25 frontend call sites and 4 scheduler jobs use', () => {
    expect(mountedUnder('/api/aws-accounts').length).toBeGreaterThan(15);
  });

  it('mounts the same route objects rather than a second implementation', () => {
    // Two implementations would drift; one object mounted twice cannot.
    const versioned = mountedUnder('/api/v1/aws');
    expect(new Set(versioned).size).toBe(versioned.length);
  });
});

describe('V1 provider-mutation gate', () => {
  it('gates remediation on BOTH prefixes', () => {
    // The gate is the control that keeps "no direct provider mutation ships
    // in V1" true. Adding a new URL to the same handlers without re-applying
    // it would have re-opened the capability through the back door.
    for (const path of ['/api/aws-accounts/remediation', '/api/aws-accounts/remediation/*', '/api/v1/aws/remediation', '/api/v1/aws/remediation/*']) {
      expect(src, `${path} is not gated`).toContain(`app.use('${path}'`);
    }
  });

  it('denies before any handler runs', () => {
    const gateCount = [...src.matchAll(/if \(!isProviderRemediationEnabled\(c\.env\)\) return remediationDisabledResponse\(\);/g)].length;
    expect(gateCount).toBe(4);
  });
});

describe('capability registry endpoint', () => {
  it('is mounted on both prefixes', () => {
    expect(mountedUnder('/api/aws-accounts')).toContain('capabilityRoutes');
    expect(mountedUnder('/api/v1/aws')).toContain('capabilityRoutes');
  });
});
