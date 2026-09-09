import { describe, it, expect } from 'vitest';

/**
 * §14.4 on the one mutation where a lost update actually costs something:
 * updating a connection's configuration.
 *
 * The failure is quiet, which is why it needs a mechanism rather than care.
 * Two people open this connection's settings; one changes the scan regions,
 * the other the schedule; the second save overwrites the first with a
 * payload built from stale data. Nothing errors, nothing is logged, and the
 * first person finds their change missing days later and reasonably
 * concludes the product lost it.
 *
 * Source-level assertions, the same technique the other route tests here
 * use — the alternative is standing up auth, RBAC, ABAC and PostgREST to
 * observe one header being compared.
 */
const sources = import.meta.glob(['./accounts.ts'], {
  query: '?raw',
  import: 'default',
  eager: true,
}) as Record<string, string>;

function source(endsWith: string): string {
  const hit = Object.entries(sources).find(([path]) => path.endsWith(endsWith));
  expect(hit, `source not found for ${endsWith}`).toBeTruthy();
  return hit![1];
}

function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('the connection update carries an optimistic-concurrency check', () => {
  const accounts = code(source('/accounts.ts'));

  it('computes an ETag from the row it just read', () => {
    expect(accounts).toMatch(/strongEtag\(versionParts\(existing\)\)/);
  });

  it('checks If-Match before applying the patch', () => {
    const update = accounts.slice(accounts.indexOf("put('/accounts/:id'"));
    const precondition = update.indexOf('requirePrecondition');
    const patchBuild = update.indexOf('const patch');
    expect(precondition).toBeGreaterThan(-1);
    // Ordering matters: a check that runs after the write is not a check.
    expect(precondition).toBeLessThan(patchBuild);
  });

  it('returns the NEW ETag so a client can chain an edit without re-reading', () => {
    expect(accounts).toMatch(/ETag: newEtag/);
  });

  it('does not require If-Match yet, so the existing client keeps working', () => {
    // Enforcement lands once clients send it. Rolling it out as mandatory
    // in one step would break every current caller, and a broken update
    // path is worse than the lost update it prevents.
    expect(accounts).toMatch(/\{ required: false \}/);
  });

  it('still rejects a STALE If-Match even while the header is optional', () => {
    // The important half. Opting out of the REQUIREMENT must not opt out of
    // the CHECK -- otherwise a client that adopted the header early gets no
    // protection from it. requirePrecondition enforces this; asserted here
    // so the call site cannot be changed to skip validation entirely.
    expect(accounts).toMatch(/requirePrecondition\(c\.req\.header\('If-Match'\), etag/);
  });
});
