import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

/**
 * AWS-01 / Blocker 5 — one failing section must not blank the dashboard.
 *
 * Six independent reads sat behind a single `Promise.all`, so any one failure
 * returned 400 for the whole endpoint. That is the same defect already fixed
 * in CloudSecurity.tsx and on the account page (AWS-P1-06), left in place
 * here.
 *
 * It is also why a tenant-isolation assertion went vacuous: the integration
 * suite's anti-vacuity guard has failed 30 consecutive runs because this
 * endpoint answers 400 there, so the dashboard returns nothing for EVERY
 * tenant and "the totals exclude Tenant B" passes without ever having been
 * capable of failing.
 *
 * Source-level because the route's value comes from its live PostgREST
 * queries; the behaviour worth pinning is the composition, which is readable
 * here without standing up a database.
 */
const SOURCE = readFileSync('src/routes/dashboard.ts', 'utf8');

describe('the AWS dashboard degrades section by section', () => {
  it('does not put its six reads behind a single Promise.all', () => {
    expect(SOURCE).toContain('Promise.allSettled');
    // The specific construct that made one failure fatal for all six.
    expect(SOURCE).not.toMatch(/=\s*await Promise\.all\(\[/);
  });

  it('names the sections it could not read', () => {
    expect(SOURCE).toContain('unavailableSections');
    expect(SOURCE).toMatch(/SECTION_NAMES/);
  });

  it('states completeness explicitly rather than leaving it inferred', () => {
    // A client cannot tell an empty section from a failed one without this.
    expect(SOURCE).toMatch(/complete:\s*unavailable\.length === 0/);
  });

  it('keeps one section name per read, so the report cannot misattribute', () => {
    const names = /const SECTION_NAMES = \[([^\]]*)\]/.exec(SOURCE)?.[1] ?? '';
    const count = names.split(',').filter((s) => s.trim().length > 0).length;
    expect(count).toBe(6);
  });

  it('falls back to an empty shape rather than undefined', () => {
    // A rejected section must yield something the downstream loops can read;
    // undefined would turn a degraded dashboard into a 500.
    expect(SOURCE).toMatch(/valueOf<[^>]*>\(\d+,\s*\[\]\)/);
  });

  it('does not leak the rejection reason into the response', () => {
    // Rejections carry sanitized DB text; a section NAME is what a caller can
    // act on, and it cannot leak schema details.
    expect(SOURCE).not.toMatch(/unavailable\.push\([^)]*\.reason/);
  });
});
