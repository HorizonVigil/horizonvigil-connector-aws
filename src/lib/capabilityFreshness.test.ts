import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

import { evaluateFreshness, DEFAULT_FRESHNESS_SLO_SECONDS } from './capabilityFreshness';

const HOUR = 3600;
const NOW = Date.parse('2026-09-22T00:00:00.000Z');
const ago = (seconds: number) => new Date(NOW - seconds * 1000).toISOString();

describe('evaluateFreshness', () => {
  /**
   * The exact production row. `billing_cost_explorer` on kamal-k8s read
   * `available` with last_success_at 2026-09-15 while scheduled cost sync had
   * been returning 503 since 09-16.
   */
  it('does not call a six-day-old success available', () => {
    const f = evaluateFreshness(
      { state: 'available', last_success_at: '2026-09-15T12:43:04.794Z', freshness_slo_seconds: 48 * HOUR },
      NOW,
    );

    expect(f.state).toBe('stale');
    expect(f.stale).toBe(true);
    expect(f.recordedState).toBe('available');
    // 09-15 12:43 -> 09-22 00:00 is 6d 11h; age is floored, never rounded up.
    expect(f.reason).toMatch(/6 days ago/);
    expect(f.reason).toMatch(/2 days/); // the SLO, stated
  });

  it('leaves a capability inside its SLO alone', () => {
    const f = evaluateFreshness(
      { state: 'available', last_success_at: ago(12 * HOUR), freshness_slo_seconds: 48 * HOUR },
      NOW,
    );
    expect(f.state).toBe('available');
    expect(f.stale).toBe(false);
    expect(f.reason).toBeNull();
  });

  it('treats the SLO boundary as still fresh', () => {
    const exactly = evaluateFreshness(
      { state: 'available', last_success_at: ago(48 * HOUR), freshness_slo_seconds: 48 * HOUR },
      NOW,
    );
    expect(exactly.stale).toBe(false);

    const oneSecondPast = evaluateFreshness(
      { state: 'available', last_success_at: ago(48 * HOUR + 1), freshness_slo_seconds: 48 * HOUR },
      NOW,
    );
    expect(oneSecondPast.stale).toBe(true);
  });

  /**
   * Recency must never rescue a negative verdict. `pavan-test1` carries
   * `failed / cost_explorer_probe_failed`; a fresh failure is still a failure,
   * and an old one must not be reported as anything better.
   */
  it('never upgrades a failed or not_enabled capability', () => {
    for (const state of ['failed', 'not_enabled', 'partial', 'unknown']) {
      const recent = evaluateFreshness({ state, last_success_at: ago(60), freshness_slo_seconds: 48 * HOUR }, NOW);
      expect(recent.state).toBe(state);
      expect(recent.stale).toBe(false);

      const ancient = evaluateFreshness({ state, last_success_at: ago(400 * 24 * HOUR) }, NOW);
      expect(ancient.state).toBe(state);
    }
  });

  it('refuses to pass through available with no recorded success', () => {
    // The verdict claims a proof the row does not carry.
    for (const last of [null, undefined, '', 'not-a-date']) {
      const f = evaluateFreshness({ state: 'available', last_success_at: last as string | null }, NOW);
      expect(f.state).toBe('stale');
      expect(f.stale).toBe(true);
      expect(f.ageSeconds).toBeNull();
      expect(f.reason).toMatch(/no successful check/i);
    }
  });

  it('falls back to the 48h default when the row carries no SLO', () => {
    const f = evaluateFreshness({ state: 'available', last_success_at: ago(50 * HOUR) }, NOW);
    expect(f.sloSeconds).toBe(DEFAULT_FRESHNESS_SLO_SECONDS);
    expect(f.stale).toBe(true);
  });

  it('clamps clock skew instead of letting it read as fresh', () => {
    // A success timestamped in the future must not age negatively and pass.
    const f = evaluateFreshness(
      { state: 'available', last_success_at: new Date(NOW + 10 * HOUR * 1000).toISOString(), freshness_slo_seconds: 48 * HOUR },
      NOW,
    );
    expect(f.ageSeconds).toBe(0);
    expect(f.stale).toBe(false);
  });

  it('reports age in units a person can act on', () => {
    expect(evaluateFreshness({ state: 'available', last_success_at: ago(3 * 24 * HOUR) }, NOW).reason).toMatch(/3 days/);
    expect(evaluateFreshness({ state: 'available', last_success_at: ago(1 * 24 * HOUR), freshness_slo_seconds: HOUR }, NOW).reason).toMatch(/1 day/);
    expect(evaluateFreshness({ state: 'available', last_success_at: ago(5 * HOUR), freshness_slo_seconds: HOUR }, NOW).reason).toMatch(/5 hours/);
  });

  it('leaks no account ids or provider text into the reason', () => {
    const f = evaluateFreshness({ state: 'available', last_success_at: ago(200 * HOUR) }, NOW);
    expect(f.reason).not.toMatch(/\d{12}/); // an AWS account id
    expect(f.reason).not.toMatch(/arn:|aws|kamal|pavan/i);
  });
});

describe('the capabilities endpoint applies it', () => {
  const source = readFileSync('src/routes/health.ts', 'utf8');

  it('evaluates freshness rather than returning the stored state', () => {
    expect(source).toContain('evaluateFreshness');
    // The raw rows must not be handed back under `items`; that was the bug.
    expect(source).not.toMatch(/items:\s*rows\s*,/);
  });

  it('selects the columns the evaluation needs', () => {
    // Without freshness_slo_seconds in the select, every row silently falls
    // back to the default and a custom SLO is ignored.
    expect(source).toMatch(/select:\s*'[^']*last_success_at[^']*'/);
    expect(source).toMatch(/select:\s*'[^']*freshness_slo_seconds[^']*'/);
  });
});
