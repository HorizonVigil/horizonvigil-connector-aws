import { describe, expect, it } from 'vitest';

import { nextDueAt, nextDueAtHours, missedPeriods, SCHEDULER_JITTER_TOLERANCE_MS } from './scheduleCadence';

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

/**
 * These reproduce the exact production sequence that lost two of five daily
 * collections (see scheduleCadence.ts). The assertions are written against
 * real measured timestamps rather than round numbers so that a regression
 * reproduces the original defect rather than merely failing.
 */
describe('nextDueAt', () => {
  it('lands before the next cron slot so jitter cannot skip an interval', () => {
    // The 09-20 tick fired at 18:30:25.207 and set the next due time.
    const tick0920 = Date.parse('2026-09-20T18:30:25.207Z');
    const due = Date.parse(nextDueAt(DAY, tick0920));

    // The 09-21 tick fired 3.6 s EARLIER in its window. Under the old
    // `Date.now() + interval` rule this was "not yet due" and the whole day's
    // collection was silently skipped.
    const tick0921 = Date.parse('2026-09-21T18:30:22.265Z');
    expect(due).toBeLessThanOrEqual(tick0921);
  });

  it('absorbs the worst backwards jitter actually observed (33 s)', () => {
    // 09-17 fired at :36.136, 09-18 at :18.652 -- the widest backwards step in
    // the five days measured.
    const late = Date.parse('2026-09-17T18:30:36.136Z');
    const due = Date.parse(nextDueAt(DAY, late));
    const early = Date.parse('2026-09-18T18:30:18.652Z');

    expect(due).toBeLessThanOrEqual(early);
  });

  it('does not drift forward across repeated cycles', () => {
    // Re-anchoring each cycle must not accumulate: after many cycles the due
    // time should still sit one tolerance ahead of the slot, not N of them.
    let t = Date.parse('2026-09-01T18:30:30.000Z');
    for (let i = 0; i < 30; i += 1) {
      const due = Date.parse(nextDueAt(DAY, t));
      // Next tick fires at roughly the same slot the following day.
      t = due + SCHEDULER_JITTER_TOLERANCE_MS;
      expect(due).toBeLessThanOrEqual(t);
    }
    // Still anchored to the 18:30 slot a month later, not drifted into
    // another hour.
    expect(new Date(t).toISOString()).toContain('T18:30:');
  });

  it('shortens the interval by exactly the tolerance', () => {
    const now = Date.parse('2026-09-22T00:00:00.000Z');
    expect(Date.parse(nextDueAt(DAY, now))).toBe(now + DAY - SCHEDULER_JITTER_TOLERANCE_MS);
  });

  it('never returns a time in the past for a short interval', () => {
    // An interval at or below the tolerance would otherwise go backwards and
    // re-enqueue the row on every single tick.
    const now = Date.parse('2026-09-22T00:00:00.000Z');
    for (const interval of [0, 1000, SCHEDULER_JITTER_TOLERANCE_MS, SCHEDULER_JITTER_TOLERANCE_MS + 1]) {
      expect(Date.parse(nextDueAt(interval, now))).toBeGreaterThanOrEqual(now);
    }
  });

  it('cannot let a daily cron fire twice on one row', () => {
    // The tolerance must stay far below the cron cadence, or shortening the
    // interval would make a second same-day tick find the row due again.
    expect(SCHEDULER_JITTER_TOLERANCE_MS).toBeLessThan(DAY / 2);
  });

  it('nextDueAtHours matches the millisecond form', () => {
    const now = Date.parse('2026-09-22T00:00:00.000Z');
    expect(nextDueAtHours(24, now)).toBe(nextDueAt(DAY, now));
    expect(nextDueAtHours(7 * 24, now)).toBe(nextDueAt(7 * DAY, now));
  });

  it('returns an ISO string PostgREST can compare', () => {
    expect(nextDueAtHours(24, Date.parse('2026-09-22T00:00:00.000Z')))
      .toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  });
});

/**
 * The bug was not in one route -- all four scheduled paths carried the same
 * `Date.now() + interval` line. This pins that none of them reintroduces it.
 */
describe('no scheduled path re-anchors on Date.now()', () => {
  it('every next_* due write goes through the shared helper', async () => {
    const { readFileSync } = await import('node:fs');
    const files = [
      'src/routes/internalScan.ts',
      'src/routes/cost.ts',
      'src/routes/permissions.ts',
    ];

    for (const file of files) {
      const source = readFileSync(file, 'utf8');
      const dueWrites = source.match(/next_(scheduled_scan_at|scheduled_cost_sync_at|permission_check_at):\s*(\w+)/g) ?? [];
      expect(dueWrites.length, `${file} writes no due timestamp`).toBeGreaterThan(0);

      // The value assigned must come from the helper, not from a raw
      // `Date.now() + <interval>` expression. Matching any millisecond
      // arithmetic on Date.now() catches every spelling the four call sites
      // used (`* 60 * 60 * 1000`, `* 24 * 60 * 60 * 1000`, ...).
      expect(source, `${file} still computes a due time from Date.now()`)
        .not.toMatch(/new Date\(Date\.now\(\)\s*\+[^)]*1000\)/);
      expect(source, `${file} does not use the shared cadence helper`)
        .toContain('nextDueAtHours');
    }
  });
});

/**
 * Detection, not just prevention. The drift went unnoticed for days because a
 * skipped period left no trace: the connection still read `connected`, health
 * was unchanged, and only `last_sync_at` quietly fell behind.
 */
describe('missedPeriods', () => {
  const DAILY = DAY;
  const dueAt = (iso: string) => iso;

  it('is zero for a punctual run', () => {
    const due = nextDueAt(DAILY, Date.parse('2026-09-20T18:30:25Z'));
    // Next day's tick, at roughly the same slot.
    expect(missedPeriods(due, Date.parse('2026-09-21T18:30:22Z'), DAILY)).toBe(0);
  });

  it('is zero for a run that is merely early within the tolerance', () => {
    const due = nextDueAt(DAILY, Date.parse('2026-09-20T18:30:00Z'));
    expect(missedPeriods(due, Date.parse('2026-09-21T18:20:00Z'), DAILY)).toBe(0);
  });

  it('counts several consecutive lost periods', () => {
    // Due 09-15 and not run until 09-20: the 09-15..09-19 executions never
    // happened, and the 09-20 one is the run doing the counting.
    expect(missedPeriods(dueAt('2026-09-15T18:30:00Z'), Date.parse('2026-09-20T18:30:00Z'), DAILY)).toBe(5);
  });

  /**
   * Due times written before the tolerance shift sit exactly on the cron slot,
   * so a run one whole period late is late by `interval` minus a few seconds.
   * Flooring would read that as zero and hide the lost day -- which is the
   * precise state production is in right now.
   */
  it('counts a lost period against a pre-existing due time written by the old code', () => {
    expect(missedPeriods(dueAt('2026-09-21T18:30:25.878Z'), Date.parse('2026-09-22T18:30:20Z'), DAILY)).toBe(1);
  });

  it('does not report a missed period for a run that has not come due', () => {
    expect(missedPeriods(dueAt('2026-09-25T18:30:00Z'), Date.parse('2026-09-22T18:30:00Z'), DAILY)).toBe(0);
  });

  it('treats a never-scheduled connection as nothing missed', () => {
    // A brand-new connection has no previous period to have missed.
    expect(missedPeriods(null, Date.parse('2026-09-22T18:30:00Z'), DAILY)).toBe(0);
  });

  it('does not invent periods from an unparseable timestamp', () => {
    expect(missedPeriods('not-a-date', Date.parse('2026-09-22T18:30:00Z'), DAILY)).toBe(0);
  });

  it('is safe for a zero or negative interval', () => {
    expect(missedPeriods(dueAt('2026-09-01T00:00:00Z'), Date.parse('2026-09-22T00:00:00Z'), 0)).toBe(0);
    expect(missedPeriods(dueAt('2026-09-01T00:00:00Z'), Date.parse('2026-09-22T00:00:00Z'), -1)).toBe(0);
  });

  it('scales to a weekly interval', () => {
    const WEEK = 7 * DAY;
    expect(missedPeriods(dueAt('2026-09-01T00:00:00Z'), Date.parse('2026-09-22T00:00:00Z'), WEEK)).toBe(3);
  });
});

describe('the scan scheduler reports missed periods', () => {
  it('detects and surfaces them rather than letting a gap pass silently', async () => {
    const { readFileSync } = await import('node:fs');
    const source = readFileSync('src/routes/internalScan.ts', 'utf8');

    // It must READ the previous due time; without it, nothing can be detected.
    expect(source).toMatch(/select:\s*'[^']*next_scheduled_scan_at[^']*'/);
    expect(source).toContain('missedPeriods');
    // And report it, not merely compute it.
    expect(source).toContain('collection.schedule.missed_periods');
  });
});
