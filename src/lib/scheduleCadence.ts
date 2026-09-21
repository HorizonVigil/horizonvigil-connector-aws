/**
 * When a periodic job becomes due again.
 *
 * THE DEFECT THIS EXISTS TO FIX (observed in production, 2026-09-22)
 *
 * Every scheduled path advanced its own due time with `Date.now() + interval`,
 * where `now` is the moment the worker HAPPENED to process the row. Cloud
 * Scheduler does not fire at an exact instant -- it fires within a window, and
 * the offset within that window varies from tick to tick. So the due time
 * inherited the previous tick's jitter, and the next tick only collected if it
 * fired LATER within its window than the previous one did.
 *
 * Any tick that fired earlier than its predecessor found the row "not yet due"
 * and skipped it for a whole interval. Measured on `scheduled-scan-aws`, whose
 * cron slot is 18:30 daily:
 *
 *   09-17  tick 18:30:36  ->  ran, set next due 09-18 18:30:36
 *   09-18  tick 18:30:18  ->  18 s early, NOT due  -> whole day skipped
 *   09-19  tick 18:30:03  ->  ran, set next due 09-20 18:30:03
 *   09-20  tick 18:30:25  ->  ran, set next due 09-21 18:30:25
 *   09-21  tick 18:30:22  ->  3.6 s early, NOT due -> whole day skipped
 *
 * Two of five consecutive daily collections were silently lost. Nothing
 * surfaced it: the connection still read `connected`, its health was unchanged,
 * and the only visible trace was `last_sync_at` quietly falling a day behind.
 * A skipped weekly permission check (same pattern, see routes/permissions.ts)
 * costs a full week.
 *
 * THE FIX
 *
 * Make the stored due time land slightly BEFORE the next cron slot, so any
 * plausible jitter still finds it due. The tolerance is subtracted from the
 * interval rather than added to the comparison because the comparison lives in
 * a PostgREST filter, where it would have to be duplicated at every call site.
 *
 * This does not drift: each cycle re-anchors to the tick that actually ran, so
 * the stored time stays a fixed tolerance ahead of the slot instead of
 * accumulating.
 *
 * WHY THIS CANNOT CAUSE A DOUBLE RUN
 *
 * The bound on how often a job runs is the cron cadence, not this value. The
 * shortest cron here is daily, so shortening a 24h interval by 15 minutes
 * cannot make two ticks both find the same row due. Collection has a second,
 * independent guard regardless: `createOrGetActiveRun` is idempotent against
 * the partial unique index on active runs (AWS-06), so even a duplicate
 * enqueue resolves to the same run rather than a second one.
 */

/**
 * How far ahead of the true interval a row is marked due again.
 *
 * Fifteen minutes: comfortably above the ~33 s of jitter observed across five
 * consecutive days, and far below the shortest interval any caller uses (24h),
 * so it changes which tick collects a row and never how many do.
 */
export const SCHEDULER_JITTER_TOLERANCE_MS = 15 * 60 * 1000;

/**
 * The next due timestamp for a job that just ran, as an ISO string.
 *
 * @param intervalMs Nominal spacing between runs.
 * @param now        Injectable for tests; defaults to the current time.
 */
export function nextDueAt(intervalMs: number, now: number = Date.now()): string {
  /*
   * An interval at or below the tolerance would otherwise produce a due time
   * in the past, which re-enqueues the row on every tick forever. Such an
   * interval is already shorter than any cron here fires, so the tick cadence
   * governs it completely and no tolerance is needed.
   */
  const adjusted = intervalMs > SCHEDULER_JITTER_TOLERANCE_MS
    ? intervalMs - SCHEDULER_JITTER_TOLERANCE_MS
    : intervalMs;

  return new Date(now + adjusted).toISOString();
}

/** Convenience for the many callers that hold an interval in hours. */
export function nextDueAtHours(intervalHours: number, now: number = Date.now()): string {
  return nextDueAt(intervalHours * 60 * 60 * 1000, now);
}

/**
 * How many whole intervals elapsed between when a job was due and when it
 * actually ran.
 *
 * Preventing the drift above is necessary but not sufficient. The defect went
 * unnoticed for days because a skipped period left no trace anywhere: the
 * connection still read `connected`, health was unchanged, and the only symptom
 * was `last_sync_at` quietly falling behind. Whatever the cause next time -- a
 * scheduler outage, a deploy window, a quota denial, a paused job -- the gap
 * itself has to be visible.
 *
 * 0 means it ran in the period it was due for, which is the normal case.
 *
 * @param previousDueAt The due timestamp the row carried before this run.
 * @param now           When the worker actually picked it up.
 * @param intervalMs    Nominal spacing between runs.
 */
export function missedPeriods(previousDueAt: string | null, now: number, intervalMs: number): number {
  if (!previousDueAt || intervalMs <= 0) return 0;

  const due = Date.parse(previousDueAt);
  if (!Number.isFinite(due)) return 0;

  const lateBy = now - due;
  if (lateBy <= 0) return 0;

  /*
   * ROUND, not floor.
   *
   * The stored due time does not sit exactly on the cron slot: `nextDueAt`
   * places it one tolerance BEFORE, and rows written before that change sit
   * exactly on it. Flooring gets both wrong at opposite ends -- a punctual run
   * against a tolerance-shifted due time floors to 0 (right), but a run one
   * whole period late against an OLD due time is late by `interval` minus a
   * few seconds and floors to 0 as well (wrong: a day was lost).
   *
   * Rounding reads both correctly, because lateness always lands near a
   * multiple of the interval: ~0.01 periods for a punctual run, ~0.99 or ~1.01
   * for one genuinely missed.
   */
  return Math.round(lateBy / intervalMs);
}
