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
