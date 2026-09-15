import type { Env } from '../env';

/**
 * Best-effort server-to-server calls fired from runFinalize (discovery.ts)
 * after EVERY discovery run — interactive (browser step-loop), the daily
 * Cloud Scheduler sweep, and the abandoned-scan/tab-closed recovery sweep
 * (both in internalScan.ts) alike, since runFinalize is the one function
 * every one of those paths already funnels through.
 *
 * Before this existed, recommendation generation and alert-rule evaluation
 * were entirely client-side side effects (cloudops-frontend's
 * syncContext.tsx, fired only after the browser-driven step-loop finished)
 * — invisible to the two server-side scan paths above. The real bug that
 * caused: a resource correctly marked cloud_resources.deleted_at by a
 * scheduled scan never had its now-stale cost_recommendations row cleared,
 * since the "clear stale recommendations" step only ever ran when a browser
 * happened to be open for that particular scan. Moving the trigger here
 * (server-side, in the one function both scan paths already share) closes
 * that gap unconditionally rather than patching each trigger site
 * separately — see cloudops-cost's routes/internal.ts and
 * cloudops-observability's alerts/routes/internal.ts for the receiving end.
 *
 * Both calls are fire-and-await (not fire-and-forget — Cloud Run can tear
 * down the execution context right after the response is sent, same
 * reasoning as notify.ts) but must never fail the scan they're attached to:
 * a missing URL/secret or a downstream error is swallowed, matching the
 * same best-effort contract materializeResourceEdges already has in
 * runFinalize.
 */
/**
 * Outcome of one hook. `not_configured` is a first-class result, not a
 * variant of "nothing to do".
 *
 * The previous version returned void and skipped silently on a missing URL or
 * secret. In production `connector-aws` carries neither `POST_SCAN_HOOK_SECRET`
 * nor `COST_OPTIMIZATION_API_URL`, so all three hooks below have been no-ops —
 * and a no-op is indistinguishable from a hook that ran and found nothing to
 * do. That is the operational reason stale cost recommendations survived for
 * three weeks: the step that clears them never fired, and nothing said so.
 *
 * Same defect class as the edge materialization that reported an empty graph
 * while every write was failing. A skipped step must announce that it was
 * skipped.
 */
export type HookOutcome =
  | { state: 'called' }
  | { state: 'not_configured'; missing: string[] }
  | { state: 'failed'; reason: string };

async function callInternal(url: string | undefined, secret: string | undefined, path: string, body: Record<string, unknown>): Promise<HookOutcome> {
  const missing: string[] = [];
  if (!url) missing.push('url');
  if (!secret) missing.push('secret');
  if (missing.length > 0) return { state: 'not_configured', missing };

  try {
    await fetch(`${url}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Scan-Secret': secret as string },
      body: JSON.stringify(body),
    });
    return { state: 'called' };
  } catch (err) {
    // Still best-effort — see the doc comment above. The scan must not fail
    // because a downstream service is unreachable; it must only stop
    // pretending the hook ran.
    return { state: 'failed', reason: err instanceof Error ? err.message : String(err) };
  }
}

export async function triggerRecommendationGeneration(env: Env, connectionId: string, orgId: string): Promise<HookOutcome> {
  return callInternal(env.COST_OPTIMIZATION_API_URL, env.POST_SCAN_HOOK_SECRET, '/internal/generate-recommendations', { connectionId, orgId });
}

export async function triggerAlertEvaluation(env: Env, connectionId: string, orgId: string): Promise<HookOutcome> {
  return callInternal(env.ALERTS_API_URL, env.POST_SCAN_HOOK_SECRET, '/internal/evaluate-alert-rules', { connectionId, orgId });
}

/**
 * Same best-effort, server-to-server pattern as the two hooks above, fired
 * from the new POST /internal/run-due-cost-syncs route (routes/cost.ts)
 * right after a scheduled sync writes fresh cost_snapshots rows — the
 * server-side equivalent of the user-triggered path's own "detect
 * immediately after a manual Sync Cost click" behavior (see
 * frontend/src/pages/AwsAccountDetail.tsx's syncCost), now reachable from a
 * context with no browser/user session to have driven that click.
 */
export async function triggerAnomalyDetection(env: Env, connectionId: string): Promise<HookOutcome> {
  return callInternal(env.COST_OPTIMIZATION_API_URL, env.POST_SCAN_HOOK_SECRET, '/internal/detect-anomalies', { connectionId });
}
