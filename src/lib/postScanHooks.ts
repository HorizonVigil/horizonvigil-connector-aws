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
async function callInternal(url: string | undefined, secret: string | undefined, path: string, body: Record<string, unknown>): Promise<void> {
  if (!url || !secret) return;
  try {
    await fetch(`${url}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Scan-Secret': secret },
      body: JSON.stringify(body),
    });
  } catch {
    // best-effort — see doc comment above
  }
}

export async function triggerRecommendationGeneration(env: Env, connectionId: string, orgId: string): Promise<void> {
  await callInternal(env.COST_OPTIMIZATION_API_URL, env.POST_SCAN_HOOK_SECRET, '/internal/generate-recommendations', { connectionId, orgId });
}

export async function triggerAlertEvaluation(env: Env, connectionId: string, orgId: string): Promise<void> {
  await callInternal(env.ALERTS_API_URL, env.POST_SCAN_HOOK_SECRET, '/internal/evaluate-alert-rules', { connectionId, orgId });
}
