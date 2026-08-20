import type { Env } from '../env';

/**
 * Best-effort fan-out to automation-api's webhook/Jira dispatcher —
 * forwards the acting user's own access token (same cross-Worker auth
 * pattern the frontend already uses calling each Worker directly), so a
 * failure here (no webhooks/Jira configured, network error) must never
 * affect the caller's real response.
 */
export async function notify(env: Env, accessToken: string, orgId: string, event: string, summary: string, detail?: string): Promise<void> {
  // No hardcoded fallback: forwarding the caller's real bearer token
  // anywhere requires an explicitly configured destination. Silently
  // skipping is consistent with this function's own contract (best-effort,
  // must never affect the caller).
  if (!env.AUTOMATION_API_URL) return;
  try {
    await fetch(`${env.AUTOMATION_API_URL}/api/automation/webhooks/dispatch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}`, 'X-Org-Id': orgId },
      body: JSON.stringify({ event, summary, detail }),
    });
  } catch {
    // best-effort — a notification failure must never affect the caller's real response
  }
}
