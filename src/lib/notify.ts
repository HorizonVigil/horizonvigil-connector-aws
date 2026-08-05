import type { Env } from '../env';

/**
 * Best-effort fan-out to automation-api's webhook/Jira dispatcher —
 * forwards the acting user's own access token (same cross-Worker auth
 * pattern the frontend already uses calling each Worker directly), so a
 * failure here (no webhooks/Jira configured, network error) must never
 * affect the caller's real response.
 */
export async function notify(env: Env, accessToken: string, orgId: string, event: string, summary: string, detail?: string): Promise<void> {
  const base = env.AUTOMATION_API_URL || 'https://cloudops360-1-automation-api.thequietmind18.workers.dev';
  try {
    await fetch(`${base}/api/automation/webhooks/dispatch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}`, 'X-Org-Id': orgId },
      body: JSON.stringify({ event, summary, detail }),
    });
  } catch {
    // best-effort — a notification failure must never affect the caller's real response
  }
}
