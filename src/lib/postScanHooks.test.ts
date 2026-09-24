import { describe, it, expect, vi, afterEach } from 'vitest';
import { triggerRecommendationGeneration, triggerAlertEvaluation, triggerAnomalyDetection } from './postScanHooks';
import type { Env } from '../env';

/**
 * A hook that cannot fire must SAY it did not fire.
 *
 * `callInternal` used to return void and skip silently when the URL or secret
 * was missing. In production `connector-aws` carries neither
 * POST_SCAN_HOOK_SECRET nor COST_OPTIMIZATION_API_URL, so all three hooks were
 * no-ops -- and a no-op looks exactly like a hook that ran and found nothing
 * to do.
 *
 * That ambiguity is the operational reason four stale cost recommendations
 * pointing at deleted resources stayed open for three weeks: the step that
 * clears them never ran, and nothing recorded that it had not.
 */
const env = (over: Partial<Env> = {}) => ({
  COST_OPTIMIZATION_API_URL: 'https://cost.example.test',
  ALERTS_API_URL: 'https://alerts.example.test',
  POST_SCAN_HOOK_SECRET: 's3cret',
  ...over,
}) as Env;

afterEach(() => { vi.unstubAllGlobals(); });

describe('post-scan hooks report whether they fired', () => {
  it('reports not_configured, naming what is missing, instead of skipping silently', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    const noUrl = await triggerRecommendationGeneration(env({ COST_OPTIMIZATION_API_URL: undefined }), 'c1', 'o1');
    expect(noUrl).toEqual({ state: 'not_configured', missing: ['url'] });

    const noSecret = await triggerRecommendationGeneration(env({ POST_SCAN_HOOK_SECRET: undefined }), 'c1', 'o1');
    expect(noSecret).toEqual({ state: 'not_configured', missing: ['secret'] });

    const neither = await triggerRecommendationGeneration(
      env({ COST_OPTIMIZATION_API_URL: undefined, POST_SCAN_HOOK_SECRET: undefined }), 'c1', 'o1');
    expect(neither).toEqual({ state: 'not_configured', missing: ['url', 'secret'] });

    // The load-bearing negative: an unconfigured hook must not reach the network.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('reports called when it actually posted', async () => {
    const fetchSpy = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchSpy);

    expect(await triggerRecommendationGeneration(env(), 'c1', 'o1')).toEqual({ state: 'called' });
    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://cost.example.test/internal/generate-recommendations');
    expect((init.headers as Record<string, string>)['X-Internal-Scan-Secret']).toBe('s3cret');
  });

  /**
   * Still best-effort: a downstream outage must not fail the scan it is
   * attached to. It must only stop pretending the hook ran.
   */
  it('reports failed rather than throwing when the downstream call errors', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('connect ECONNREFUSED')));
    const out = await triggerAlertEvaluation(env(), 'c1', 'o1');
    expect(out).toEqual({ state: 'failed', reason: 'connect ECONNREFUSED' });
  });

  it('reports a non-successful HTTP response as failed', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 503 }));
    await expect(triggerRecommendationGeneration(env(), 'c1', 'o1')).resolves.toEqual({ state: 'failed', reason: 'HTTP 503' });
  });

  it('applies the same contract to every hook, including anomaly detection', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));
    for (const outcome of [
      await triggerRecommendationGeneration(env(), 'c1', 'o1'),
      await triggerAlertEvaluation(env(), 'c1', 'o1'),
      await triggerAnomalyDetection(env(), 'c1'),
    ]) expect(outcome.state).toBe('called');

    vi.stubGlobal('fetch', vi.fn());
    const bare = env({ COST_OPTIMIZATION_API_URL: undefined, ALERTS_API_URL: undefined, POST_SCAN_HOOK_SECRET: undefined });
    for (const outcome of [
      await triggerRecommendationGeneration(bare, 'c1', 'o1'),
      await triggerAlertEvaluation(bare, 'c1', 'o1'),
      await triggerAnomalyDetection(bare, 'c1'),
    ]) expect(outcome.state).toBe('not_configured');
  });
});
