import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, writeAuditLog, guarded, okJson, errJson } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { resolveCredentials, type ResolvableConnection } from './permissions';
import {
  RI_SERVICES, fetchReservationRecommendations, mapReservationRecommendation,
  fetchRightsizingRecommendations, mapRightsizingRecommendation,
  startSavingsPlansGeneration, pollSavingsPlansGeneration, fetchSavingsPlansRecommendation, mapSavingsPlanRecommendation,
  type CostRecommendationInsert,
} from '../lib/ceRecommendations';

export const recommendationsSyncRoutes = new Hono<{ Bindings: Env }>();

const SAVINGS_PLAN_GENERATION_STALE_AFTER_MS = 24 * 60 * 60 * 1000;

/**
 * POST /api/aws-accounts/accounts/:id/recommendations/sync — real, per-cloud
 * Reserved Instance / Savings Plan / Rightsizing recommendations, replacing
 * what was previously dead code: the Reserved Instances and Savings Plans
 * tabs had no generation path anywhere (confirmed via exhaustive grep of
 * this repo and horizonvigil-cost), yet the frontend told users otherwise.
 * horizonvigil-cost/src/lib/generateRecommendations.ts's homegrown
 * EC2/EBS/EIP heuristic is untouched and still runs via its own
 * /generate endpoint — this is a second, real-API-backed source, not a
 * replacement (see the dedup filter this adds there for rightsizing).
 *
 * Every dollar figure here is copied verbatim from AWS's own recommendation
 * APIs -- never recomputed locally. Savings Plans is genuinely asynchronous
 * (AWS itself computes it in the background); rather than inventing polling
 * infrastructure, generation state lives on the connection row (same
 * convention as cur_last_synced_at) and this same endpoint, called again
 * later, picks up where it left off.
 */
recommendationsSyncRoutes.post('/accounts/:id/recommendations/sync', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    const rows = await db.select<(ResolvableConnection & { id: string; savings_plans_recommendation_id: string | null; savings_plans_generation_started_at: string | null })[]>('cloud_connections', {
      select: 'id,connection_method,credentials_encrypted,role_arn,external_id,default_region,savings_plans_recommendation_id,savings_plans_generation_started_at',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const connection = rows[0];
    if (!connection) return errJson(404, 'Account not found');

    const resolved = await resolveCredentials(c.env, connection);
    if ('error' in resolved) return errJson(400, resolved.error);
    const { creds } = resolved;

    const errors: string[] = [];
    const toInsert: CostRecommendationInsert[] = [];

    // ── Reserved Instances (EC2 + RDS) ──────────────────────────────────
    for (const service of RI_SERVICES) {
      const res = await fetchReservationRecommendations(creds, service);
      if (!res.ok) { errors.push(`${service} RI: ${res.error}`); continue; }
      for (const rec of res.body.Recommendations ?? []) {
        for (const detail of rec.RecommendationDetails ?? []) {
          const mapped = mapReservationRecommendation(rec, detail, service, connection.id);
          if (mapped) toInsert.push(mapped);
        }
      }
    }

    // ── Rightsizing (EC2) ────────────────────────────────────────────────
    const rightsizing = await fetchRightsizingRecommendations(creds);
    if (!rightsizing.ok) {
      errors.push(`Rightsizing: ${rightsizing.error}`);
    } else {
      for (const rec of rightsizing.body.RightsizingRecommendations ?? []) {
        const resourceId = rec.CurrentInstance?.ResourceId;
        let resourceRowId: string | null = null;
        if (resourceId) {
          const resourceRows = await db.select<{ id: string }[]>('cloud_resources', {
            select: 'id',
            filters: { connection_id: `eq.${connection.id}`, resource_type_key: 'eq.ec2_instance', resource_id: `eq.${resourceId}` },
            limit: 1,
          });
          resourceRowId = resourceRows[0]?.id ?? null;
        }
        const mapped = mapRightsizingRecommendation(rec, connection.id, resourceRowId);
        if (mapped) toInsert.push(mapped);
      }
    }

    // ── Savings Plans (async: start once, poll on subsequent calls) ─────
    let savingsPlansStatus: 'generating' | 'ready' | 'error' | 'not_started' = 'not_started';
    const generationIsStale = connection.savings_plans_generation_started_at
      && Date.now() - new Date(connection.savings_plans_generation_started_at).getTime() > SAVINGS_PLAN_GENERATION_STALE_AFTER_MS;

    if (!connection.savings_plans_recommendation_id || generationIsStale) {
      const started = await startSavingsPlansGeneration(creds);
      if (!started.ok) {
        errors.push(`Savings Plans: ${started.error}`);
        savingsPlansStatus = 'error';
      } else {
        await db.update('cloud_connections', { id: `eq.${connection.id}` }, {
          savings_plans_recommendation_id: started.recommendationId,
          savings_plans_generation_started_at: new Date().toISOString(),
        }, 'return=minimal');
        savingsPlansStatus = 'generating';
      }
    } else {
      const polled = await pollSavingsPlansGeneration(creds, connection.savings_plans_recommendation_id);
      if (!polled.ok) {
        errors.push(`Savings Plans: ${polled.error}`);
        savingsPlansStatus = 'error';
      } else if (polled.status === 'PROCESSING') {
        savingsPlansStatus = 'generating';
      } else if (polled.status === 'FAILED') {
        errors.push('Savings Plans: AWS reported generation FAILED — will retry on next sync.');
        await db.update('cloud_connections', { id: `eq.${connection.id}` }, { savings_plans_recommendation_id: null, savings_plans_generation_started_at: null }, 'return=minimal');
        savingsPlansStatus = 'error';
      } else {
        const fetched = await fetchSavingsPlansRecommendation(creds);
        if (!fetched.ok) {
          errors.push(`Savings Plans: ${fetched.error}`);
          savingsPlansStatus = 'error';
        } else {
          const plan = fetched.body.SavingsPlansPurchaseRecommendation;
          const planType = plan?.SavingsPlansType ?? 'COMPUTE_SP';
          const term = plan?.TermInYears ?? 'ONE_YEAR';
          const paymentOption = plan?.PaymentOption ?? 'NO_UPFRONT';
          for (const detail of plan?.SavingsPlansPurchaseRecommendationDetails ?? []) {
            const mapped = mapSavingsPlanRecommendation(detail, planType, term, paymentOption, connection.id);
            if (mapped) toInsert.push(mapped);
          }
          // Result consumed -- clear the pointer so the next stale-check window starts fresh.
          await db.update('cloud_connections', { id: `eq.${connection.id}` }, { savings_plans_recommendation_id: null, savings_plans_generation_started_at: null }, 'return=minimal');
          savingsPlansStatus = 'ready';
        }
      }
    }

    if (toInsert.length > 0) {
      await db.insert('cost_recommendations?on_conflict=connection_id,category,external_key', toInsert, 'resolution=merge-duplicates,return=minimal');
    }

    await writeAuditLog(db, {
      orgId, actorId: auth.userId, action: 'aws_account.recommendations_synced', targetType: 'cloud_connection', targetId: connection.id,
      metadata: { inserted: toInsert.length, savingsPlansStatus, errors: errors.length ? errors : undefined },
    });

    return okJson({ inserted: toInsert.length, savingsPlansStatus, errors });
  }),
);
