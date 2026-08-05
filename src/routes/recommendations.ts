import { Hono, getAuthContext, requireOrgId, createDb, requireMember, getOrgConnectionIds, inFilter, guarded, okJson, type Env } from '@cloudops360/shared-lib';
import { notCurrentlyExcludedFilter } from '../lib/exclusions';

export const recommendationsRoutes = new Hono<{ Bindings: Env }>();

/** GET /api/aws-accounts/accounts/:id/recommendations — one account's open cost recommendations, from the same table cost-optimization-api owns. */
recommendationsRoutes.get('/accounts/:id/recommendations', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMember(db, auth.userId, orgId);

    const rows = await db.select('cost_recommendations', {
      select: 'id,category,issue,recommended_action,potential_monthly_savings,priority,status',
      filters: { connection_id: `eq.${c.req.param('id')}`, status: 'eq.open', or: notCurrentlyExcludedFilter() },
      order: 'potential_monthly_savings.desc',
      limit: 50,
    });
    return okJson({ recommendations: rows });
  }),
);

/** GET /api/aws-accounts/recommendations — org-wide open recommendation count + total potential savings, for the dashboard. */
recommendationsRoutes.get('/recommendations', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMember(db, auth.userId, orgId);

    const connectionIds = await getOrgConnectionIds(db, orgId);
    const rows = await db.select<{ potential_monthly_savings: string }[]>('cost_recommendations', {
      select: 'potential_monthly_savings',
      filters: { connection_id: inFilter(connectionIds), status: 'eq.open', or: notCurrentlyExcludedFilter() },
      limit: 5000,
    });

    return okJson({
      openRecommendations: rows.length,
      totalPotentialMonthlySavings: Math.round(rows.reduce((s, r) => s + Number(r.potential_monthly_savings || 0), 0) * 100) / 100,
    });
  }),
);
