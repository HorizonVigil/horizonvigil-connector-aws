import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, getOrgConnectionIds, inFilter, guarded, okJson, type Env, getActiveScope } from '@horizonvigil/shared-lib';
import { notCurrentlyExcludedFilter } from '../lib/exclusions';

export const recommendationsRoutes = new Hono<{ Bindings: Env }>();

/** GET /api/aws-accounts/accounts/:id/recommendations — one account's open cost recommendations, from the same table cost-optimization-api owns. */
recommendationsRoutes.get('/accounts/:id/recommendations', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'optimization', 'read');

    const rows = await db.select('cost_recommendations', {
      select: 'id,connection_id,resource_id,category,issue,recommended_action,potential_monthly_savings,priority,status,created_at,external_key,' +
        'excluded_reason,excluded_justification,excluded_by,excluded_at,excluded_until,assigned_to,last_notified_at,last_notified_by,' +
        'source,commitment_term,payment_option',
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
    await requireMenuPermission(db, auth.userId, orgId, 'optimization', 'read');

    const connectionIds = await getOrgConnectionIds(db, orgId, auth.userId, getActiveScope(c.req.raw, orgId));
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
