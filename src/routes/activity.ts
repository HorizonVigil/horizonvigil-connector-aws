import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, guarded, okJson, parsePagination, paginatedEnvelope, type Env } from '@cloudops360/shared-lib';

export const activityRoutes = new Hono<{ Bindings: Env }>();

interface AuditRow {
  id: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  profiles: { email: string; full_name: string | null } | null;
}

function mapRow(r: AuditRow) {
  return {
    id: r.id,
    action: r.action,
    targetType: r.target_type,
    targetId: r.target_id,
    metadata: r.metadata,
    occurredAt: r.created_at,
    actor: r.profiles ? { email: r.profiles.email, name: r.profiles.full_name } : null,
  };
}

/**
 * GET /api/aws-accounts/accounts/:id/activity — one account's own audit
 * trail: every audit_log row CloudOps360 itself wrote while acting on this
 * connection (connect/disconnect/test/validation/discovery/sync/recommendation
 * events). This is CloudOps360's own action log, not AWS CloudTrail — it
 * won't show e.g. a security group edited via the AWS Console or CLI. Real
 * AWS-side audit (CloudTrail LookupEvents) isn't ingested by any scanner yet.
 */
activityRoutes.get('/accounts/:id/activity', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const url = new URL(c.req.url);
    const pagination = parsePagination(url);
    const filters: Record<string, string> = { org_id: `eq.${orgId}`, target_type: 'eq.cloud_connection', target_id: `eq.${c.req.param('id')}` };
    const action = url.searchParams.get('action');
    if (action) filters.action = `ilike.*${action}*`;
    const actorId = url.searchParams.get('actorId');
    if (actorId) filters.actor_id = `eq.${actorId}`;
    const from = url.searchParams.get('from');
    const to = url.searchParams.get('to');
    if (from && to) filters.and = `(created_at.gte.${from},created_at.lte.${to})`;
    else if (from) filters.created_at = `gte.${from}`;
    else if (to) filters.created_at = `lte.${to}`;

    const [rows, total] = await db.selectWithCount<AuditRow[]>('audit_log', {
      select: 'id,action,target_type,target_id,metadata,created_at,profiles(email,full_name)',
      filters,
      order: 'created_at.desc',
      limit: pagination.limit,
      offset: pagination.offset,
    });
    return okJson(paginatedEnvelope(rows.map(mapRow), total, pagination));
  }),
);

/** GET /api/aws-accounts/activity — org-wide AWS-Accounts-domain activity feed, for the dashboard's Recent Activity panel. */
activityRoutes.get('/activity', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const url = new URL(c.req.url);
    const pagination = parsePagination(url);
    const [rows, total] = await db.selectWithCount<AuditRow[]>('audit_log', {
      select: 'id,action,target_type,target_id,metadata,created_at,profiles(email,full_name)',
      filters: { org_id: `eq.${orgId}`, action: 'ilike.aws_account.*' },
      order: 'created_at.desc',
      limit: pagination.limit,
      offset: pagination.offset,
    });
    return okJson(paginatedEnvelope(rows.map(mapRow), total, pagination));
  }),
);
