import { Hono, getAuthContext, requireOrgId, createDb, requireMember, guarded, okJson, parsePagination, paginatedEnvelope, type Env } from '@cloudops360/shared-lib';

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

/** GET /api/aws-accounts/accounts/:id/activity — one account's own audit trail (connect/disconnect/test/validation events). */
activityRoutes.get('/accounts/:id/activity', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMember(db, auth.userId, orgId);

    const url = new URL(c.req.url);
    const pagination = parsePagination(url);
    const [rows, total] = await db.selectWithCount<AuditRow[]>('audit_log', {
      select: 'id,action,target_type,target_id,metadata,created_at,profiles(email,full_name)',
      filters: { org_id: `eq.${orgId}`, target_type: 'eq.cloud_connection', target_id: `eq.${c.req.param('id')}` },
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
    await requireMember(db, auth.userId, orgId);

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
