import { Hono, getAuthContext, requireOrgId, createDb, requireMember, guarded, okJson, errJson } from '@cloudops360/shared-lib';
import type { Env } from '../env';

export const orgHierarchyRoutes = new Hono<{ Bindings: Env }>();

/**
 * GET /api/aws-accounts/organizations — connected accounts grouped by their
 * 12-digit AWS account id. This is a grouping of *this org's connections*,
 * not a live read of AWS Organizations (that needs `organizations:List*`
 * calls against the payer account, not built in this pass).
 */
orgHierarchyRoutes.get('/organizations', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMember(db, auth.userId, orgId);

    const rows = await db.select<{ aws_account_id: string; connection_name: string; environment: string; status: string }[]>('cloud_connections', {
      select: 'aws_account_id,connection_name,environment,status',
      filters: { org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });

    const groups = new Map<string, typeof rows>();
    for (const row of rows) {
      const list = groups.get(row.aws_account_id) ?? [];
      list.push(row);
      groups.set(row.aws_account_id, list);
    }

    return okJson({
      awsAccounts: Array.from(groups.entries()).map(([awsAccountId, connections]) => ({ awsAccountId, connections })),
    });
  }),
);

/** GET /api/aws-accounts/cross-account-roles — connections using the recommended STS AssumeRole method. */
orgHierarchyRoutes.get('/cross-account-roles', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMember(db, auth.userId, orgId);

    const rows = await db.select('cloud_connections', {
      select: 'id,connection_name,aws_account_id,role_arn,external_id,status,created_at',
      filters: { org_id: `eq.${orgId}`, connection_method: 'eq.cross_account_role' },
    });
    return okJson({ roles: rows });
  }),
);

/** GET /api/aws-accounts/credentials/:id — masked credential summary + rotation reminder for one connection. */
orgHierarchyRoutes.get('/credentials/:id', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMember(db, auth.userId, orgId);

    const rows = await db.select<
      { connection_method: string; masked_access_key: string | null; key_rotated_at: string | null; role_arn: string | null; external_id: string | null }[]
    >('cloud_connections', {
      select: 'connection_method,masked_access_key,key_rotated_at,role_arn,external_id',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const row = rows[0];
    if (!row) return errJson(404, 'Account not found');

    const rotationDueInDays = row.key_rotated_at
      ? Math.max(0, 90 - Math.floor((Date.now() - new Date(row.key_rotated_at).getTime()) / (24 * 60 * 60 * 1000)))
      : null;

    return okJson({
      connectionMethod: row.connection_method,
      maskedAccessKey: row.masked_access_key,
      keyRotatedAt: row.key_rotated_at,
      rotationDueInDays,
      roleArn: row.role_arn,
      externalId: row.external_id,
    });
  }),
);
