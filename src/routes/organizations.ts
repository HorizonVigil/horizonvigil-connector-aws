import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, getOrgConnectionIds, getActiveScope, inFilter, guarded, okJson, errJson, requirePermittedConnection } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { resolveCredentials, type ResolvableConnection } from './permissions';
import { listOrganizationTree, type OrgTreeNode } from '../lib/scanners/organizations';

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
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    // This response lists connection names and account ids directly, so it
    // must be bounded by the permitted set rather than the whole org.
    const permittedIds = await getOrgConnectionIds(db, orgId, auth.userId, getActiveScope(c.req.raw, orgId));
    const rows = await db.select<{ aws_account_id: string; connection_name: string; environment: string; status: string }[]>('cloud_connections', {
      select: 'aws_account_id,connection_name,environment,status',
      filters: { id: inFilter(permittedIds), org_id: `eq.${orgId}`, provider: 'eq.aws' },
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

/**
 * GET /api/aws-accounts/organizations/hierarchy?managementConnectionId=
 * — the real AWS Organizations OU tree (spec §25), walked live via the
 * management connection's own credentials, with every account annotated as
 * `connected` / `not_connected` against this org's `cloud_connections`. When
 * no `managementConnectionId` is given, or the given connection can't read
 * Organizations, the response falls back to `{ mode: 'flat', ... }` — the
 * same account-id grouping `/organizations` returns — so the Hierarchy view
 * always has something real to render. Live-cloud call: NOT runnable in this
 * environment (needs PLATFORM_AWS_* for cross-account role assumption).
 */
orgHierarchyRoutes.get('/organizations/hierarchy', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    // Same bounding as /organizations above. This set also decides which
    // accounts in the live AWS Organizations tree get annotated as
    // "connected", so an unbounded read would disclose the existence of
    // connections the caller is not permitted to see.
    const permittedIds = await getOrgConnectionIds(db, orgId, auth.userId, getActiveScope(c.req.raw, orgId));
    const connectedRows = await db.select<{ aws_account_id: string; id: string; connection_name: string; status: string; environment: string }[]>('cloud_connections', {
      select: 'aws_account_id,id,connection_name,status,environment',
      filters: { id: inFilter(permittedIds), org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const connectedById = new Map(connectedRows.map((r) => [r.aws_account_id, r]));

    const flat = () => {
      const groups = new Map<string, typeof connectedRows>();
      for (const row of connectedRows) {
        const list = groups.get(row.aws_account_id) ?? [];
        list.push(row);
        groups.set(row.aws_account_id, list);
      }
      return okJson({
        mode: 'flat' as const,
        awsAccounts: [...groups.entries()].map(([awsAccountId, connections]) => ({ awsAccountId, connections })),
      });
    };

    const managementConnectionId = c.req.query('managementConnectionId');
    if (!managementConnectionId) return flat();

    // This id is caller-supplied and its credentials are then used to walk the
    // real AWS Organizations tree, so it needs the same permitted-set check as
    // a path parameter would.
    await requirePermittedConnection(db, orgId, auth.userId, managementConnectionId, getActiveScope(c.req.raw, orgId));
    const rows = await db.select<(ResolvableConnection & { id: string })[]>('cloud_connections', {
      select: 'id,connection_method,credentials_encrypted,role_arn,external_id,default_region',
      filters: { id: `eq.${managementConnectionId}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const mgmt = rows[0];
    if (!mgmt) return errJson(404, 'Management account connection not found.');

    const resolved = await resolveCredentials(c.env, mgmt);
    if ('error' in resolved) return flat();

    const tree = await listOrganizationTree(resolved.creds);
    if (!tree.ok) return flat();

    const annotate = (node: OrgTreeNode): unknown => ({
      type: node.type,
      id: node.id,
      name: node.name,
      accounts: node.accounts.map((a) => {
        const connected = connectedById.get(a.id);
        return { ...a, connected: !!connected, connectionId: connected?.id ?? null, environment: connected?.environment ?? null };
      }),
      children: node.children.map(annotate),
    });

    return okJson({ mode: 'tree' as const, roots: tree.roots.map(annotate) });
  }),
);

/** GET /api/aws-accounts/cross-account-roles — connections using the recommended STS AssumeRole method. */
orgHierarchyRoutes.get('/cross-account-roles', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    // Lists connection names, account ids and role ARNs, so it is bounded by
    // the permitted set like every other connection listing.
    const permittedIds = await getOrgConnectionIds(db, orgId, auth.userId, getActiveScope(c.req.raw, orgId));
    const rows = await db.select('cloud_connections', {
      select: 'id,connection_name,aws_account_id,role_arn,external_id,status,created_at',
      filters: { id: inFilter(permittedIds), org_id: `eq.${orgId}`, connection_method: 'eq.cross_account_role' },
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
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    // Authorize the caller for THIS connection before reading it: an
    // id + org_id filter proves org ownership, not that this caller is
    // permitted the connection (resource grants / active scope).
    await requirePermittedConnection(db, orgId, auth.userId, c.req.param('id'), getActiveScope(c.req.raw, orgId));
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
