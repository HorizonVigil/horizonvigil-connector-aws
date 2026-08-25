import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, getOrgConnectionIds, inFilter, guarded, okJson, errJson, parsePagination, paginatedEnvelope } from '@horizonvigil/shared-lib';
import type { Env } from '../env';

export const identitiesRoutes = new Hono<{ Bindings: Env }>();

const LIST_SELECT =
  'id,connection_id,provider,identity_type,native_id,native_label,display_name,is_human,privilege_level,privilege_reasons,mfa_enabled,last_used_at,last_used_source,identity_created_at,first_seen_at,last_seen_at';

/**
 * GET /api/aws-accounts/identities — the first read surface over
 * cloud_identities (built this session as the canonical, cross-cloud
 * identity model — AWS-populated today via the IAM scanner, GCP/Azure to
 * follow). Org-scoped the same way every other cross-connection list route
 * in this codebase is: cloud_identities has no direct org_id column (same
 * shape as cloud_resources), so this resolves the org's connection ids
 * first via getOrgConnectionIds rather than relying on RLS alone to narrow
 * to one org.
 */
identitiesRoutes.get('/identities', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const connectionIds = await getOrgConnectionIds(db, orgId, auth.userId);

    const url = new URL(c.req.url);
    const pagination = parsePagination(url);
    const filters: Record<string, string> = { connection_id: inFilter(connectionIds), deleted_at: 'is.null' };
    const provider = url.searchParams.get('provider');
    const identityType = url.searchParams.get('identityType');
    const privilegeLevel = url.searchParams.get('privilegeLevel');
    const isHuman = url.searchParams.get('isHuman');
    const search = url.searchParams.get('search');
    if (provider) filters.provider = `eq.${provider}`;
    if (identityType) filters.identity_type = `eq.${identityType}`;
    if (privilegeLevel) filters.privilege_level = `eq.${privilegeLevel}`;
    if (isHuman === 'true' || isHuman === 'false') filters.is_human = `eq.${isHuman}`;
    if (search) {
      // Name-or-native-id search, same or=(...) convention as accounts.ts.
      filters.or = `(display_name.ilike.*${search}*,native_id.ilike.*${search}*,native_label.ilike.*${search}*)`;
    }

    const sortParam = url.searchParams.get('sort');
    const sortDir = url.searchParams.get('sortDir') === 'desc' ? 'desc' : 'asc';
    const SORTABLE_COLUMNS = new Set(['display_name', 'identity_type', 'privilege_level', 'last_used_at', 'identity_created_at', 'first_seen_at']);
    const order = sortParam && SORTABLE_COLUMNS.has(sortParam) ? `${sortParam}.${sortDir}` : 'privilege_level.desc,display_name.asc';

    const [rows, total] = await db.selectWithCount('cloud_identities', {
      select: LIST_SELECT,
      filters,
      order,
      limit: pagination.limit,
      offset: pagination.offset,
    });

    return okJson(paginatedEnvelope(rows as unknown[], total, pagination));
  }),
);

/**
 * GET /api/aws-accounts/identities/summary — counts by privilege level and
 * MFA status, for a dashboard-style KPI strip without the frontend having
 * to page through every identity to compute them client-side.
 *
 * Registered BEFORE /identities/:id below — Hono matches routes in
 * registration order, and /identities/:id is a wildcard that matches any
 * single path segment, "summary" included. With /identities/:id registered
 * first (as this route originally was), every real request to this route
 * was silently swallowed by that one instead: it queried cloud_identities
 * with id=eq.summary, Postgres rejected "summary" as an invalid uuid
 * (22P02), and PostgREST returned 400 — confirmed live via Cloud Run logs,
 * 100% reproducible on every single call. The frontend's loadIdentities
 * fetches this and the list endpoint via Promise.all with no per-call catch,
 * so that one 400 rejected the whole batch and left `identities` at its
 * initial empty array — real data (34 identities on a real connected
 * account) rendering as a misleading "No identities match these filters."
 */
identitiesRoutes.get('/identities/summary', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const connectionIds = await getOrgConnectionIds(db, orgId, auth.userId);
    const rows = await db.select<{ identity_type: string; is_human: boolean; privilege_level: string | null; mfa_enabled: boolean | null }[]>('cloud_identities', {
      select: 'identity_type,is_human,privilege_level,mfa_enabled',
      filters: { connection_id: inFilter(connectionIds), deleted_at: 'is.null' },
    });

    const summary = {
      total: rows.length,
      users: rows.filter((r) => r.identity_type === 'user').length,
      roles: rows.filter((r) => r.identity_type === 'role').length,
      adminEquivalent: rows.filter((r) => r.privilege_level === 'admin_equivalent').length,
      broad: rows.filter((r) => r.privilege_level === 'broad').length,
      scoped: rows.filter((r) => r.privilege_level === 'scoped').length,
      humanWithoutMfa: rows.filter((r) => r.is_human && r.mfa_enabled === false).length,
    };
    return okJson(summary);
  }),
);

/** GET /api/aws-accounts/identities/:id */
identitiesRoutes.get('/identities/:id', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const connectionIds = await getOrgConnectionIds(db, orgId, auth.userId);
    const rows = await db.select<Record<string, unknown>[]>('cloud_identities', {
      select: `${LIST_SELECT},metadata`,
      filters: { id: `eq.${c.req.param('id')}`, connection_id: inFilter(connectionIds) },
    });
    const identity = rows[0];
    if (!identity) return errJson(404, 'Identity not found');
    return okJson(identity);
  }),
);

/**
 * GET /api/aws-accounts/identities/:id/edges — every cloud_resource_edges
 * row where this identity is either endpoint (a role's ASSUMES edges from
 * the resources that can assume it, an instance profile's CONTAINS edge to
 * it, etc). Two queries rather than one OR'd query: source_identity_id and
 * target_identity_id are separate columns (see the edges migration for
 * why), so a single PostgREST filter can't match "either side" in one call.
 */
identitiesRoutes.get('/identities/:id/edges', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const connectionIds = await getOrgConnectionIds(db, orgId, auth.userId);
    const identityId = c.req.param('id');
    const select = 'id,relationship_type,confidence,source_engine,source_resource_id,source_identity_id,target_resource_id,target_identity_id,metadata,first_seen_at,last_seen_at';
    const [asSource, asTarget] = await Promise.all([
      db.select<Record<string, unknown>[]>('cloud_resource_edges', { select, filters: { connection_id: inFilter(connectionIds), source_identity_id: `eq.${identityId}`, deleted_at: 'is.null' } }),
      db.select<Record<string, unknown>[]>('cloud_resource_edges', { select, filters: { connection_id: inFilter(connectionIds), target_identity_id: `eq.${identityId}`, deleted_at: 'is.null' } }),
    ]);
    return okJson({ outbound: asSource, inbound: asTarget });
  }),
);
