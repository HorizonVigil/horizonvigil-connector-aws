import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, getOrgConnectionIds, inFilter, guarded, okJson, errJson, type Env } from '@horizonvigil/shared-lib';

export const regionsRoutes = new Hono<{ Bindings: Env }>();

interface RegionSummary {
  region: string;
  resourceCount: number;
  accountsEnabled: number;
  accountsWithResources: number;
}

/**
 * GET /api/aws-accounts/regions — every region enabled on at least one
 * connection (via scan_regions), with real discovered-resource counts from
 * cloud_resources layered on top. A region can be "enabled" with zero
 * resources (honest — either nothing's there, or resource discovery hasn't
 * populated it, no discovery engine runs in this pass) — shown as 0, not hidden.
 */
regionsRoutes.get('/regions', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const connections = await db.select<{ id: string; scan_regions: string[] }[]>('cloud_connections', {
      select: 'id,scan_regions',
      filters: { org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const connectionIds = connections.map((conn) => conn.id);

    const resourceRows = await db.select<{ region: string | null; connection_id: string }[]>('cloud_resources', {
      select: 'region,connection_id',
      filters: { connection_id: inFilter(connectionIds), deleted_at: 'is.null' },
      limit: 5000,
    });

    const byRegion = new Map<string, RegionSummary>();
    for (const conn of connections) {
      for (const region of conn.scan_regions ?? []) {
        const entry = byRegion.get(region) ?? { region, resourceCount: 0, accountsEnabled: 0, accountsWithResources: 0 };
        entry.accountsEnabled++;
        byRegion.set(region, entry);
      }
    }
    const accountsWithResourcesByRegion = new Map<string, Set<string>>();
    for (const row of resourceRows) {
      if (!row.region) continue;
      const entry = byRegion.get(row.region) ?? { region: row.region, resourceCount: 0, accountsEnabled: 0, accountsWithResources: 0 };
      entry.resourceCount++;
      byRegion.set(row.region, entry);
      const set = accountsWithResourcesByRegion.get(row.region) ?? new Set<string>();
      set.add(row.connection_id);
      accountsWithResourcesByRegion.set(row.region, set);
    }
    for (const [region, set] of accountsWithResourcesByRegion) {
      const entry = byRegion.get(region);
      if (entry) entry.accountsWithResources = set.size;
    }

    return okJson({ regions: Array.from(byRegion.values()).sort((a, b) => b.resourceCount - a.resourceCount) });
  }),
);

/** GET /api/aws-accounts/accounts/:id/regions — one account's own region breakdown. */
regionsRoutes.get('/accounts/:id/regions', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const rows = await db.select<{ id: string; scan_regions: string[]; default_region: string; last_discovery_at: string | null }[]>('cloud_connections', {
      select: 'id,scan_regions,default_region,last_discovery_at',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const connection = rows[0];
    if (!connection) return errJson(404, 'Account not found');

    const resourceRows = await db.select<{ region: string | null }[]>('cloud_resources', {
      select: 'region',
      filters: { connection_id: `eq.${connection.id}`, deleted_at: 'is.null' },
      limit: 5000,
    });
    const countByRegion = new Map<string, number>();
    for (const row of resourceRows) {
      if (!row.region) continue;
      countByRegion.set(row.region, (countByRegion.get(row.region) ?? 0) + 1);
    }

    const regions = (connection.scan_regions ?? []).map((region) => ({
      region,
      isDefault: region === connection.default_region,
      resourceCount: countByRegion.get(region) ?? 0,
      lastScan: connection.last_discovery_at,
    }));

    return okJson({ regions });
  }),
);
