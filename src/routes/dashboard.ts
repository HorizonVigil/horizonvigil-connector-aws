import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, getOrgConnectionIds, inFilter, guarded, okJson } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { notCurrentlyExcludedFilter } from '../lib/exclusions';

export const dashboardRoutes = new Hono<{ Bindings: Env }>();

interface ConnectionRow {
  id: string;
  connection_name: string;
  status: string;
  environment: string;
  scan_regions: string[];
  last_sync_at: string | null;
  last_discovery_at: string | null;
  last_permission_check_at: string | null;
  error_message: string | null;
  resource_summary: Record<string, unknown> | null;
  key_rotated_at: string | null;
}

const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

function monthStartIso(): string {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString().slice(0, 10);
}

/**
 * GET /api/aws-accounts/dashboard — the domain's real operational landing
 * view, not a table. Every figure here is a live query against this org's
 * own data — nothing hardcoded, nothing simulated. Two fields are
 * deliberately honest nulls rather than fabricated: `nextScheduledDiscovery`
 * and `discoverySuccessRate` — no discovery engine or scheduler exists in
 * this rebuild (docs/about-project.md), so there is nothing true to report
 * for either. "Sync" throughout this dashboard means a real permission-
 * validation run (see routes/permissions.ts), which is the actual
 * capability this domain has today.
 */
dashboardRoutes.get('/dashboard', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const connections = await db.select<ConnectionRow[]>('cloud_connections', {
      select: 'id,connection_name,status,environment,scan_regions,last_sync_at,last_discovery_at,last_permission_check_at,error_message,resource_summary,key_rotated_at',
      filters: { org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const connectionIds = connections.map((conn) => conn.id);

    const [resourceRows, recentRuns, costRows, recommendationRows, activityRows, alertRows] = await Promise.all([
      db.select<{ region: string | null }[]>('cloud_resources', { select: 'region', filters: { connection_id: inFilter(connectionIds), deleted_at: 'is.null' }, limit: 5000 }),
      db.select<{ connection_id: string; status: string; started_at: string }[]>('connection_validation_runs', {
        select: 'connection_id,status,started_at',
        filters: { connection_id: inFilter(connectionIds) },
        order: 'started_at.desc',
        limit: 500,
      }),
      db.select<{ connection_id: string; unblended_cost: string }[]>('cost_snapshots', {
        select: 'connection_id,unblended_cost',
        filters: { connection_id: inFilter(connectionIds), usage_date: `gte.${monthStartIso()}` },
        limit: 5000,
      }),
      db.select<{ potential_monthly_savings: string }[]>('cost_recommendations', { select: 'potential_monthly_savings', filters: { connection_id: inFilter(connectionIds), status: 'eq.open', or: notCurrentlyExcludedFilter() }, limit: 5000 }),
      db.select<{ id: string; action: string; target_id: string | null; created_at: string; profiles: { email: string } | null }[]>('audit_log', {
        select: 'id,action,target_id,created_at,profiles(email)',
        filters: { org_id: `eq.${orgId}`, action: 'ilike.aws_account.*' },
        order: 'created_at.desc',
        limit: 8,
      }),
      db.select<{ id: string; alert_name: string; severity: string; connection_id: string | null; triggered_at: string }[]>('alerts', {
        select: 'id,alert_name,severity,connection_id,triggered_at',
        filters: { org_id: `eq.${orgId}`, status: 'eq.open', connection_id: inFilter(connectionIds) },
        order: 'triggered_at.desc',
        limit: 5,
      }),
    ]);

    // Latest validation run per connection (already sorted desc above).
    const latestRunByConnection = new Map<string, { status: string; started_at: string }>();
    for (const run of recentRuns) if (!latestRunByConnection.has(run.connection_id)) latestRunByConnection.set(run.connection_id, run);

    let healthy = 0;
    let failed = 0;
    let disconnected = 0;
    let needingAttention = 0;
    let rotationDue = 0;
    // Bounded to the first 10 so the dashboard payload can't balloon on a
    // large org — this is the same condition the count above uses, computed
    // in the same pass, so the stat card and this list can never disagree
    // (unlike deriving a "needing attention" list client-side from whatever
    // page of the paginated Inventory happens to be loaded).
    const needingAttentionList: { connectionId: string; connectionName: string; reason: string }[] = [];
    for (const conn of connections) {
      if (conn.status === 'disconnected') disconnected++;
      else if (conn.status === 'error' || conn.status === 'expired') failed++;
      else if (conn.status === 'connected' && !conn.error_message) healthy++;
      if (conn.key_rotated_at && Date.now() - new Date(conn.key_rotated_at).getTime() > NINETY_DAYS_MS) rotationDue++;
      if (conn.status !== 'disconnected' && (conn.error_message || conn.status === 'pending')) {
        needingAttention++;
        if (needingAttentionList.length < 10) {
          needingAttentionList.push({
            connectionId: conn.id,
            connectionName: conn.connection_name,
            reason: conn.error_message ?? 'Not yet validated',
          });
        }
      }
    }

    const regionsCovered = new Set(connections.flatMap((conn) => conn.scan_regions ?? [])).size;
    const lastDiscovery = connections.map((conn) => conn.last_discovery_at).filter((v): v is string => !!v).sort().at(-1) ?? null;

    const syncFailures = Array.from(latestRunByConnection.values()).filter((run) => run.status === 'failed').length;

    const costByConnection = new Map<string, number>();
    for (const row of costRows) costByConnection.set(row.connection_id, (costByConnection.get(row.connection_id) ?? 0) + Number(row.unblended_cost || 0));
    const nameById = new Map(connections.map((conn) => [conn.id, conn.connection_name]));
    const topCostAccounts = Array.from(costByConnection.entries())
      .map(([connectionId, cost]) => ({ connectionId, connectionName: nameById.get(connectionId) ?? connectionId, monthToDate: Math.round(cost * 100) / 100 }))
      .sort((a, b) => b.monthToDate - a.monthToDate)
      .slice(0, 5);

    const growthByConnection = new Map<string, number>();
    for (const conn of connections) {
      const total = (conn.resource_summary as { totalResources?: number } | null)?.totalResources;
      if (typeof total === 'number') growthByConnection.set(conn.id, total);
    }
    const topGrowingAccounts = Array.from(growthByConnection.entries())
      .map(([connectionId, totalResources]) => ({ connectionId, connectionName: nameById.get(connectionId) ?? connectionId, totalResources }))
      .sort((a, b) => b.totalResources - a.totalResources)
      .slice(0, 5);

    return okJson({
      totalAccounts: connections.length,
      healthyAccounts: healthy,
      failedAccounts: failed,
      disconnectedAccounts: disconnected,
      accountsNeedingAttention: needingAttention,
      accountsNeedingAttentionList: needingAttentionList,
      resourcesDiscovered: resourceRows.length,
      regionsCovered,
      lastDiscovery,
      nextScheduledDiscovery: null,
      discoverySuccessRate: null,
      permissionErrors: syncFailures,
      syncFailures,
      monthlyCost: Math.round(Array.from(costByConnection.values()).reduce((s, v) => s + v, 0) * 100) / 100,
      topCostAccounts,
      topGrowingAccounts,
      openRecommendations: recommendationRows.length,
      potentialMonthlySavings: Math.round(recommendationRows.reduce((s, r) => s + Number(r.potential_monthly_savings || 0), 0) * 100) / 100,
      rotationDue,
      recentActivity: activityRows.map((row) => ({ id: row.id, action: row.action, targetId: row.target_id, occurredAt: row.created_at, actorEmail: row.profiles?.email ?? null })),
      recentAlerts: alertRows.map((row) => ({ id: row.id, alertName: row.alert_name, severity: row.severity, connectionId: row.connection_id, triggeredAt: row.triggered_at })),
    });
  }),
);

/** GET /api/aws-accounts/sync-status — last sync/discovery/validation timestamps per account. */
dashboardRoutes.get('/sync-status', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const rows = await db.select<ConnectionRow[]>('cloud_connections', {
      select: 'id,connection_name,status,last_sync_at,last_discovery_at,last_permission_check_at,error_message',
      filters: { org_id: `eq.${orgId}`, provider: 'eq.aws' },
      order: 'last_sync_at.desc.nullslast',
    });
    return okJson({ accounts: rows });
  }),
);

/** GET /api/aws-accounts/health — per-account health rollup (status + resource_summary + error state). */
dashboardRoutes.get('/health', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const rows = await db.select<ConnectionRow[]>('cloud_connections', {
      select: 'id,connection_name,status,error_message,resource_summary,last_discovery_at',
      filters: { org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });

    const healthy = rows.filter((r) => r.status === 'connected' && !r.error_message).length;
    const unhealthy = rows.filter((r) => r.status === 'error' || r.status === 'expired' || Boolean(r.error_message)).length;

    return okJson({ healthy, unhealthy, total: rows.length, accounts: rows });
  }),
);
