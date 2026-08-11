import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, getOrgConnectionIds, inFilter, writeAuditLog, guarded, okJson, errJson } from '@cloudops360/shared-lib';
import type { Env } from '../env';
import { callJsonApi } from '../lib/awsApi';
import { resolveCredentials, type ResolvableConnection } from './permissions';

export const costRoutes = new Hono<{ Bindings: Env }>();

function monthStartIso(): string {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString().slice(0, 10);
}

function todayIso(): string {
  return new Date().toISOString().slice(0, 10);
}

interface CostExplorerGroup {
  Keys: string[];
  Metrics: { UnblendedCost: { Amount: string; Unit: string } };
}
interface CostExplorerResult {
  TimePeriod: { Start: string; End: string };
  Groups: CostExplorerGroup[];
}

/**
 * POST /api/aws-accounts/accounts/:id/cost/sync — the cost ingestion this
 * domain has never had: a real ce:GetCostAndUsage call (month-to-date,
 * daily granularity, grouped by service) using the connection's own stored
 * credentials, written into cost_snapshots. Every other cost surface in
 * this codebase (Cost Management, Overview, this domain's own /cost) reads
 * from that table; until this endpoint existed, nothing ever wrote to it.
 * Re-syncing replaces this month's rows for the connection rather than
 * appending, so re-running it is safe and idempotent. Zero-cost rows are
 * dropped at the source — AWS returns one row per service per day even at
 * $0, which is exactly what made the CSV report noisy before this existed.
 */
costRoutes.post('/accounts/:id/cost/sync', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    const rows = await db.select<(ResolvableConnection & { aws_account_id: string })[]>('cloud_connections', {
      select: 'id,aws_account_id,connection_method,credentials_encrypted,role_arn,external_id,default_region',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const connection = rows[0];
    if (!connection) return errJson(404, 'Account not found');

    const resolved = await resolveCredentials(c.env, connection);
    if ('error' in resolved) return errJson(400, resolved.error);

    const start = monthStartIso();
    const end = todayIso();

    const result = await callJsonApi(resolved.creds, {
      service: 'ce',
      region: 'us-east-1',
      host: 'ce.us-east-1.amazonaws.com',
      target: 'AWSInsightsIndexService.GetCostAndUsage',
      body: {
        TimePeriod: { Start: start, End: end },
        Granularity: 'DAILY',
        Metrics: ['UnblendedCost'],
        GroupBy: [{ Type: 'DIMENSION', Key: 'SERVICE' }],
      },
    });

    if (!result.ok) {
      const message = result.errorMessage ?? result.errorCode ?? `Cost Explorer request failed (HTTP ${result.status})`;
      await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'aws_account.cost_sync_failed', targetType: 'cloud_connection', targetId: connection.id, metadata: { reason: message } });
      return errJson(result.status === 403 ? 403 : 502, message);
    }

    const body = result.body as { ResultsByTime?: CostExplorerResult[] };
    const snapshotRows: Record<string, unknown>[] = [];
    for (const period of body.ResultsByTime ?? []) {
      for (const group of period.Groups ?? []) {
        const amount = Number(group.Metrics?.UnblendedCost?.Amount ?? 0);
        if (amount === 0) continue;
        snapshotRows.push({
          connection_id: connection.id,
          account_id: connection.aws_account_id,
          usage_date: period.TimePeriod.Start,
          service: group.Keys[0] || 'Unknown',
          unblended_cost: amount,
          currency: group.Metrics.UnblendedCost.Unit || 'USD',
        });
      }
    }

    // Replace this month's snapshots for this connection rather than
    // appending — makes a re-sync idempotent instead of duplicating rows
    // (cost_snapshots has no unique constraint PostgREST can upsert against
    // via this client without a matching on_conflict column list).
    await db.remove('cost_snapshots', { connection_id: `eq.${connection.id}`, usage_date: `gte.${start}` }, 'return=minimal');
    if (snapshotRows.length > 0) {
      await db.insert('cost_snapshots', snapshotRows, 'return=minimal');
    }

    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'aws_account.cost_synced', targetType: 'cloud_connection', targetId: connection.id, metadata: { rowCount: snapshotRows.length, start, end } });

    return okJson({ synced: snapshotRows.length, start, end });
  }),
);

/** GET /api/aws-accounts/accounts/:id/cost — one account's month-to-date cost + top services, from the same cost_snapshots table cost-management-api owns. */
costRoutes.get('/accounts/:id/cost', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const rows = await db.select<{ service: string; unblended_cost: string; usage_date: string }[]>('cost_snapshots', {
      select: 'service,unblended_cost,usage_date',
      filters: { connection_id: `eq.${c.req.param('id')}`, usage_date: `gte.${monthStartIso()}` },
      limit: 5000,
    });

    const byService: Record<string, number> = {};
    let monthToDate = 0;
    for (const row of rows) {
      const cost = Number(row.unblended_cost || 0);
      monthToDate += cost;
      byService[row.service] = (byService[row.service] ?? 0) + cost;
    }

    return okJson({ monthToDate: Math.round(monthToDate * 100) / 100, byService });
  }),
);

/** GET /api/aws-accounts/cost-summary — org-wide top-cost / fastest-growing accounts, for the AWS Accounts dashboard. */
costRoutes.get('/cost-summary', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const connectionIds = await getOrgConnectionIds(db, orgId, auth.userId);
    const [connections, costRows] = await Promise.all([
      db.select<{ id: string; connection_name: string }[]>('cloud_connections', { select: 'id,connection_name', filters: { id: inFilter(connectionIds), provider: 'eq.aws' } }),
      db.select<{ connection_id: string; unblended_cost: string }[]>('cost_snapshots', {
        select: 'connection_id,unblended_cost',
        filters: { connection_id: inFilter(connectionIds), usage_date: `gte.${monthStartIso()}` },
        limit: 5000,
      }),
    ]);

    const nameById = new Map(connections.map((conn) => [conn.id, conn.connection_name]));
    const costById = new Map<string, number>();
    for (const row of costRows) costById.set(row.connection_id, (costById.get(row.connection_id) ?? 0) + Number(row.unblended_cost || 0));

    const topCostAccounts = Array.from(costById.entries())
      .map(([connectionId, cost]) => ({ connectionId, connectionName: nameById.get(connectionId) ?? connectionId, monthToDate: Math.round(cost * 100) / 100 }))
      .sort((a, b) => b.monthToDate - a.monthToDate)
      .slice(0, 5);

    return okJson({ topCostAccounts, totalMonthToDate: Math.round(Array.from(costById.values()).reduce((s, v) => s + v, 0) * 100) / 100 });
  }),
);
