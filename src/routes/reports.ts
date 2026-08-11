import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, getOrgConnectionIds, inFilter, guarded, errJson, type Env } from '@cloudops360/shared-lib';

export const reportsRoutes = new Hono<{ Bindings: Env }>();

const REPORT_KINDS = ['account-summary', 'health', 'permissions', 'sync', 'cost'] as const;
type ReportKind = typeof REPORT_KINDS[number];

function toCsv(headers: string[], rows: (string | number | null)[][]): string {
  const escape = (v: string | number | null) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  return [headers.map(escape).join(','), ...rows.map((row) => row.map(escape).join(','))].join('\n');
}

function csvResponse(csv: string, filename: string): Response {
  return new Response(csv, { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="${filename}"` } });
}

/**
 * GET /api/aws-accounts/reports/:kind — real CSV built from live query
 * results at request time (not a stored report row like reports-api's
 * domain — this is a lighter-weight, always-current export scoped to just
 * this domain's own data, matching "own API layer" from the spec).
 */
reportsRoutes.get('/reports/:kind', (c) =>
  guarded(async () => {
    const kind = c.req.param('kind') as ReportKind;
    if (!REPORT_KINDS.includes(kind)) return errJson(400, `kind must be one of: ${REPORT_KINDS.join(', ')}`);

    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const connectionIds = await getOrgConnectionIds(db, orgId, auth.userId);
    const connections = await db.select<Record<string, unknown>[]>('cloud_connections', {
      select: 'id,connection_name,aws_account_id,status,environment,connection_method,default_region,last_sync_at,last_permission_check_at,error_message',
      filters: { id: inFilter(connectionIds), provider: 'eq.aws' },
    });

    if (kind === 'account-summary') {
      const rows = connections.map((conn) => [conn.connection_name as string, conn.aws_account_id as string, conn.status as string, conn.environment as string, conn.connection_method as string, conn.default_region as string]);
      return csvResponse(toCsv(['Name', 'Account ID', 'Status', 'Environment', 'Method', 'Default Region'], rows), 'aws-accounts-summary.csv');
    }

    if (kind === 'sync') {
      const rows = connections.map((conn) => [conn.connection_name as string, (conn.last_sync_at as string) ?? 'Never', (conn.last_permission_check_at as string) ?? 'Never']);
      return csvResponse(toCsv(['Name', 'Last Sync', 'Last Permission Check'], rows), 'aws-accounts-sync.csv');
    }

    if (kind === 'health') {
      const rows = connections.map((conn) => [conn.connection_name as string, conn.status === 'connected' && !conn.error_message ? 'Healthy' : 'Unhealthy', (conn.error_message as string) ?? '']);
      return csvResponse(toCsv(['Name', 'Health', 'Error'], rows), 'aws-accounts-health.csv');
    }

    if (kind === 'cost') {
      const costRows = await db.select<{ connection_id: string; service: string; unblended_cost: string }[]>('cost_snapshots', {
        select: 'connection_id,service,unblended_cost',
        filters: { connection_id: inFilter(connectionIds), usage_date: `gte.${new Date(Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), 1)).toISOString().slice(0, 10)}` },
        limit: 5000,
      });
      const nameById = new Map(connections.map((conn) => [conn.id as string, conn.connection_name as string]));
      // cost_snapshots has one row per day per service — aggregate to one row
      // per account+service (same grouping as /accounts/:id/cost) instead of
      // dumping every raw daily snapshot, which for a 30-day month made every
      // service show up to 30 times over.
      const totalByKey = new Map<string, { account: string; service: string; total: number }>();
      for (const r of costRows) {
        const key = r.connection_id + '::' + r.service;
        const entry = totalByKey.get(key) ?? { account: nameById.get(r.connection_id) ?? r.connection_id, service: r.service, total: 0 };
        entry.total += Number(r.unblended_cost || 0);
        totalByKey.set(key, entry);
      }
      const rows = Array.from(totalByKey.values())
        .sort((a, b) => b.total - a.total)
        .map((e) => [e.account, e.service, Math.round(e.total * 100) / 100]);
      return csvResponse(toCsv(['Account', 'Service', 'Cost (USD, month to date)'], rows), 'aws-accounts-cost.csv');
    }

    // permissions
    const runs = await db.select<{ id: string; connection_id: string; status: string; started_at: string }[]>('connection_validation_runs', {
      select: 'id,connection_id,status,started_at',
      filters: { connection_id: inFilter(connectionIds) },
      order: 'started_at.desc',
      limit: 500,
    });
    const latestRunByConnection = new Map<string, { id: string; status: string; started_at: string }>();
    for (const run of runs) if (!latestRunByConnection.has(run.connection_id)) latestRunByConnection.set(run.connection_id, run);
    const runIds = Array.from(latestRunByConnection.values()).map((r) => r.id);
    const checks = runIds.length
      ? await db.select<{ run_id: string; service: string; status: string; detail: string }[]>('connection_permission_checks', { select: 'run_id,service,status,detail', filters: { run_id: inFilter(runIds) }, limit: 2000 })
      : [];
    const nameById = new Map(connections.map((conn) => [conn.id as string, conn.connection_name as string]));
    const rows: (string | number | null)[][] = [];
    for (const [connectionId, run] of latestRunByConnection) {
      for (const check of checks.filter((ck) => ck.run_id === run.id)) {
        rows.push([nameById.get(connectionId) ?? connectionId, check.service, check.status, check.detail]);
      }
    }
    return csvResponse(toCsv(['Account', 'Service', 'Status', 'Detail'], rows), 'aws-accounts-permissions.csv');
  }),
);
