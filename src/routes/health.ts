import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, getOrgConnectionIds, getActiveScope, inFilter, guarded, okJson, errJson, requirePermittedConnection } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { computeHealth, summarizeHealth, type HealthConnectionInput, type HealthValidationInput } from '../lib/health';

export const healthRoutes = new Hono<{ Bindings: Env }>();

interface ConnRow extends HealthConnectionInput {
  connection_name: string;
  environment: string;
  aws_account_id: string;
}

interface RunRow {
  id: string;
  connection_id: string;
  status: string;
  finished_at: string | null;
  error_message: string | null;
  started_at: string;
}

const HEALTH_SELECT =
  'id,connection_name,environment,aws_account_id,status,connection_method,error_message,last_sync_at,last_discovery_at,last_permission_check_at,key_rotated_at';

/** Latest validation run per connection + its denied/errored check counts, in two bounded queries. */
async function latestRunsWithCounts(
  db: ReturnType<typeof createDb>,
  connectionIds: string[],
): Promise<Map<string, HealthValidationInput>> {
  const out = new Map<string, HealthValidationInput>();
  if (connectionIds.length === 0) return out;

  const runs = await db.select<RunRow[]>('connection_validation_runs', {
    select: 'id,connection_id,status,finished_at,error_message,started_at',
    filters: { connection_id: inFilter(connectionIds) },
    order: 'started_at.desc',
    limit: 2000,
  });

  const latestByConn = new Map<string, RunRow>();
  for (const r of runs) if (!latestByConn.has(r.connection_id)) latestByConn.set(r.connection_id, r);

  const latestRunIds = [...latestByConn.values()].map((r) => r.id);
  const checks = latestRunIds.length
    ? await db.select<{ run_id: string; status: string }[]>('connection_permission_checks', {
        select: 'run_id,status',
        filters: { run_id: inFilter(latestRunIds) },
        limit: 5000,
      })
    : [];

  const deniedByRun = new Map<string, number>();
  const erroredByRun = new Map<string, number>();
  for (const ck of checks) {
    if (ck.status === 'denied') deniedByRun.set(ck.run_id, (deniedByRun.get(ck.run_id) ?? 0) + 1);
    if (ck.status === 'error') erroredByRun.set(ck.run_id, (erroredByRun.get(ck.run_id) ?? 0) + 1);
  }

  for (const [connId, run] of latestByConn) {
    out.set(connId, {
      status: run.status,
      finished_at: run.finished_at,
      error_message: run.error_message,
      deniedChecks: deniedByRun.get(run.id) ?? 0,
      erroredChecks: erroredByRun.get(run.id) ?? 0,
    });
  }
  return out;
}

/**
 * GET /api/aws-accounts/health/detailed — the spec §8/§37 explainable-health
 * view: one entry per AWS connection, each with its five named signals and a
 * documented weighted score (see lib/health.ts), plus a roll-up. Every input
 * is a live query against this org's own `cloud_connections` +
 * `connection_validation_runs` — nothing stored, nothing simulated.
 */
healthRoutes.get('/health/detailed', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    // Bounded by the permitted set, not the org: this response renders
    // connection names, status and health directly, so an org-wide read
    // disclosed accounts outside the caller's grants and outside the
    // active folder/project scope.
    const permittedIds = await getOrgConnectionIds(db, orgId, auth.userId, getActiveScope(c.req.raw, orgId));

    const connections = await db.select<ConnRow[]>('cloud_connections', {
      select: HEALTH_SELECT,
      filters: { id: inFilter(permittedIds), org_id: `eq.${orgId}`, provider: 'eq.aws' },
      limit: 5000,
    });

    const runs = await latestRunsWithCounts(db, connections.map((conn) => conn.id));
    const now = Date.now();

    const accounts = connections.map((conn) => {
      const health = computeHealth(conn, runs.get(conn.id) ?? null, now);
      return {
        connectionName: conn.connection_name,
        provider: 'aws' as const,
        identifier: conn.aws_account_id,
        environment: conn.environment,
        ...health,
      };
    });

    return okJson({ provider: 'aws', accounts, summary: summarizeHealth(accounts) });
  }),
);

/**
 * GET /api/aws-accounts/accounts/:id/health — one connection's health, with
 * the same signal breakdown, for the account-detail Health/Access views.
 */
healthRoutes.get('/accounts/:id/health', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    // Authorize the caller for THIS connection before reading it: an
    // id + org_id filter proves org ownership, not that this caller is
    // permitted the connection (resource grants / active scope).
    await requirePermittedConnection(db, orgId, auth.userId, c.req.param('id'), getActiveScope(c.req.raw, orgId));
    const rows = await db.select<ConnRow[]>('cloud_connections', {
      select: HEALTH_SELECT,
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const conn = rows[0];
    if (!conn) return errJson(404, 'Account not found');

    const runs = await latestRunsWithCounts(db, [conn.id]);
    const health = computeHealth(conn, runs.get(conn.id) ?? null, Date.now());

    return okJson({
      connectionName: conn.connection_name,
      provider: 'aws',
      identifier: conn.aws_account_id,
      environment: conn.environment,
      ...health,
    });
  }),
);

/**
 * GET /accounts/:id/capabilities — per-capability health (§2.3, §6.2).
 *
 * The blended per-connection score cannot express "inventory is fine but Cost
 * Explorer is denied". This returns the state of each capability with the
 * permission snapshot that proves it, so every claim can be drilled into
 * rather than taken on trust.
 */
healthRoutes.get('/accounts/:id/capabilities', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const id = c.req.param('id');
    await requirePermittedConnection(db, orgId, auth.userId, id, getActiveScope(c.req.raw, orgId));

    const rows = await db.select<Record<string, unknown>[]>('connector_capability_status', {
      select: 'capability,state,reason_code,source,expected_scope,covered_scope,last_attempt_at,last_success_at,permission_snapshot_id,updated_at',
      filters: { connection_id: `eq.${id}`, org_id: `eq.${orgId}` },
      order: 'capability.asc',
      limit: 100,
    });

    return okJson({
      items: rows,
      total: rows.length,
      // An empty list is "never evaluated", not "all healthy" -- stated
      // explicitly so a client cannot read absence as success.
      evaluated: rows.length > 0,
      explanation: rows.length === 0
        ? 'Capability health has not been evaluated for this connection yet. Run Validate Permissions to populate it.'
        : null,
    });
  }),
);
