import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, getOrgConnectionIds, inFilter, writeAuditLog, guarded, okJson, errJson, type Db, getActiveScope, requirePermittedConnection } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { callJsonApi, type AwsCreds } from '../lib/awsApi';
import { resolveCredentials, type ResolvableConnection } from './permissions';
import { triggerAnomalyDetection } from '../lib/postScanHooks';
import { ensureBillingPeriod, writeCostFacts } from '../lib/costFacts';
import { recordCostSourceState, stateForFailure, stateForSuccess } from '../lib/costSourceState';

const MAX_CONNECTIONS_PER_COST_SYNC_RUN = 5;

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

export interface SyncTarget {
  id: string;
  aws_account_id: string;
  /**
   * Optional so every existing caller and test keeps working unchanged.
   *
   * cost_facts and cost_source_status are org-scoped, so without it the
   * Phase 3c writes are skipped rather than attributed to the wrong tenant.
   * Skipping is the right failure here: a cost fact with no tenant is worse
   * than a missing one.
   */
  org_id?: string;
}

/**
 * Pure transform: a raw GetCostAndUsage response body -> the exact
 * cost_snapshots rows to write. Extracted out of syncConnectionCost so this
 * (the part with actual branching logic — zero-cost filtering, the
 * Keys[0]/'Unknown' and Unit/'USD' fallbacks) is unit-testable against a
 * hand-built fixture without needing a live AWS call or a real Db.
 */
/** A decimal amount exactly as AWS wrote it: digits, optional sign, optional fraction. */
const DECIMAL_AMOUNT = /^-?\d+(\.\d+)?$/;

export interface CostSnapshotBuild {
  rows: Record<string, unknown>[];
  /**
   * Rows AWS returned that were deliberately not stored because they are
   * exactly zero. Counted rather than silently dropped -- see the note in
   * buildCostSnapshotRows.
   */
  zeroCostRowsSkipped: number;
  /**
   * Rows whose amount was absent or not a valid decimal. NEVER treated as
   * zero: an amount we could not read is not an amount of nothing.
   */
  unreadableRows: number;
}

export function buildCostSnapshotRows(body: { ResultsByTime?: CostExplorerResult[] }, connection: SyncTarget): CostSnapshotBuild {
  const rows: Record<string, unknown>[] = [];
  let zeroCostRowsSkipped = 0;
  let unreadableRows = 0;

  for (const period of body.ResultsByTime ?? []) {
    for (const group of period.Groups ?? []) {
      const raw = group.Metrics?.UnblendedCost?.Amount;

      /**
       * Kept as the exact decimal STRING AWS sent.
       *
       * This previously read `Number(... ?? 0)`, which lost precision before
       * the value ever reached the database -- `cost_snapshots.unblended_cost`
       * is Postgres `numeric` (exact) and was being handed an already-lossy
       * double. Passing the string through lets Postgres parse it exactly.
       */
      if (typeof raw !== 'string' || !DECIMAL_AMOUNT.test(raw.trim())) {
        // `?? 0` used to turn a missing amount into a zero-cost row, which
        // was then dropped by the filter below -- so an unreadable amount
        // vanished entirely. Absence is not zero, and it is not nothing.
        unreadableRows += 1;
        continue;
      }
      const amount = raw.trim();

      /**
       * Exactly-zero rows are still skipped, and that is a deliberate
       * storage trade-off with a real cost: Cost Explorer returns a row per
       * service per day including every service billing nothing, so storing
       * them would multiply this table by an order of magnitude.
       *
       * The consequence, stated rather than hidden: `cost_snapshots` row
       * count is NOT the number of rows AWS returned, so it cannot on its own
       * establish a proven zero or satisfy an observed-vs-expected
       * reconciliation. `zeroCostRowsSkipped` is returned so the caller can
       * account for the difference instead of discovering the gap later.
       */
      if (/^-?0(\.0+)?$/.test(amount)) {
        zeroCostRowsSkipped += 1;
        continue;
      }

      rows.push({
        connection_id: connection.id,
        account_id: connection.aws_account_id,
        usage_date: period.TimePeriod.Start,
        service: group.Keys[0] || 'Unknown',
        unblended_cost: amount,
        currency: group.Metrics.UnblendedCost.Unit || 'USD',
      });
    }
  }
  return { rows, zeroCostRowsSkipped, unreadableRows };
}

/**
 * The real ce:GetCostAndUsage call (month-to-date, daily granularity,
 * grouped by service) plus the cost_snapshots write — extracted so both the
 * user-triggered route below and the new service-role-authenticated
 * /internal/run-due-cost-syncs route call the exact same real billing logic,
 * not two copies that could drift. Re-syncing replaces this month's rows for
 * the connection rather than appending, so re-running it is safe and
 * idempotent.
 */
async function syncConnectionCost(db: Db, creds: AwsCreds, connection: SyncTarget): Promise<{ ok: true; synced: number; start: string; end: string; zeroCostRowsSkipped: number; unreadableRows: number; costFacts: { inserted: number; unchanged: number; restated: number; restatedFingerprints: string[] } } | { ok: false; status: number; message: string }> {
  const start = monthStartIso();
  const end = todayIso();

  const result = await callJsonApi(creds, {
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
    /**
     * Phase 3c: a failed sync now records WHICH kind of failure.
     *
     * "Cost Explorer is not enabled" is an opt-in state the customer fixes in
     * one click; a 403 on a configured source is a policy problem; a 500 is
     * ours or AWS's. Collapsing them is how someone gets sent to fix an IAM
     * policy that was already correct -- and how all three end up rendering
     * as $0.
     */
    if (connection.org_id) {
      await recordCostSourceState(
        db,
        { orgId: connection.org_id, connectionId: connection.id, sourceType: 'COST_EXPLORER', payerAccountId: connection.aws_account_id ?? null },
        stateForFailure(result.status, message),
      );
    }
    return { ok: false, status: result.status === 403 ? 403 : 502, message };
  }

  const built = buildCostSnapshotRows(result.body as { ResultsByTime?: CostExplorerResult[] }, connection);
  const snapshotRows = built.rows;

  // Replace this month's snapshots for this connection rather than
  // appending — makes a re-sync idempotent instead of duplicating rows
  // (cost_snapshots has no unique constraint PostgREST can upsert against
  // via this client without a matching on_conflict column list).
  await db.remove('cost_snapshots', { connection_id: `eq.${connection.id}`, usage_date: `gte.${start}` }, 'return=minimal');
  if (snapshotRows.length > 0) {
    await db.insert('cost_snapshots', snapshotRows, 'return=minimal');
  }

  /**
   * Phase 3c: dual-write into cost_facts alongside cost_snapshots.
   *
   * EXPAND, not cutover (§34). cost_snapshots keeps serving every current
   * read path untouched; cost_facts accumulates the authoritative model in
   * parallel so it can be validated against the old one before anything
   * depends on it.
   *
   * Unlike the snapshot path above, this is NOT delete-and-replace. Replacing
   * would make a restatement indistinguishable from an ordinary re-sync and
   * would destroy the previous amount, which §15/§17 require to stay
   * auditable.
   */
  let factResult = { inserted: 0, unchanged: 0, restated: 0, restatedFingerprints: [] as string[] };
  if (connection.org_id) {
    const factCtx = {
      orgId: connection.org_id,
      connectionId: connection.id,
      payerAccountId: connection.aws_account_id ?? null,
      sourceType: 'COST_EXPLORER' as const,
    };
    const factInputs = snapshotRows.map((r) => ({
      usageDate: String(r.usage_date),
      service: String(r.service),
      region: (r.region as string | null) ?? null,
      linkedAccountId: (r.account_id as string | null) ?? null,
      amount: String(r.unblended_cost),
      currency: String(r.currency),
    }));

    try {
      if (factInputs.length > 0) await ensureBillingPeriod(db, factCtx, factInputs[0].usageDate);
      factResult = await writeCostFacts(db, factCtx, factInputs);
    } catch {
      // The dual-write must not fail a sync that already stored its
      // snapshots. A gap in cost_facts is visible; a lost sync is not.
    }

    /**
     * State is judged on coverage, not on the request having returned 200.
     * A sync covering some requested accounts is PARTIAL, and a total built
     * from it must not be presented as the organisation's spend -- nor as $0
     * if the uncovered accounts held the cost.
     */
    const covered = [...new Set(snapshotRows.map((r) => String(r.account_id)))];
    const requested = connection.aws_account_id ? [connection.aws_account_id] : [];
    await recordCostSourceState(
      db,
      { orgId: connection.org_id, connectionId: connection.id, sourceType: 'COST_EXPLORER', payerAccountId: connection.aws_account_id ?? null },
      {
        ...stateForSuccess({ requestedAccountIds: requested, coveredAccountIds: covered, sourceObservedAt: null }),
        recordCount: snapshotRows.length,
        currency: snapshotRows.length > 0 ? String(snapshotRows[0].currency) : null,
        coveredPeriodStart: start,
        coveredPeriodEnd: end,
      },
      requested,
      covered,
    );
  }

  return {
    ok: true,
    synced: snapshotRows.length,
    start,
    end,
    // Reported so a caller can reconcile stored rows against what AWS
    // actually returned, rather than assuming they are the same number.
    zeroCostRowsSkipped: built.zeroCostRowsSkipped,
    unreadableRows: built.unreadableRows,
    costFacts: factResult,
  };
}

/**
 * POST /api/aws-accounts/accounts/:id/cost/sync — the cost ingestion this
 * domain has never had: a real ce:GetCostAndUsage call using the
 * connection's own stored credentials, written into cost_snapshots. Every
 * other cost surface in this codebase (Cost Management, Overview, this
 * domain's own /cost) reads from that table; until this endpoint existed,
 * nothing ever wrote to it. See syncConnectionCost() above for the shared
 * logic also used by the scheduled /internal/run-due-cost-syncs route below.
 */
costRoutes.post('/accounts/:id/cost/sync', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    // Authorize the caller for THIS connection before reading it: an
    // id + org_id filter proves org ownership, not that this caller is
    // permitted the connection (resource grants / active scope).
    await requirePermittedConnection(db, orgId, auth.userId, c.req.param('id'), getActiveScope(c.req.raw, orgId));
    const rows = await db.select<(ResolvableConnection & { aws_account_id: string })[]>('cloud_connections', {
      select: 'id,org_id,aws_account_id,connection_method,credentials_encrypted,role_arn,external_id,default_region',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const connection = rows[0];
    if (!connection) return errJson(404, 'Account not found');

    const resolved = await resolveCredentials(c.env, connection);
    if ('error' in resolved) return errJson(400, resolved.error);

    const outcome = await syncConnectionCost(db, resolved.creds, connection);
    if (!outcome.ok) {
      await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'aws_account.cost_sync_failed', targetType: 'cloud_connection', targetId: connection.id, metadata: { reason: outcome.message } });
      return errJson(outcome.status, outcome.message);
    }

    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'aws_account.cost_synced', targetType: 'cloud_connection', targetId: connection.id, metadata: { rowCount: outcome.synced, start: outcome.start, end: outcome.end } });

    return okJson({ synced: outcome.synced, start: outcome.start, end: outcome.end });
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

    const connectionIds = await getOrgConnectionIds(db, orgId, auth.userId, getActiveScope(c.req.raw, orgId));
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

interface CostSyncDue { id: string; org_id: string; aws_account_id: string; cost_sync_interval_hours: number }

/**
 * POST /internal/run-due-cost-syncs — cost ingestion has been 100%
 * click-triggered since it existed (every route above requires a real
 * logged-in user's session). This is the server-side scheduled equivalent,
 * mirroring internalScan.ts's own /internal/run-due-scans in every way that
 * matters: a shared secret (INTERNAL_COST_SYNC_SECRET, its own value —
 * see env.ts for why) authenticates a Cloud Scheduler job instead of a
 * user, SUPABASE_SERVICE_ROLE_KEY bypasses RLS since there's no per-user
 * token to forward, and the due-connection query/advance-next-run shape is
 * identical, just against cost_sync_enabled/cost_sync_interval_hours/
 * next_scheduled_cost_sync_at instead of the scan-scheduling columns.
 *
 * Capped at MAX_CONNECTIONS_PER_COST_SYNC_RUN per invocation — one
 * Cost Explorer call per connection is far cheaper than a full resource
 * scan, so this cap exists for the same "never let one invocation run
 * unbounded" reason as run-due-scans, not because of a comparable timeout
 * risk; a connection not reached this cycle is simply picked up next tick
 * (its next_scheduled_cost_sync_at isn't advanced until it actually runs).
 *
 * Triggers anomaly detection after each successful sync via
 * triggerAnomalyDetection() (lib/postScanHooks.ts) — the scheduled path's
 * equivalent of the manual path's "detect right after a Sync Cost click"
 * behavior — best-effort, same as every other postScanHooks call in this
 * codebase.
 */
costRoutes.post('/internal/run-due-cost-syncs', (c) =>
  guarded(async () => {
    const secret = c.req.header('x-internal-scan-secret');
    if (!c.env.INTERNAL_COST_SYNC_SECRET) return errJson(503, 'INTERNAL_COST_SYNC_SECRET is not configured — scheduled cost sync is not active in this environment.');
    if (!c.env.SUPABASE_SERVICE_ROLE_KEY) return errJson(503, 'SUPABASE_SERVICE_ROLE_KEY is not configured — scheduled cost sync cannot authenticate to the database in this environment.');
    if (secret !== c.env.INTERNAL_COST_SYNC_SECRET) return errJson(403, 'Invalid or missing X-Internal-Scan-Secret.');

    const db = createDb(c.env, c.env.SUPABASE_SERVICE_ROLE_KEY);
    const now = new Date().toISOString();

    const due = await db.select<CostSyncDue[]>('cloud_connections', {
      select: 'id,org_id,aws_account_id,cost_sync_interval_hours',
      filters: {
        provider: 'eq.aws', cost_sync_enabled: 'eq.true',
        or: `(next_scheduled_cost_sync_at.is.null,next_scheduled_cost_sync_at.lte.${now})`,
        status: 'neq.pending',
      },
      limit: MAX_CONNECTIONS_PER_COST_SYNC_RUN,
    });

    const results: { connectionId: string; synced?: number; error?: string }[] = [];
    for (const row of due) {
      const connectionRows = await db.select<(ResolvableConnection & { aws_account_id: string })[]>('cloud_connections', {
        select: 'id,org_id,aws_account_id,connection_method,credentials_encrypted,role_arn,external_id,default_region',
        filters: { id: `eq.${row.id}` },
      });
      const connection = connectionRows[0];
      if (!connection) continue;

      const resolved = await resolveCredentials(c.env, connection);
      if ('error' in resolved) {
        await writeAuditLog(db, { orgId: row.org_id, actorId: null, action: 'aws_account.cost_sync_failed', targetType: 'cloud_connection', targetId: row.id, metadata: { reason: resolved.error, trigger: 'scheduled' } });
        results.push({ connectionId: row.id, error: resolved.error });
        continue;
      }

      const outcome = await syncConnectionCost(db, resolved.creds, connection);
      const nextSync = new Date(Date.now() + row.cost_sync_interval_hours * 60 * 60 * 1000).toISOString();
      await db.update('cloud_connections', { id: `eq.${row.id}` }, { next_scheduled_cost_sync_at: nextSync }, 'return=minimal');

      if (!outcome.ok) {
        await writeAuditLog(db, { orgId: row.org_id, actorId: null, action: 'aws_account.cost_sync_failed', targetType: 'cloud_connection', targetId: row.id, metadata: { reason: outcome.message, trigger: 'scheduled' } });
        results.push({ connectionId: row.id, error: outcome.message });
        continue;
      }

      await writeAuditLog(db, { orgId: row.org_id, actorId: null, action: 'aws_account.cost_synced', targetType: 'cloud_connection', targetId: row.id, metadata: { rowCount: outcome.synced, start: outcome.start, end: outcome.end, trigger: 'scheduled' } });
      await triggerAnomalyDetection(c.env, row.id);
      results.push({ connectionId: row.id, synced: outcome.synced });
    }

    return okJson({ connectionsSynced: results.length, results });
  }),
);
