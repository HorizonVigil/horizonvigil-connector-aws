import { Hono, createDb, getActiveScope, getAuthContext, getOrgConnectionIds, guarded, inFilter, okJson, requireMenuPermission, requireOrgId } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { capabilityEvidence, costSourceEvidence, inventoryEvidence, type CapabilityFact, type CostSourceFact, type InventoryRunFact } from '../lib/evidenceContract';
import { selectAllPages } from '../lib/pagedSelect';

export const evidenceRoutes = new Hono<{ Bindings: Env }>();

interface ConnectionFact { id: string; aws_account_id: string; connection_name: string }
interface RunFact extends InventoryRunFact { connection_id: string }
interface CapabilityRow extends CapabilityFact { connection_id: string }
interface CostSourceRow extends CostSourceFact { connection_id: string }

/**
 * Stable, tenant-scoped AWS evidence for Horizon Intelligence & Advisor.
 *
 * This endpoint exports verdicts and their limitations. It deliberately does
 * not export decrypted credentials, raw provider payloads, or an unqualified
 * resource/cost/finding total. Consumers can follow rawEvidenceReference to
 * the owning endpoint when a human needs the underlying record.
 */
evidenceRoutes.get('/evidence', (c) => guarded(async () => {
  const auth = getAuthContext(c.req.raw);
  const orgId = requireOrgId(c.req.raw);
  const db = createDb(c.env, auth.accessToken);
  await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

  const permitted = await getOrgConnectionIds(db, orgId, auth.userId, getActiveScope(c.req.raw, orgId));
  const requested = c.req.query('connection_id')?.trim();
  const ids = requested ? permitted.filter((id) => id === requested) : permitted;
  if (ids.length === 0) return okJson({ version: '1', provider: 'aws', items: [], retrievedAt: new Date().toISOString() });

  const [connectionPage, capabilityPage, costSourcePage] = await Promise.all([
    selectAllPages<ConnectionFact>(db, 'cloud_connections', {
      select: 'id,aws_account_id,connection_name', filters: { id: inFilter(ids), org_id: `eq.${orgId}`, provider: 'eq.aws' }, order: 'id.asc',
    }),
    selectAllPages<CapabilityRow>(db, 'connector_capability_status', {
      select: 'connection_id,capability,state,reason_code,last_attempt_at,last_success_at,freshness_slo_seconds,permission_snapshot_id,updated_at',
      filters: { connection_id: inFilter(ids), org_id: `eq.${orgId}` }, order: 'connection_id.asc,capability.asc',
    }),
    selectAllPages<CostSourceRow>(db, 'cost_source_status', {
      select: 'connection_id,source_type,state,reason_code,covered_period_start,covered_period_end,last_attempt_at,last_success_at,source_observed_at,freshness_slo_seconds,record_count,updated_at',
      filters: { connection_id: inFilter(ids), org_id: `eq.${orgId}` }, order: 'connection_id.asc,source_type.asc',
    }),
  ]);

  const connections = connectionPage.rows;
  const capabilities = capabilityPage.rows;
  const costSources = costSourcePage.rows;
  // PostgREST cannot express "latest row per connection" without an RPC.
  // Querying one bounded row per permitted AWS connection is deliberate: a
  // global limit lets a noisy account's history hide another account.
  const runs: RunFact[] = [];
  for (let start = 0; start < connections.length; start += 20) {
    const batch = connections.slice(start, start + 20);
    const rows = await Promise.all(batch.map(async (connection) => {
      const latest = await db.select<RunFact[]>('collection_runs', {
        select: 'id,connection_id,status,total_steps,completed_steps,failed_steps,degraded_resource_types,finished_at,started_at',
        filters: { connection_id: `eq.${connection.id}`, org_id: `eq.${orgId}`, capability: 'eq.inventory' }, order: 'queued_at.desc', limit: 1,
      });
      return latest[0] ?? null;
    }));
    runs.push(...rows.filter((row): row is RunFact => row !== null));
  }

  const retrievedAt = new Date().toISOString();
  const latestRun = new Map<string, RunFact>();
  for (const run of runs) if (!latestRun.has(run.connection_id)) latestRun.set(run.connection_id, run);
  const accountByConnection = new Map(connections.map((row) => [row.id, row.aws_account_id]));
  const items = connections.map((connection) => inventoryEvidence({
    orgId, connectionId: connection.id, awsAccountId: connection.aws_account_id, run: latestRun.get(connection.id) ?? null, retrievedAt,
  }));
  for (const row of capabilities) {
    const awsAccountId = accountByConnection.get(row.connection_id);
    if (awsAccountId) items.push(capabilityEvidence({ orgId, connectionId: row.connection_id, awsAccountId, row, retrievedAt }));
  }
  for (const row of costSources) {
    const awsAccountId = accountByConnection.get(row.connection_id);
    if (awsAccountId) items.push(costSourceEvidence({ orgId, connectionId: row.connection_id, awsAccountId, row, retrievedAt }));
  }

  return okJson({
    version: '1', provider: 'aws', retrievedAt, items,
    limitations: [
      ...(connections.length === 0 ? ['No AWS connections are available in the selected scope.'] : []),
      ...(!connectionPage.complete || !capabilityPage.complete || !costSourcePage.complete ? ['One or more evidence tables could not be read completely.'] : []),
    ],
  });
}));
