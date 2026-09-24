import {
  Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission,
  requirePermittedConnection, getActiveScope, guarded, okJson, errJson, type Db, type Env,
} from '@horizonvigil/shared-lib';
import { isConnectionPurgeEnabled } from '../lib/capabilities';

/**
 * §12.2 — disconnect impact preview.
 *
 * Answers "what happens if I do this?" BEFORE the customer does it, for the
 * two destructive-ish actions on a connection.
 *
 * The two are not the same and the preview refuses to blur them:
 *
 *   Disconnect          soft. A status flip. Collection stops; every row is
 *                       retained and the account can be reconnected.
 *   Delete permanently  irreversible, cascading across 29 tables. Currently
 *                       server-denied (CONNECTION_PURGE_ENABLED), and the
 *                       preview says so rather than implying it is available.
 *
 * Counts are read live. A preview that showed a stale count would be worse
 * than none: the number is the whole basis on which someone decides.
 */
export const disconnectImpactRoutes = new Hono<{ Bindings: Env }>();

/**
 * Tables whose rows a permanent delete would remove, chosen because a
 * customer recognises them. This is NOT the full cascade set (29 tables);
 * `cascadeTableCount` reports the real total so the list is not mistaken for
 * the whole story.
 */
const COUNTED_TABLES: readonly { table: string; label: string }[] = [
  { table: 'cloud_resources', label: 'Discovered resources' },
  { table: 'cost_snapshots', label: 'Daily cost records' },
  { table: 'cost_recommendations', label: 'Cost recommendations' },
  { table: 'collection_runs', label: 'Collection runs' },
  { table: 'connection_validation_runs', label: 'Permission validations' },
  { table: 'alerts', label: 'Alerts' },
  { table: 'cloud_identities', label: 'IAM identities' },
  { table: 'ingestion_batches', label: 'Ingestion batches' },
  { table: 'resource_observations', label: 'Resource observations (lineage)' },
  { table: 'quarantine_records', label: 'Quarantined records' },
];

/**
 * FKs to cloud_connections that are NOT ON DELETE CASCADE.
 *
 * Verified against the live schema 2026-09-10: `incidents` and
 * `verification_runs` are NO ACTION. A permanent delete with rows in either
 * does not cascade -- it FAILS on a foreign-key violation. Surfacing this in
 * the preview means the customer learns it before pressing the button rather
 * than from an opaque database error afterwards.
 */
const BLOCKING_TABLES: readonly string[] = ['incidents', 'verification_runs'];

async function countRows(db: Db, table: string, connectionId: string): Promise<number | null> {
  try {
    const [, total] = await db.selectWithCount<unknown[]>(table, {
      select: 'id',
      filters: { connection_id: `eq.${connectionId}` },
      limit: 1,
    });
    return total;
  } catch {
    // A table this deployment does not have, or one the caller cannot read.
    // null, never 0: "we could not count" and "there are none" are different
    // answers and only one of them is safe to act on.
    return null;
  }
}

/** GET /accounts/:id/disconnect-impact — what each action would actually do. */
disconnectImpactRoutes.get('/accounts/:id/disconnect-impact', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const id = c.req.param('id');
    // Authorization first. This throws (and the shared guard maps it to 404,
    // not 403) so the endpoint cannot be used to confirm an id exists.
    await requirePermittedConnection(db, orgId, auth.userId, id, getActiveScope(c.req.raw, orgId));

    const [connection] = await db.select<{ aws_account_id: string | null; connection_name: string | null; status: string | null }[]>(
      'cloud_connections',
      { select: 'aws_account_id,connection_name,status', filters: { id: `eq.${id}`, org_id: `eq.${orgId}`, provider: 'eq.aws' }, limit: 1 },
    );
    if (!connection) return errJson(404, 'Account not found');

    const [counts, blocking] = await Promise.all([
      Promise.all(COUNTED_TABLES.map(async (t) => ({ ...t, rows: await countRows(db, t.table, id) }))),
      Promise.all(BLOCKING_TABLES.map(async (t) => ({ table: t, rows: await countRows(db, t, id) }))),
    ]);

    const unreadable = counts.filter((c2) => c2.rows === null).map((c2) => c2.table);
    const knownTotal = counts.reduce((n, c2) => n + (c2.rows ?? 0), 0);
    const blockers = blocking.filter((b) => (b.rows ?? 0) > 0);

    return okJson({
      connectionId: id,
      accountId: connection.aws_account_id ?? null,
      connectionName: connection.connection_name ?? null,
      currentStatus: connection.status ?? null,

      disconnect: {
        reversible: true,
        summary: 'Stops collection. Nothing is deleted, and the account can be reconnected.',
        stops: [
          'Scheduled and manual resource discovery',
          'Scheduled cost synchronisation',
          'Permission validation',
          'Alert evaluation for this account',
        ],
        retains: [
          'All discovered resources and their history',
          'All cost records',
          'All recommendations',
          'All audit and activity history',
          'Stored credentials, so reconnection does not require re-entering keys',
        ],
        note: 'Dashboards and totals will stop including this account once collection stops, because its data will go stale rather than because it was removed.',
      },

      permanentDelete: {
        reversible: false,
        /**
         * Read live from the environment, never assumed. A preview that said
         * this was available while the server returns 403 would be the same
         * false-capability problem in a new place.
         */
        available: isConnectionPurgeEnabled(c.env),
        unavailableReason: isConnectionPurgeEnabled(c.env)
          ? null
          : 'Permanent deletion is disabled on this deployment. Disconnect is available and preserves history.',
        summary: 'Irreversibly removes this connection and everything linked to it.',
        /** The full cascade breadth, so the itemised list below is not read as exhaustive. */
        cascadeTableCount: 29,
        wouldDelete: counts.map((c2) => ({ label: c2.label, table: c2.table, rows: c2.rows })),
        /**
         * Stated separately from the counts. A total that silently omitted
         * tables it could not read would understate the loss.
         */
        countedRows: knownTotal,
        uncountedTables: unreadable,
        countIsComplete: unreadable.length === 0,
        /**
         * These do not cascade. With rows present, a permanent delete fails
         * with a foreign-key violation instead of completing -- better learned
         * here than from a database error.
         */
        blockedBy: blockers.map((b) => ({ table: b.table, rows: b.rows })),
        wouldFail: blockers.length > 0,
      },
    });
  }),
);
