import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, writeAuditLog, guarded, okJson, errJson, type Db, requirePermittedConnection } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { resolveCredentials, type ResolvableConnection } from './permissions';
import { discoverCurReport, fetchCurManifest, parseCurBatch, type CurConnectionConfig } from '../lib/curIngest';

export const curRoutes = new Hono<{ Bindings: Env }>();

interface CurConnectionRow extends ResolvableConnection {
  cur_report_name: string | null;
  cur_s3_bucket: string | null;
  cur_s3_prefix: string | null;
  cur_s3_region: string | null;
}

async function loadConnection(db: Db, orgId: string, userId: string | null, id: string): Promise<CurConnectionRow | null> {
  // Compile-enforced authorization: `userId` is required so every call site
  // has to decide. An id + org_id filter proves only that the connection
  // belongs to the caller's org, never that this caller is permitted it.
  // Pass null ONLY from internal/scheduled paths that run without a user.
  if (userId) await requirePermittedConnection(db, orgId, userId, id);
  const rows = await db.select<CurConnectionRow[]>('cloud_connections', {
    select: 'id,connection_method,credentials_encrypted,role_arn,external_id,default_region,cur_report_name,cur_s3_bucket,cur_s3_prefix,cur_s3_region',
    filters: { id: `eq.${id}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
  });
  return rows[0] ?? null;
}

/** POST /api/aws-accounts/accounts/:id/cur/discover — finds the customer's own Cost & Usage Report via cur:DescribeReportDefinitions (no manual S3 bucket entry needed) and saves it on the connection. */
curRoutes.post('/accounts/:id/cur/discover', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    const connection = await loadConnection(db, orgId, auth.userId, c.req.param('id'));
    if (!connection) return errJson(404, 'Account not found');
    const resolved = await resolveCredentials(c.env, connection);
    if ('error' in resolved) return errJson(400, resolved.error);

    const result = await discoverCurReport(resolved.creds);
    if ('error' in result) return errJson(404, result.error);

    const { report } = result;
    await db.update('cloud_connections', { id: `eq.${connection.id}` }, {
      cur_report_name: report.ReportName, cur_s3_bucket: report.S3Bucket, cur_s3_prefix: report.S3Prefix, cur_s3_region: report.S3Region,
    }, 'return=minimal');

    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'aws_account.cur_discovered', targetType: 'cloud_connection', targetId: connection.id, metadata: { reportName: report.ReportName, bucket: report.S3Bucket } });
    return okJson({ reportName: report.ReportName, bucket: report.S3Bucket, prefix: report.S3Prefix, region: report.S3Region });
  }),
);

/** GET /api/aws-accounts/accounts/:id/cur/manifest — the current billing period's manifest (the list of data files to ingest). */
curRoutes.get('/accounts/:id/cur/manifest', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    const connection = await loadConnection(db, orgId, auth.userId, c.req.param('id'));
    if (!connection) return errJson(404, 'Account not found');
    if (!connection.cur_s3_bucket || !connection.cur_s3_prefix || !connection.cur_report_name || !connection.cur_s3_region) {
      return errJson(400, 'No Cost & Usage Report configured for this account yet — run Discover first.');
    }
    const resolved = await resolveCredentials(c.env, connection);
    if ('error' in resolved) return errJson(400, resolved.error);

    const config: CurConnectionConfig = { cur_s3_bucket: connection.cur_s3_bucket, cur_s3_prefix: connection.cur_s3_prefix, cur_report_name: connection.cur_report_name, cur_s3_region: connection.cur_s3_region };
    const result = await fetchCurManifest(resolved.creds, config);
    if ('error' in result) return errJson(404, result.error);

    return okJson({ billingPeriod: result.billingPeriod, reportKeys: result.manifest.reportKeys });
  }),
);

interface IngestStepBody {
  reportKey?: string;
  skipRows?: number;
}

/**
 * POST /api/aws-accounts/accounts/:id/cur/ingest-step — parses and upserts
 * the next batch of rows from one CUR data file. Aggregates multiple line
 * items for the same resource+day within this batch before upserting
 * (a resource commonly has several CUR rows per day — usage, surcharges,
 * etc.) — a real but accepted limitation is that line items for the same
 * resource+day split across two different steps' batches will overwrite
 * rather than sum, since PostgREST upsert has no additive mode.
 */
/**
 * REMOVED (Phase 12 verification pass): `POST .../cur/ingest-step`, the
 * per-chunk endpoint the browser's unbounded ingest loop used to call.
 *
 * Phase 7 replaced it with server-owned cur-runs; the route stayed mounted
 * and I wrongly reported it removed after probing it with the wrong method.
 * Ingestion is an idempotent upsert, so this could not corrupt data -- but
 * it could advance a billing period's ingest with nothing recording where
 * it stopped, which is the exact defect Phase 7 exists to fix.
 */

/**
 * POST /accounts/:id/cur/finalize was REMOVED (Phase B cleanup, 2026-09-10).
 *
 * It stamped `cur_last_synced_at = now()` unconditionally, with no check that
 * any report file had actually completed -- a direct bypass of the property
 * curWorkflow.ts:markCurSyncComplete exists to hold, which stamps that column
 * ONLY when every file finished. `cur_last_synced_at` is what the UI reads as
 * "cost data current as of", so an authenticated caller could mark cost data
 * current without a single row having been ingested.
 *
 * The durable cur-runs path stamps it correctly and is the only writer now.
 */
