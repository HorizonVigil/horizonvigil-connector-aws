import { Hono, getAuthContext, requireOrgId, createDb, requireRole, writeAuditLog, guarded, okJson, errJson, type Db } from '@cloudops360/shared-lib';
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

async function loadConnection(db: Db, orgId: string, id: string): Promise<CurConnectionRow | null> {
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
    await requireRole(db, auth.userId, orgId, ['editor'], true);

    const connection = await loadConnection(db, orgId, c.req.param('id'));
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
    await requireRole(db, auth.userId, orgId, ['editor'], true);

    const connection = await loadConnection(db, orgId, c.req.param('id'));
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
curRoutes.post('/accounts/:id/cur/ingest-step', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireRole(db, auth.userId, orgId, ['editor'], true);

    const body = (await c.req.json().catch(() => ({}))) as IngestStepBody;
    if (!body.reportKey) return errJson(400, 'reportKey is required');
    const skipRows = body.skipRows ?? 0;

    const connection = await loadConnection(db, orgId, c.req.param('id'));
    if (!connection) return errJson(404, 'Account not found');
    if (!connection.cur_s3_bucket || !connection.cur_s3_region) return errJson(400, 'No Cost & Usage Report configured for this account yet.');
    const resolved = await resolveCredentials(c.env, connection);
    if ('error' in resolved) return errJson(400, resolved.error);

    const result = await parseCurBatch(resolved.creds, connection.cur_s3_bucket, connection.cur_s3_region, body.reportKey, skipRows);
    if ('error' in result) return errJson(400, result.error);

    if (result.costRows.length > 0) {
      const grouped = new Map<string, { resource_id: string; service: string; region: string | null; usage_date: string; unblended_cost: number }>();
      for (const row of result.costRows) {
        const key = `${row.resource_id}:${row.usage_date}`;
        const existing = grouped.get(key);
        if (existing) existing.unblended_cost += row.unblended_cost;
        else grouped.set(key, { ...row });
      }
      const rows = Array.from(grouped.values()).map((row) => ({ connection_id: connection.id, ...row, unblended_cost: Math.round(row.unblended_cost * 100) / 100 }));
      await db.insert('resource_costs?on_conflict=connection_id,resource_id,usage_date', rows, 'resolution=merge-duplicates,return=minimal');
    }

    return okJson({ rowsProcessed: result.rowsProcessed, rowsIngestedThisBatch: result.rowsIngestedThisBatch, done: result.done });
  }),
);

/** POST /api/aws-accounts/accounts/:id/cur/finalize — called once after every reportKey finishes ingesting; records the sync timestamp. */
curRoutes.post('/accounts/:id/cur/finalize', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireRole(db, auth.userId, orgId, ['editor'], true);

    const connection = await loadConnection(db, orgId, c.req.param('id'));
    if (!connection) return errJson(404, 'Account not found');

    const now = new Date().toISOString();
    await db.update('cloud_connections', { id: `eq.${connection.id}` }, { cur_last_synced_at: now }, 'return=minimal');
    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'aws_account.cur_synced', targetType: 'cloud_connection', targetId: connection.id });
    return okJson({ syncedAt: now });
  }),
);
