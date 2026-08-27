import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, requireMenuPermissionWithAbac, writeAuditLog, guarded, okJson, errJson, parsePagination, paginatedEnvelope, HttpError, enforceRateLimit, checkCloudAccountLimit } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { encryptCredentials, maskAccessKey, looksLikeValidAccessKeyId } from '../lib/crypto';

export const accountsRoutes = new Hono<{ Bindings: Env }>();

const LIST_SELECT =
  'id,org_id,project_id,connection_method,aws_account_id,connection_name,masked_access_key,external_id,role_arn,default_region,status,environment,support_plan,resource_summary,last_discovery_at,last_full_scan_at,last_sync_at,key_rotated_at,error_message,scan_regions,created_at,updated_at';

/** GET /api/aws-accounts/accounts — Account Inventory, paginated + filterable. */
accountsRoutes.get('/accounts', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const url = new URL(c.req.url);
    const pagination = parsePagination(url);
    const filters: Record<string, string> = { org_id: `eq.${orgId}`, provider: 'eq.aws' };
    const status = url.searchParams.get('status');
    const environment = url.searchParams.get('environment');
    const method = url.searchParams.get('connectionMethod');
    const region = url.searchParams.get('region');
    const search = url.searchParams.get('search');
    if (status) filters.status = `eq.${status}`;
    if (environment) filters.environment = `eq.${environment}`;
    if (method) filters.connection_method = `eq.${method}`;
    if (region) filters.scan_regions = `cs.{${region}}`;
    if (search) {
      // Name-or-account-ID search — PostgREST's `or=(...)` combinator, scoped to
      // org_id via the separate `filters.org_id` entry above (PostgREST ANDs
      // distinct query keys). buildQuery URL-encodes this whole value once, so
      // `search` is interpolated raw here, same convention as every other ilike
      // filter in this codebase (see resources-api/src/routes/search.ts).
      filters.or = `(connection_name.ilike.*${search}*,aws_account_id.ilike.*${search}*)`;
    }

    const sortParam = url.searchParams.get('sort');
    const sortDir = url.searchParams.get('sortDir') === 'desc' ? 'desc' : 'asc';
    const SORTABLE_COLUMNS = new Set(['connection_name', 'aws_account_id', 'status', 'environment', 'default_region', 'last_sync_at', 'created_at']);
    const order = sortParam && SORTABLE_COLUMNS.has(sortParam) ? `${sortParam}.${sortDir}` : 'created_at.desc';

    const [rows, total] = await db.selectWithCount('cloud_connections', {
      select: LIST_SELECT,
      filters,
      order,
      limit: pagination.limit,
      offset: pagination.offset,
    });

    return okJson(paginatedEnvelope(rows as unknown[], total, pagination));
  }),
);

/** GET /api/aws-accounts/accounts/:id */
accountsRoutes.get('/accounts/:id', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const rows = await db.select('cloud_connections', {
      select: LIST_SELECT,
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const account = (rows as unknown[])[0];
    if (!account) return errJson(404, 'Account not found');
    return okJson(account);
  }),
);

interface ConnectBody {
  connectionName?: string;
  connectionMethod?: 'access_key' | 'cross_account_role';
  awsAccountId?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  roleArn?: string;
  externalId?: string;
  defaultRegion?: string;
  environment?: string;
  scanRegions?: string[];
  projectId?: string | null;
}

/** POST /api/aws-accounts/accounts — Account Onboarding. Requires admin/owner (matches the connect/disconnect role boundary). */
accountsRoutes.post('/accounts', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'admin');
    // Previously unlimited -- a single admin session could hammer this
    // endpoint with no backstop at all. 30/hour comfortably covers a real
    // onboarding session (even a large one, added one account at a time)
    // without capping normal use; genuinely bulk onboarding belongs on
    // POST /accounts/bulk-import-from-organization (bulkImport.ts), which
    // has its own, much stricter limit.
    await enforceRateLimit(db, `aws-account:connect:${orgId}`, 30, 3600);
    // Soft, non-blocking -- checked before the insert so `used` reflects the
    // count this new account is about to join, not after. Never rejects the
    // connect itself; only surfaces a real upgrade prompt in the response.
    const limitCheck = await checkCloudAccountLimit(db, orgId);

    const body = (await c.req.json().catch(() => ({}))) as ConnectBody;
    if (!body.connectionName) return errJson(400, 'connectionName is required');
    if (!body.awsAccountId || !/^\d{12}$/.test(body.awsAccountId)) return errJson(400, 'awsAccountId must be a 12-digit AWS account id');
    if (body.connectionMethod !== 'access_key' && body.connectionMethod !== 'cross_account_role') {
      return errJson(400, "connectionMethod must be 'access_key' or 'cross_account_role'");
    }

    const insert: Record<string, unknown> = {
      org_id: orgId,
      project_id: body.projectId ?? null,
      provider: 'aws',
      connection_method: body.connectionMethod,
      aws_account_id: body.awsAccountId,
      connection_name: body.connectionName,
      default_region: body.defaultRegion ?? 'us-east-1',
      environment: body.environment ?? 'production',
      scan_regions: body.scanRegions ?? undefined,
      status: 'pending',
      created_by: auth.userId,
      credentials_encrypted: {},
    };

    if (body.connectionMethod === 'access_key') {
      if (!body.accessKeyId || !looksLikeValidAccessKeyId(body.accessKeyId)) return errJson(400, 'accessKeyId does not look like a valid AWS access key id');
      if (!body.secretAccessKey || body.secretAccessKey.length < 20) return errJson(400, 'secretAccessKey is required');
      insert.credentials_encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, {
        accessKeyId: body.accessKeyId,
        secretAccessKey: body.secretAccessKey,
      });
      insert.masked_access_key = maskAccessKey(body.accessKeyId);
      insert.key_rotated_at = new Date().toISOString();
    } else {
      if (!body.roleArn || !/^arn:aws:iam::\d{12}:role\//.test(body.roleArn)) return errJson(400, 'roleArn must be a valid IAM role ARN');
      insert.role_arn = body.roleArn;
      insert.external_id = body.externalId || crypto.randomUUID();
    }

    const [created] = await db.insert<Record<string, unknown>[]>('cloud_connections', insert);
    await writeAuditLog(db, {
      orgId,
      actorId: auth.userId,
      action: 'aws_account.connected',
      targetType: 'cloud_connection',
      targetId: String(created.id),
      metadata: { connectionMethod: body.connectionMethod, awsAccountId: body.awsAccountId },
    });

    const { credentials_encrypted: _omit, ...safe } = created;
    return okJson({ ...safe, planLimitWarning: limitCheck.atLimit ? limitCheck.message : null }, 201);
  }),
);

interface UpdateBody {
  connectionName?: string;
  environment?: string;
  projectId?: string | null;
  defaultRegion?: string;
  scanRegions?: string[];
  supportPlan?: string | null;
}

/**
 * PUT /api/aws-accounts/accounts/:id — update name/environment/project/regions.
 * Editor and above by default -- but this is also the first real ABAC
 * integration point in the codebase: requireMenuPermissionWithAbac checks
 * the org's abac_policies (if any) against this specific connection's own
 * environment before falling back to the plain role/menu-permission check,
 * so an org can define e.g. "deny cloud write access to users whose
 * department != Platform when resource.environment == production" without
 * that policy needing any code change here -- see cloudops-shared-lib's
 * abac.ts for the evaluator and cloudops-admin's abac-policies routes for
 * how policies get authored.
 */
accountsRoutes.put('/accounts/:id', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);

    const [existing] = await db.select<{ environment: string }[]>('cloud_connections', {
      select: 'environment',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    if (!existing) return errJson(404, 'Account not found');
    await requireMenuPermissionWithAbac(db, auth.userId, orgId, 'cloud', 'write', { environment: existing.environment, provider: 'aws' });

    const body = (await c.req.json().catch(() => ({}))) as UpdateBody;
    const patch: Record<string, unknown> = {};
    if (body.connectionName !== undefined) patch.connection_name = body.connectionName;
    if (body.environment !== undefined) patch.environment = body.environment;
    if (body.projectId !== undefined) patch.project_id = body.projectId;
    if (body.defaultRegion !== undefined) patch.default_region = body.defaultRegion;
    if (body.scanRegions !== undefined) patch.scan_regions = body.scanRegions;
    if (body.supportPlan !== undefined) patch.support_plan = body.supportPlan;
    if (Object.keys(patch).length === 0) return errJson(400, 'No updatable fields provided');
    patch.updated_at = new Date().toISOString();

    const rows = await db.update<Record<string, unknown>[]>('cloud_connections', { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' }, patch);
    if (!rows.length) return errJson(404, 'Account not found');

    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'aws_account.updated', targetType: 'cloud_connection', targetId: c.req.param('id'), metadata: patch });
    const { credentials_encrypted: _omit, ...safe } = rows[0];
    return okJson(safe);
  }),
);

interface UpdateCredentialsBody {
  accessKeyId?: string;
  secretAccessKey?: string;
}

/**
 * PUT /api/aws-accounts/accounts/:id/credentials — re-supply credentials for
 * an access-key connection: rotation, or re-encrypting under a new
 * ENCRYPTION_KEY after a key rotation (disconnect+re-add hits the
 * org_id+aws_account_id unique constraint since disconnect is a soft
 * status-flip, not a row delete — this updates the existing row in place so
 * connection_id, and everything keyed off it — resources, cost history,
 * validation runs, audit log — stays intact). Resets status to 'pending'
 * since the new credentials haven't been validated yet.
 */
accountsRoutes.put('/accounts/:id/credentials', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');
    await enforceRateLimit(db, `aws-account:rotate-credentials:${orgId}`, 30, 3600);

    const rows = await db.select<{ id: string; connection_method: string }[]>('cloud_connections', {
      select: 'id,connection_method',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const account = rows[0];
    if (!account) return errJson(404, 'Account not found');
    if (account.connection_method !== 'access_key') {
      return errJson(400, 'Only access-key connections store credentials to update — cross-account-role connections re-resolve automatically via sts:AssumeRole.');
    }

    const body = (await c.req.json().catch(() => ({}))) as UpdateCredentialsBody;
    if (!body.accessKeyId || !looksLikeValidAccessKeyId(body.accessKeyId)) return errJson(400, 'accessKeyId does not look like a valid AWS access key id');
    if (!body.secretAccessKey || body.secretAccessKey.length < 20) return errJson(400, 'secretAccessKey is required');

    const credentials_encrypted = await encryptCredentials(c.env.ENCRYPTION_KEY, {
      accessKeyId: body.accessKeyId,
      secretAccessKey: body.secretAccessKey,
    });

    const updated = await db.update<Record<string, unknown>[]>(
      'cloud_connections',
      { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
      {
        credentials_encrypted,
        masked_access_key: maskAccessKey(body.accessKeyId),
        key_rotated_at: new Date().toISOString(),
        status: 'pending',
        error_message: null,
        updated_at: new Date().toISOString(),
      },
    );

    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'aws_account.credentials_updated', targetType: 'cloud_connection', targetId: c.req.param('id') });
    const { credentials_encrypted: _omit, ...safe } = updated[0];
    return okJson(safe);
  }),
);

interface UpdateRoleBody {
  roleArn?: string;
  externalId?: string;
}

/**
 * PUT /api/aws-accounts/accounts/:id/role — re-supply role ARN/external ID
 * for a cross-account-role connection. Same "update in place" pattern and
 * reason as /credentials above — the org_id+aws_account_id unique constraint
 * blocks a disconnect+re-add regardless of connection method, so this is
 * the only real way to fix a cross-account-role connection whose role was
 * misconfigured or needs re-pointing.
 */
accountsRoutes.put('/accounts/:id/role', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    const rows = await db.select<{ id: string; connection_method: string }[]>('cloud_connections', {
      select: 'id,connection_method',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const account = rows[0];
    if (!account) return errJson(404, 'Account not found');
    if (account.connection_method !== 'cross_account_role') {
      return errJson(400, 'Only cross-account-role connections have a role to update — access-key connections use /credentials instead.');
    }

    const body = (await c.req.json().catch(() => ({}))) as UpdateRoleBody;
    if (!body.roleArn || !/^arn:aws:iam::\d{12}:role\//.test(body.roleArn)) return errJson(400, 'roleArn must be a valid IAM role ARN');
    if (!body.externalId) return errJson(400, 'externalId is required');

    const updated = await db.update<Record<string, unknown>[]>(
      'cloud_connections',
      { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
      { role_arn: body.roleArn, external_id: body.externalId, status: 'pending', error_message: null, updated_at: new Date().toISOString() },
    );

    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'aws_account.role_updated', targetType: 'cloud_connection', targetId: c.req.param('id') });
    const { credentials_encrypted: _omit, ...safe } = updated[0];
    return okJson(safe);
  }),
);

/**
 * DELETE /api/aws-accounts/accounts/:id — Disconnect. Implemented as a
 * status transition rather than a hard row delete: cloud_resources,
 * cost_snapshots, and friends all carry a connection_id foreign key, and
 * this pass has no visibility into whether those were defined with
 * ON DELETE CASCADE — a status flip is non-destructive either way and
 * keeps the account's history intact for audit/reporting.
 */
accountsRoutes.delete('/accounts/:id', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'admin');

    const rows = await db.update<Record<string, unknown>[]>(
      'cloud_connections',
      { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
      { status: 'disconnected', updated_at: new Date().toISOString() },
    );
    if (!rows.length) return errJson(404, 'Account not found');

    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'aws_account.disconnected', targetType: 'cloud_connection', targetId: c.req.param('id') });
    return okJson({ disconnected: c.req.param('id') });
  }),
);

/**
 * DELETE /api/aws-accounts/accounts/:id/permanently — hard delete, cascading
 * to every table with a connection_id FK (cloud_resources, cost_snapshots,
 * connection_validation_runs, alerts, and friends — all ON DELETE CASCADE
 * per the live schema). Unlike DELETE /accounts/:id (Disconnect, a soft
 * status-flip that preserves history and is *why* /credentials and /role
 * above exist — Disconnect alone can't free an AWS Account ID for
 * reconnection), this is genuinely irreversible. Admin/owner only, same bar
 * as Disconnect.
 */
accountsRoutes.delete('/accounts/:id/permanently', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'admin');

    const rows = await db.select<{ id: string; connection_name: string; aws_account_id: string }[]>('cloud_connections', {
      select: 'id,connection_name,aws_account_id',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const account = rows[0];
    if (!account) return errJson(404, 'Account not found');

    await db.remove('cloud_connections', { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' }, 'return=minimal');

    await writeAuditLog(db, {
      orgId,
      actorId: auth.userId,
      action: 'aws_account.deleted_permanently',
      targetType: 'cloud_connection',
      targetId: account.id,
      metadata: { connectionName: account.connection_name, awsAccountId: account.aws_account_id },
    });

    return okJson({ deleted: account.id });
  }),
);

/**
 * POST /api/aws-accounts/accounts/:id/test — re-validate stored credentials.
 * No live AWS call is made in this pass (that's the discovery/scanning
 * engine, explicitly out of scope here — see docs/about-project.md); this
 * checks that credentials are present and well-formed and reports that
 * honestly rather than faking a live sts:GetCallerIdentity result.
 */
accountsRoutes.post('/accounts/:id/test', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    const rows = await db.select<Record<string, unknown>[]>('cloud_connections', {
      select: 'id,connection_method,credentials_encrypted,role_arn,external_id',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const account = rows[0];
    if (!account) throw new HttpError(404, 'Account not found');

    const hasCredentials =
      account.connection_method === 'access_key'
        ? Boolean((account.credentials_encrypted as Record<string, unknown> | null)?.ciphertext)
        : Boolean(account.role_arn && account.external_id);

    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'aws_account.test_triggered', targetType: 'cloud_connection', targetId: c.req.param('id') });

    return okJson({
      credentialsPresent: hasCredentials,
      liveValidation: false,
      message: hasCredentials
        ? 'Credentials are stored and well-formed. Live validation against AWS (sts:GetCallerIdentity) requires the discovery engine, not built in this pass.'
        : 'No credentials stored for this connection method.',
    });
  }),
);
