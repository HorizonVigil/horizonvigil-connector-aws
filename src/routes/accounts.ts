import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, requireMenuPermissionWithAbac, writeAuditLog, guarded, okJson, errJson, parsePagination, paginatedEnvelope, HttpError, enforceRateLimit, checkCloudAccountLimit, getOrgConnectionIds, getActiveScope, inFilter, requirePermittedConnection, strongEtag, versionParts, requirePrecondition } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { encryptCredentials, maskAccessKey, looksLikeValidAccessKeyId } from '../lib/crypto';
import { validateCandidate, activateCandidate, rollbackToPrevious } from '../lib/credentialRotation';
import { isConnectionPurgeEnabled, purgeDisabledResponse, isAssumeRoleEnabled, assumeRoleDisabledResponse } from '../lib/capabilities';

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
    // The account list is a permitted-set read, not just an org read.
    //
    // Filtering on org_id alone made this endpoint bypass BOTH controls that
    // are supposed to bound it: resource grants (Phase 0.7 -- a user with no
    // grants gets no connections from getOrgConnectionIds, yet still saw every
    // account in the org here) and the active folder/project scope (Phase 1 --
    // selecting a folder left the full global account list on screen, which is
    // one of the specific symptoms the 2026-09-08 audits reported).
    //
    // getOrgConnectionIds already applies org membership, grants and scope, so
    // intersecting on `id` is the whole fix. inFilter([]) yields a filter that
    // matches nothing, so "no permitted accounts" renders as an empty list
    // rather than falling open to the org.
    const permittedIds = await getOrgConnectionIds(db, orgId, auth.userId, getActiveScope(c.req.raw, orgId));
    const filters: Record<string, string> = { id: inFilter(permittedIds), org_id: `eq.${orgId}`, provider: 'eq.aws' };
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

    // Same permitted-set check as the list route above: org membership alone
    // let any member fetch any connection in the org by id, regardless of
    // resource grants. 404 rather than 403 so the response doesn't confirm
    // that an id the caller may not see exists.
    const id = c.req.param('id');
    const permittedIds = await getOrgConnectionIds(db, orgId, auth.userId, getActiveScope(c.req.raw, orgId));
    if (!permittedIds.includes(id)) return errJson(404, 'Account not found');

    const rows = await db.select('cloud_connections', {
      select: LIST_SELECT,
      filters: { id: `eq.${id}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
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
    // AWS-P0-02: the cross-account role path is not certified (the product's
    // own UI says live sts:AssumeRole scanning is not wired up). Refuse it
    // here rather than only in the wizard, so a direct API call cannot create
    // a connection that can never collect.
    if (body.connectionMethod === 'cross_account_role' && !isAssumeRoleEnabled(c.env)) {
      return assumeRoleDisabledResponse();
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

    /**
     * Duplicate connections are a DOMAIN conflict, not a database error.
     *
     * 2026-09-08 AWS connector audit, AWS-P0-03: the create flow used to let
     * the unique-constraint failure reach the browser, which matched on the
     * raw constraint name (`cloud_connections_org_id_aws_account_id_key`) and
     * then called updateAccountCredentials/updateAccountRole -- so a second
     * "Add account" submit silently ROTATED the credentials of an existing
     * connection. Creating and rotating are different operations with
     * different blast radius, and one must never become the other.
     *
     * Disconnect is a soft status flip rather than a row delete, so a
     * disconnected account still occupies the (org_id, aws_account_id) key.
     * That case is reported explicitly, because "already connected" would be
     * confusing for a connection the user deliberately disconnected.
     */
    const existingRows = await db.select<{ id: string; connection_name: string; status: string }[]>('cloud_connections', {
      select: 'id,connection_name,status',
      filters: { org_id: `eq.${orgId}`, provider: 'eq.aws', aws_account_id: `eq.${body.awsAccountId}` },
    });
    const existing = existingRows[0];
    if (existing) {
      return c.json(
        {
          ok: false,
          code: 'connection_already_exists',
          error:
            existing.status === 'disconnected'
              ? `AWS account ${body.awsAccountId} already has a disconnected connection in this organization. Reconnect it instead of creating a new one.`
              : `AWS account ${body.awsAccountId} is already connected to this organization.`,
          existingConnection: { id: existing.id, name: existing.connection_name, status: existing.status },
        },
        409,
      );
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

    const [existing] = await db.select<{ id: string; environment: string; updated_at: string | null }[]>('cloud_connections', {
      select: 'id,environment,updated_at',
      filters: { id: `eq.${c.req.param('id')}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    if (!existing) return errJson(404, 'Account not found');
    await requireMenuPermissionWithAbac(db, auth.userId, orgId, 'cloud', 'write', { environment: existing.environment, provider: 'aws' });

    /**
     * §14.4 optimistic concurrency.
     *
     * The failure this prevents is quiet, which is why it needs a mechanism
     * rather than care: two people open this connection's settings, one
     * changes the scan regions and the other the schedule, and the second
     * save overwrites the first with a payload built from stale data.
     * Nothing errors and nothing is logged; the first person finds their
     * change missing days later and reasonably concludes we lost it.
     *
     * `required: false` while the client is migrated. A caller that sends
     * no If-Match keeps working exactly as before; a caller that sends a
     * STALE one is refused either way, so opting out of the requirement
     * does not opt out of the check. The ETag is returned on every response
     * below so clients can adopt it before it is enforced.
     */
    const etag = await strongEtag(versionParts(existing));
    requirePrecondition(c.req.header('If-Match'), etag, { required: false });

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
    // The NEW version, so the client can chain a second edit without
    // re-reading -- and so a client that just adopted If-Match has
    // somewhere to get its first value.
    const newEtag = await strongEtag(versionParts(safe as { id?: unknown; updated_at?: unknown }));
    return okJson(safe, 200, { ETag: newEtag });
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

    const rows = await db.select<{ id: string; connection_method: string; aws_account_id: string; credentials_encrypted: unknown }[]>('cloud_connections', {
      select: 'id,connection_method,aws_account_id,credentials_encrypted',
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

    /**
     * Validate BEFORE activating (§5, AWS-P0-03).
     *
     * This used to encrypt the new keys straight over the live credential,
     * set the connection to `pending`, and rely on a later validation to
     * notice a problem. A typo therefore took a working connection down, and
     * the credential that worked had already been destroyed -- nothing to
     * roll back to.
     *
     * Now: prove the candidate, archive the outgoing secret, then swap. A
     * failed candidate never touches the live connection, so the worst
     * outcome of a bad paste is an error message.
     */
    const candidate = { accessKeyId: body.accessKeyId, secretAccessKey: body.secretAccessKey };
    const validation = await validateCandidate(c.env, candidate, account.aws_account_id);
    if (!validation.ok) {
      await writeAuditLog(db, {
        orgId, actorId: auth.userId, action: 'aws_account.credential_rotation_rejected',
        targetType: 'cloud_connection', targetId: c.req.param('id'),
        metadata: { code: validation.code },
      });
      return c.json({ ok: false, code: validation.code, error: validation.message }, 400);
    }

    const versionId = await activateCandidate(db, c.env, {
      orgId,
      connectionId: account.id,
      actorId: auth.userId,
      candidate,
      identityArn: validation.identityArn ?? null,
      accountId: validation.accountId ?? null,
      outgoingEncrypted: account.credentials_encrypted,
    });

    await writeAuditLog(db, {
      orgId, actorId: auth.userId, action: 'aws_account.credentials_rotated',
      targetType: 'cloud_connection', targetId: c.req.param('id'),
      metadata: { versionId, identityArn: validation.identityArn, rollbackAvailable: Boolean(account.credentials_encrypted) },
    });

    const rows2 = await db.select<Record<string, unknown>[]>('cloud_connections', {
      select: LIST_SELECT,
      filters: { id: `eq.${account.id}` },
    });
    return okJson({ ...rows2[0], credentialVersionId: versionId, validatedIdentity: validation.identityArn });
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
/**
 * POST /accounts/:id/credentials/rollback — restore the previous credential.
 *
 * Only possible because activation archives the outgoing encrypted blob
 * before overwriting it. Without that step this endpoint could exist but
 * could not do anything, which is worse than not offering it.
 */
accountsRoutes.post('/accounts/:id/credentials/rollback', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');
    await requirePermittedConnection(db, orgId, auth.userId, c.req.param('id'), getActiveScope(c.req.raw, orgId));

    const result = await rollbackToPrevious(db, c.req.param('id'));
    if (!result.ok) return c.json({ ok: false, code: result.code, error: result.message }, 409);

    await writeAuditLog(db, {
      orgId, actorId: auth.userId, action: 'aws_account.credential_rollback',
      targetType: 'cloud_connection', targetId: c.req.param('id'),
      metadata: { restoredVersionId: result.versionId },
    });
    return okJson({ restoredVersionId: result.versionId });
  }),
);

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

    // Same gate as create: an un-certified method must not be reachable by
    // updating an existing connection into it either.
    if (!isAssumeRoleEnabled(c.env)) return assumeRoleDisabledResponse();

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
    // Phase 0.6 (2026-09-08 audits): permanent purge is disabled by default.
    // Checked before any auth/DB work so a crafted request cannot probe for a
    // connection's existence. Disconnect remains available and preserves
    // history. See lib/capabilities.ts for the full list of missing controls.
    if (!isConnectionPurgeEnabled(c.env)) return purgeDisabledResponse();

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
