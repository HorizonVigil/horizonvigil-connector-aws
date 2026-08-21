import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, requireRole, writeAuditLog, guarded, okJson, errJson, enforceRateLimit, type Db } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { resolveCredentials, type ResolvableConnection } from './permissions';
import { listOrganizationAccounts, type OrgAccount } from '../lib/scanners/organizations';

export const bulkImportRoutes = new Hono<{ Bindings: Env }>();

/**
 * Fixed on purpose, not customer-chosen: templates/horizonvigil-scan-role-
 * stackset.yaml creates a role under this exact name in every member
 * account, which is what lets bulk-import derive each account's role ARN
 * from its account ID alone (arn:aws:iam::<id>:role/HorizonVigilRead)
 * instead of asking the customer to tell it account-by-account.
 */
const ROLE_NAME = 'HorizonVigilRead';
const MAX_ACCOUNTS_PER_BULK_IMPORT = 2000;

/** Every aws_account_id this org already has an AWS connection for, paginated to completion rather than one `in.(...)` filter -- at real scale (thousands of accounts) that filter's query string would risk the URL length AWS/Cloud Run infra actually allows through. */
async function existingAwsAccountIds(db: Db, orgId: string): Promise<Set<string>> {
  const ids = new Set<string>();
  let offset = 0;
  const limit = 1000;
  for (;;) {
    const [rows, total] = await db.selectWithCount<{ aws_account_id: string }[]>('cloud_connections', {
      select: 'aws_account_id',
      filters: { org_id: `eq.${orgId}`, provider: 'eq.aws' },
      limit, offset,
    });
    for (const r of rows) ids.add(r.aws_account_id);
    offset += rows.length;
    if (rows.length === 0 || offset >= total) break;
  }
  return ids;
}

/**
 * Generated once per org, on whichever request needs it first (either this
 * endpoint below, or bulk-import itself as a safety net) -- never
 * regenerated once set, since every member account a customer's StackSet
 * deployment touches has to trust the exact same value forever, and
 * bulk-import derives each new connection's external_id from this same
 * column, not from a fresh crypto call per account.
 */
async function getOrCreateOrgExternalId(db: Db, orgId: string): Promise<string> {
  const rows = await db.select<{ aws_org_external_id: string | null }[]>('organizations', {
    select: 'aws_org_external_id',
    filters: { id: `eq.${orgId}` },
  });
  const existing = rows[0]?.aws_org_external_id;
  if (existing) return existing;
  const generated = crypto.randomUUID();
  await db.update('organizations', { id: `eq.${orgId}` }, { aws_org_external_id: generated }, 'return=minimal');
  return generated;
}

/**
 * GET /api/aws-accounts/organizations/external-id — the value a customer
 * needs BEFORE deploying templates/horizonvigil-scan-role-stackset.yaml as
 * a StackSet (it's a required template parameter), so it has to be
 * obtainable on its own, not just handed back as bulk-import's own side
 * effect after the StackSet already exists. Same admin bar as connecting a
 * single account — this reveals a per-org secret-ish value, not the
 * blast-radius concern the bulk-import endpoint itself has.
 */
bulkImportRoutes.get('/organizations/external-id', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'admin');

    const externalId = await getOrCreateOrgExternalId(db, orgId);
    return okJson({ externalId, roleName: ROLE_NAME });
  }),
);

interface BulkImportBody {
  managementConnectionId?: string;
  projectId?: string | null;
  environment?: string;
}

/**
 * POST /api/aws-accounts/accounts/bulk-import-from-organization — the bulk
 * onboarding path the interactive per-account wizard genuinely can't reach
 * at a 2,000+-account scale (it creates one connection per submit). Requires
 * the customer to have already done two things outside this endpoint: (1)
 * connected their AWS Organizations management account (or a delegated
 * administrator) as a normal single connection via the existing POST
 * /accounts route -- this endpoint borrows THAT connection's own resolved
 * credentials for one organizations:ListAccounts call, the same
 * resolveCredentials() every other route in this file already uses, not a
 * new credential path; and (2) deployed templates/horizonvigil-scan-role-
 * stackset.yaml as a StackSet across their Organization/OU, parameterized
 * with the external ID from GET .../external-id above, so every member
 * account already has a HorizonVigilRead role trusting
 * PLATFORM_AWS_ACCOUNT_ID before this ever runs.
 *
 * Neither prerequisite is verified beyond what the AWS calls themselves
 * reveal here: a ListAccounts failure surfaces as a normal 400 (most likely
 * cause: the given connection isn't the management account); a missing or
 * misconfigured StackSet role only becomes visible once
 * /internal/run-first-scans (internalScan.ts) actually tries to assume it,
 * exactly like any other broken cross-account-role connection today —
 * and, on top of that, actually calling sts:AssumeRole against a
 * cross-account-role connection needs PLATFORM_AWS_ACCESS_KEY_ID/SECRET
 * (see resolveCredentials in permissions.ts), which is not provisioned in
 * this environment. Every connection this endpoint creates is real and
 * correctly shaped; whether it can ever actually authenticate is genuinely
 * unverifiable until that credential exists.
 *
 * requireRole(['owner']) rather than requireMenuPermission(..., 'admin'):
 * deliberately stricter than the single-account route, which any org admin
 * can call — this can create up to MAX_ACCOUNTS_PER_BULK_IMPORT connections
 * in one request, a blast radius that should need the org owner's own
 * sign-off, not just admin-level 'cloud' menu access. Rate-limited on top of
 * that (3/hour/org) since nothing about this action is time-sensitive enough
 * to need more, and a mistaken repeat call at this scale is expensive to
 * unwind.
 */
bulkImportRoutes.post('/accounts/bulk-import-from-organization', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireRole(db, auth.userId, orgId, ['owner']);
    await enforceRateLimit(db, `bulk-import:${orgId}`, 3, 3600);

    const body = (await c.req.json().catch(() => ({}))) as BulkImportBody;
    if (!body.managementConnectionId) {
      return errJson(400, 'managementConnectionId is required — connect your AWS Organizations management account first via the normal single-account flow, then bulk-import from it.');
    }

    const rows = await db.select<(ResolvableConnection & { id: string })[]>('cloud_connections', {
      select: 'id,connection_method,credentials_encrypted,role_arn,external_id,default_region',
      filters: { id: `eq.${body.managementConnectionId}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const managementConnection = rows[0];
    if (!managementConnection) return errJson(404, 'Management account connection not found.');

    const resolved = await resolveCredentials(c.env, managementConnection);
    if ('error' in resolved) return errJson(400, `Could not resolve credentials for the management account connection: ${resolved.error}`);

    const listed = await listOrganizationAccounts(resolved.creds);
    if (!listed.ok) return errJson(400, listed.error);

    const activeAccounts = listed.accounts.filter((a): a is OrgAccount & { Id: string } => a.Status === 'ACTIVE' && !!a.Id);
    const inactiveCount = listed.accounts.length - activeAccounts.length;
    if (activeAccounts.length > MAX_ACCOUNTS_PER_BULK_IMPORT) {
      return errJson(400, `This Organization has ${activeAccounts.length} active accounts, above this endpoint's ${MAX_ACCOUNTS_PER_BULK_IMPORT}-per-call safety limit. Contact HorizonVigil for a staged import.`);
    }

    const alreadyConnected = await existingAwsAccountIds(db, orgId);
    const toInsert = activeAccounts.filter((a) => !alreadyConnected.has(a.Id));

    if (toInsert.length === 0) {
      return okJson({ imported: 0, skippedAlreadyConnected: activeAccounts.length, skippedInactive: inactiveCount, connections: [] });
    }

    const externalId = await getOrCreateOrgExternalId(db, orgId);

    const inserted = await db.insert<{ id: string; aws_account_id: string }[]>(
      'cloud_connections',
      toInsert.map((a) => ({
        org_id: orgId,
        project_id: body.projectId ?? null,
        provider: 'aws',
        connection_method: 'cross_account_role',
        aws_account_id: a.Id,
        connection_name: a.Name ?? a.Id,
        role_arn: `arn:aws:iam::${a.Id}:role/${ROLE_NAME}`,
        external_id: externalId,
        default_region: 'us-east-1',
        environment: body.environment ?? 'production',
        status: 'pending',
        auto_scan_enabled: true,
        created_by: auth.userId,
        credentials_encrypted: {},
      })),
    );

    await writeAuditLog(db, {
      orgId,
      actorId: auth.userId,
      action: 'aws_account.bulk_imported',
      targetType: 'cloud_connection',
      targetId: body.managementConnectionId,
      metadata: { imported: inserted.length, skippedAlreadyConnected: activeAccounts.length - toInsert.length, skippedInactive: inactiveCount },
    });

    return okJson({
      imported: inserted.length,
      skippedAlreadyConnected: activeAccounts.length - toInsert.length,
      skippedInactive: inactiveCount,
      connections: inserted.map((r) => ({ id: r.id, awsAccountId: r.aws_account_id })),
    }, 201);
  }),
);
