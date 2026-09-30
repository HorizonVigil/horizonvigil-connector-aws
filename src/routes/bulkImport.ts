import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, requireRole, writeAuditLog, guarded, okJson, errJson, enforceRateLimit, checkCloudAccountLimit, type Db } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { isAssumeRoleEnabled, assumeRoleDisabledResponse } from '../lib/capabilities';
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
export const MAX_ACCOUNTS_PER_BULK_IMPORT = 2000;

/**
 * Rows per insert request.
 *
 * The whole import used to go in ONE insert. At 2,000 accounts that is a
 * single multi-megabyte request in a single transaction, where one rejected
 * row loses all 2,000 and the customer gets no partial progress and no idea
 * which account was the problem. Chunking bounds the body, bounds the
 * transaction, and lets a failure name the batch it happened in while the
 * batches that succeeded stay imported.
 */
export const INSERT_CHUNK = 200;

export function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/**
 * The partition the member roles live in, taken from the management
 * connection's own role ARN.
 *
 * Hardcoding `arn:aws:` produces role ARNs that cannot exist in GovCloud
 * (`aws-us-gov`) or China (`aws-cn`) — every imported connection would be
 * shaped correctly and authenticate nowhere. Access-key connections have no
 * ARN to read, so they fall back to the commercial partition, which is where
 * they almost certainly are.
 */
export function partitionOf(roleArn: string | null | undefined): string {
  const parts = (roleArn ?? '').split(':');
  return parts.length > 1 && parts[1] ? parts[1] : 'aws';
}

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
  /** Optional OU or root id. Omitted, the whole Organization is imported. */
  parentId?: string;
  projectId?: string | null;
  environment?: string;
}

/**
 * GET /api/aws-accounts/accounts/bulk-import/preview?managementConnectionId=
 * — a read-only dry run of the bulk import below: lists the Organization's
 * accounts via the management connection's own credentials, diffs against
 * what this org already has connected, and returns the counts + a small
 * sample so the UI can show "820 accounts found, 12 already connected, 808
 * importable" before the customer commits. No `cloud_connections` rows are
 * created. Same read-level bar as viewing the account list — the blast-radius
 * concern is on the POST, not on counting.
 */
bulkImportRoutes.get('/accounts/bulk-import/preview', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const managementConnectionId = c.req.query('managementConnectionId');
    if (!managementConnectionId) {
      return errJson(400, 'managementConnectionId is required — pass the connection id of your AWS Organizations management account.');
    }
    // Optional OU scope. The preview MUST accept the same scope as the import,
    // or the counts a customer approves are not the accounts they get.
    const parentId = c.req.query('parentId') ?? undefined;

    const rows = await db.select<(ResolvableConnection & { id: string })[]>('cloud_connections', {
      select: 'id,connection_method,credentials_encrypted,role_arn,external_id,default_region',
      filters: { id: `eq.${managementConnectionId}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
    });
    const managementConnection = rows[0];
    if (!managementConnection) return errJson(404, 'Management account connection not found.');

    const resolved = await resolveCredentials(c.env, managementConnection);
    if ('error' in resolved) return errJson(400, `Could not resolve credentials for the management account connection: ${resolved.error}`);

    const listed = await listOrganizationAccounts(resolved.creds, parentId);
    if (!listed.ok) return errJson(400, listed.error);

    const active = listed.accounts.filter((a): a is OrgAccount & { Id: string } => a.Status === 'ACTIVE' && !!a.Id);
    const alreadyConnected = await existingAwsAccountIds(db, orgId);
    const importable = active.filter((a) => !alreadyConnected.has(a.Id));

    // The plan position AFTER the import, not before. "You are at 48 of 50"
    // is not the useful sentence when the next click adds 800.
    const planLimit = await checkCloudAccountLimit(db, orgId);
    const projected = planLimit.included && planLimit.included > 0
      ? { used: planLimit.used, included: planLimit.included, afterImport: planLimit.used + importable.length,
          overBy: Math.max(0, planLimit.used + importable.length - planLimit.included) }
      : null;

    return okJson({
      scope: parentId ? { parentId } : { parentId: null, description: 'entire organization' },
      total: listed.accounts.length,
      active: active.length,
      inactive: listed.accounts.length - active.length,
      alreadyConnected: active.length - importable.length,
      importable: importable.length,
      overLimit: importable.length > MAX_ACCOUNTS_PER_BULK_IMPORT ? importable.length - MAX_ACCOUNTS_PER_BULK_IMPORT : 0,
      plan: projected,
      sample: importable.slice(0, 8).map((a) => ({ id: a.Id, name: a.Name ?? a.Id })),
    });
  }),
);

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
 * exactly like any other broken cross-account-role connection today.
 *
 * That last caveat USED to be larger: assuming a member role needed
 * PLATFORM_AWS_ACCESS_KEY_ID, which was never provisioned, so every
 * connection this created was correctly shaped and could never authenticate.
 * Workload identity removed that dependency -- there is no platform AWS
 * credential to provision any more -- so an imported connection can now
 * actually be assumed, provided the StackSet was deployed with the matching
 * TrustMode and PlatformGoogleSubject.
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
    /**
     * AWS-P0-02: bulk onboarding walks AWS Organizations and creates member
     * connections that would use the cross-account role path, which is not
     * certified. The audit's disposition is explicit -- "Do not expose while
     * AssumeRole/external-ID flow is broken" -- so this is denied at the
     * entrypoint rather than failing partway through a partial import.
     */
    if (!isAssumeRoleEnabled(c.env)) return assumeRoleDisabledResponse();

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

    const listed = await listOrganizationAccounts(resolved.creds, body.parentId);
    if (!listed.ok) return errJson(400, listed.error);

    const activeAccounts = listed.accounts.filter((a): a is OrgAccount & { Id: string } => a.Status === 'ACTIVE' && !!a.Id);
    const inactiveCount = listed.accounts.length - activeAccounts.length;
    if (activeAccounts.length > MAX_ACCOUNTS_PER_BULK_IMPORT) {
      // Actionable, not a support ticket: scoping to an OU is a parameter on
      // this same endpoint, and the preview accepts it too.
      return errJson(400, `This ${body.parentId ? 'organizational unit' : 'Organization'} has ${activeAccounts.length} active accounts, above this endpoint's ${MAX_ACCOUNTS_PER_BULK_IMPORT}-per-call safety limit. Import one organizational unit at a time by passing "parentId" (preview the same scope first with ?parentId=).`);
    }

    const alreadyConnected = await existingAwsAccountIds(db, orgId);
    const toInsert = activeAccounts.filter((a) => !alreadyConnected.has(a.Id));

    if (toInsert.length === 0) {
      return okJson({ imported: 0, skippedAlreadyConnected: activeAccounts.length, skippedInactive: inactiveCount, connections: [] });
    }

    const externalId = await getOrCreateOrgExternalId(db, orgId);
    const partition = partitionOf(managementConnection.role_arn);
    const planLimit = await checkCloudAccountLimit(db, orgId);

    const rowsFor = (a: OrgAccount & { Id: string }) => ({
      org_id: orgId,
      project_id: body.projectId ?? null,
      provider: 'aws',
      connection_method: 'cross_account_role',
      aws_account_id: a.Id,
      connection_name: a.Name ?? a.Id,
      // Partition taken from the management connection, not hardcoded: an
      // `arn:aws:` role cannot exist in GovCloud or China.
      role_arn: `arn:${partition}:iam::${a.Id}:role/${ROLE_NAME}`,
      external_id: externalId,
      default_region: managementConnection.default_region ?? 'us-east-1',
      environment: body.environment ?? 'production',
      status: 'pending',
      auto_scan_enabled: true,
      created_by: auth.userId,
      credentials_encrypted: {},
    });

    const inserted: { id: string; aws_account_id: string }[] = [];
    const failedBatches: { accounts: number; firstAccountId: string; error: string }[] = [];

    for (const batch of chunk(toInsert, INSERT_CHUNK)) {
      try {
        const rows = await db.insert<{ id: string; aws_account_id: string }[]>('cloud_connections', batch.map(rowsFor));
        inserted.push(...rows);
      } catch (err) {
        // Record and continue. One rejected batch must not discard the ones
        // that already landed, and the customer needs to know WHICH accounts
        // are missing rather than being told the whole import failed.
        failedBatches.push({
          accounts: batch.length,
          firstAccountId: batch[0].Id,
          error: err instanceof Error ? err.message : 'insert failed',
        });
      }
    }

    await writeAuditLog(db, {
      orgId,
      actorId: auth.userId,
      action: 'aws_account.bulk_imported',
      targetType: 'cloud_connection',
      targetId: body.managementConnectionId,
      metadata: {
        imported: inserted.length,
        failed: toInsert.length - inserted.length,
        scope: body.parentId ?? 'organization',
        skippedAlreadyConnected: activeAccounts.length - toInsert.length,
        skippedInactive: inactiveCount,
      },
    });

    return okJson({
      imported: inserted.length,
      // Stated separately and always, so a partial import can never read as a
      // complete one. `imported` alone would look like success at any scale.
      attempted: toInsert.length,
      failed: toInsert.length - inserted.length,
      failedBatches,
      scope: body.parentId ? { parentId: body.parentId } : { parentId: null, description: 'entire organization' },
      skippedAlreadyConnected: activeAccounts.length - toInsert.length,
      skippedInactive: inactiveCount,
      planLimitWarning: planLimit.included && planLimit.included > 0 && planLimit.used + inserted.length > planLimit.included
        ? `This import takes you to ${planLimit.used + inserted.length} cloud accounts against a plan that includes ${planLimit.included}.`
        : null,
      // Imported connections are created 'pending'. They are assumed and
      // validated by /internal/run-first-scans, not by this request -- 1,000
      // sts:AssumeRole calls do not belong in one HTTP request.
      nextStep: inserted.length > 0
        ? 'Connections are queued as pending. First scans run on the scheduled internal sweep; a role whose trust policy does not match will surface there as a connection error.'
        : null,
      connections: inserted.map((r) => ({ id: r.id, awsAccountId: r.aws_account_id })),
    }, 201);
  }),
);
