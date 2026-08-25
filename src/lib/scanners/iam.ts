import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems, field } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';
import { analyzePrincipalPolicies, parsePolicyDocument, ROLE_ANALYSIS_CAP, type PrincipalPolicyFetcher, type PrivilegeAnalysisResult } from '../iamPrivilegeAnalysis';

const VERSION = '2010-05-08';
/** IAM is a global service with a single endpoint — always signed against us-east-1 regardless of which scan region a caller passes in, same convention AWS's own CLI/SDKs use for IAM/STS. */
const REGION = 'us-east-1';
const ENDPOINT = 'iam.amazonaws.com';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const IAM_RESOURCE_TYPES = ['iam_user', 'iam_role', 'iam_policy', 'iam_group', 'iam_instance_profile', 'iam_oidc_provider', 'iam_saml_provider', 'iam_credential_report'] as const;

/**
 * Users, roles, customer-managed policies, and groups — one signer, 4
 * List* calls. Global service: `ctx.region` is ignored (see REGION above),
 * so discovery.ts must only ever schedule this once per account, not once
 * per scan region like the regional scanners.
 *
 * IAM's list-level XML uses `<member>` for repeated elements (not EC2's
 * `<item>`), which is why extractListItems takes a tag-name parameter.
 * List calls don't return tags (that needs a separate ListXTags call per
 * resource) — skipped in this first pass rather than adding N extra calls
 * per resource; `tags` is left undefined here.
 */
export async function scanIam(ctx: ScannerContext): Promise<ScannedResource[]> {
  const call = async (action: string, params?: Record<string, string>): Promise<string> => {
    const result = await callQueryApi(ctx.creds, { service: 'iam', region: REGION, host: ENDPOINT, action, version: VERSION, params });
    if (!result.ok) {
      console.error(`IAM ${action} failed (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return '';
    }
    return result.body as string;
  };

  const [users, roles, policies, groups, instanceProfiles, oidcProviders, samlProviders] = await Promise.all([
    call('ListUsers'),
    call('ListRoles'),
    // Scope=Local restricts to customer-managed policies — the ~1,500 AWS-managed
    // policies (Scope=AWS, the default) would swamp every account's inventory
    // with policies nobody created and nobody can act on.
    call('ListPolicies', { Scope: 'Local' }),
    call('ListGroups'),
    call('ListInstanceProfiles'),
    call('ListOpenIDConnectProviders'),
    call('ListSAMLProviders'),
  ]);

  const out: ScannedResource[] = [];
  // Principals to run privilege analysis on after the main inventory loops
  // below — kept as direct object references into `out` so attaching
  // privilegeLevel/privilegeReasons later just mutates `resource.metadata`
  // in place, no second pass over `out` needed to find them again.
  const principalsToAnalyze: { resource: ScannedResource; kind: 'Role' | 'User'; name: string }[] = [];

  for (const u of extractListItems(extractSection(users, 'Users'), 'member')) {
    const userName = field(u, 'UserName') ?? undefined;
    const resource: ScannedResource = {
      resourceTypeKey: 'iam_user', resourceId: field(u, 'UserId')!, region: null,
      resourceName: userName,
      metadata: { arn: field(u, 'Arn'), path: field(u, 'Path'), createDate: field(u, 'CreateDate'), passwordLastUsed: field(u, 'PasswordLastUsed') },
    };
    out.push(resource);
    if (userName) principalsToAnalyze.push({ resource, kind: 'User', name: userName });
  }
  for (const r of extractListItems(extractSection(roles, 'Roles'), 'member')) {
    const roleName = field(r, 'RoleName') ?? undefined;
    const resource: ScannedResource = {
      resourceTypeKey: 'iam_role', resourceId: field(r, 'RoleId')!, region: null,
      resourceName: roleName,
      metadata: { arn: field(r, 'Arn'), path: field(r, 'Path'), createDate: field(r, 'CreateDate'), description: field(r, 'Description'), maxSessionDuration: field(r, 'MaxSessionDuration') },
    };
    out.push(resource);
    if (roleName) principalsToAnalyze.push({ resource, kind: 'Role', name: roleName });
  }
  for (const p of extractListItems(extractSection(policies, 'Policies'), 'member')) {
    out.push({
      resourceTypeKey: 'iam_policy', resourceId: field(p, 'PolicyId')!, region: null,
      resourceName: field(p, 'PolicyName') ?? undefined,
      metadata: { arn: field(p, 'Arn'), path: field(p, 'Path'), attachmentCount: field(p, 'AttachmentCount'), defaultVersionId: field(p, 'DefaultVersionId'), createDate: field(p, 'CreateDate'), updateDate: field(p, 'UpdateDate') },
    });
  }
  for (const g of extractListItems(extractSection(groups, 'Groups'), 'member')) {
    out.push({
      resourceTypeKey: 'iam_group', resourceId: field(g, 'GroupId')!, region: null,
      resourceName: field(g, 'GroupName') ?? undefined,
      metadata: { arn: field(g, 'Arn'), path: field(g, 'Path'), createDate: field(g, 'CreateDate') },
    });
  }
  for (const ip of extractListItems(extractSection(instanceProfiles, 'InstanceProfiles'), 'member')) {
    out.push({
      resourceTypeKey: 'iam_instance_profile', resourceId: field(ip, 'InstanceProfileId')!, region: null,
      resourceName: field(ip, 'InstanceProfileName') ?? undefined,
      metadata: { arn: field(ip, 'Arn'), path: field(ip, 'Path'), createDate: field(ip, 'CreateDate') },
      relationships: { roleNames: extractListItems(extractSection(ip, 'Roles'), 'member').map((r) => field(r, 'RoleName')) },
    });
  }
  // Neither list call returns a name — only the ARN, whose trailing segment
  // (the provider URL for OIDC, an admin-supplied name for SAML) stands in
  // for a display name.
  for (const oidc of extractListItems(extractSection(oidcProviders, 'OpenIDConnectProviderList'), 'member')) {
    const arn = field(oidc, 'Arn');
    if (!arn) continue;
    out.push({ resourceTypeKey: 'iam_oidc_provider', resourceId: arn, region: null, resourceName: arn.split('/').pop(), metadata: { arn } });
  }
  for (const saml of extractListItems(extractSection(samlProviders, 'SAMLProviderList'), 'member')) {
    const arn = field(saml, 'Arn');
    if (!arn) continue;
    out.push({
      resourceTypeKey: 'iam_saml_provider', resourceId: arn, region: null, resourceName: arn.split('/').pop(),
      metadata: { arn, validUntil: field(saml, 'ValidUntil'), createDate: field(saml, 'CreateDate') },
    });
  }

  // Real IAM policy-document analysis for the "is this identity
  // over-privileged" leg of a toxic-combination correlation (see
  // iamPrivilegeAnalysis.ts) — capped at ROLE_ANALYSIS_CAP principals and
  // cached per policy ARN across all of them, since the same customer-
  // managed policy is commonly attached to many roles in a real account.
  const managedPolicyDocCache = new Map<string, ReturnType<typeof parsePolicyDocument>>();
  const fetchManagedPolicyDocument = async (policyArn: string) => {
    if (managedPolicyDocCache.has(policyArn)) return managedPolicyDocCache.get(policyArn) ?? null;
    const policyXml = await call('GetPolicy', { PolicyArn: policyArn });
    const versionId = field(policyXml, 'DefaultVersionId');
    if (!versionId) {
      managedPolicyDocCache.set(policyArn, null);
      return null;
    }
    const versionXml = await call('GetPolicyVersion', { PolicyArn: policyArn, VersionId: versionId });
    const doc = parsePolicyDocument(field(versionXml, 'Document'));
    managedPolicyDocCache.set(policyArn, doc);
    return doc;
  };

  for (const { resource, kind, name } of principalsToAnalyze.slice(0, ROLE_ANALYSIS_CAP)) {
    const fetcher: PrincipalPolicyFetcher = {
      listAttachedPolicies: async () => {
        const xml = await call(`ListAttached${kind}Policies`, { [`${kind}Name`]: name });
        return extractListItems(extractSection(xml, 'AttachedPolicies'), 'member')
          .map((m) => field(m, 'PolicyArn'))
          .filter((arn): arn is string => !!arn)
          .map((policyArn) => ({ policyArn }));
      },
      listInlinePolicyNames: async () => {
        const xml = await call(`List${kind}Policies`, { [`${kind}Name`]: name });
        return extractListItems(extractSection(xml, 'PolicyNames'), 'member').map((s) => s.trim()).filter(Boolean);
      },
      getInlinePolicyDocument: async (policyName: string) => {
        const xml = await call(`Get${kind}Policy`, { [`${kind}Name`]: name, PolicyName: policyName });
        return parsePolicyDocument(field(xml, 'PolicyDocument'));
      },
      getManagedPolicyDocument: fetchManagedPolicyDocument,
    };
    let result: PrivilegeAnalysisResult;
    try {
      result = await analyzePrincipalPolicies(fetcher, `${kind.toLowerCase()} ${name}`);
    } catch (err) {
      console.error(`IAM privilege analysis failed for ${kind} ${name} (continuing without it): ${err instanceof Error ? err.message : err}`);
      continue;
    }
    resource.metadata = { ...resource.metadata, privilegeLevel: result.privilegeLevel, privilegeReasons: result.privilegeReasons };
  }

  // Credential report: a single account-wide security summary (MFA/access-key
  // hygiene), not one row per user — AWS generates it asynchronously and
  // caches it for ~4h, so GenerateCredentialReport is fired first and
  // GetCredentialReport is tried once right after; if the report isn't ready
  // yet (State STARTED/INPROGRESS on a first-ever call for this account) it's
  // skipped this run rather than polled inline, and picked up cleanly on the
  // next daily auto-scan once AWS has finished generating it.
  await call('GenerateCredentialReport');
  const reportXml = await call('GetCredentialReport');
  const content = field(reportXml, 'Content');
  if (content) {
    const csv = atob(content);
    const rows = csv.trim().split('\n').map((line) => line.split(','));
    const header = rows[0];
    const col = (name: string) => header.indexOf(name);
    const dataRows = rows.slice(1);
    const userCol = col('user');
    const mfaCol = col('mfa_active');
    const pwEnabledCol = col('password_enabled');
    const pwLastUsedCol = col('password_last_used');
    const key1ActiveCol = col('access_key_1_active');
    const key1RotatedCol = col('access_key_1_last_rotated');
    const key1LastUsedCol = col('access_key_1_last_used_date');
    const key2ActiveCol = col('access_key_2_active');
    const key2RotatedCol = col('access_key_2_last_rotated');
    const key2LastUsedCol = col('access_key_2_last_used_date');
    const ninetyDaysAgo = Date.now() - 90 * 24 * 60 * 60 * 1000;
    const isStaleKey = (active: string | undefined, rotated: string | undefined) =>
      active === 'true' && !!rotated && rotated !== 'N/A' && new Date(rotated).getTime() < ninetyDaysAgo;
    let usersWithoutMfa = 0;
    let usersWithStaleKeys = 0;

    // The per-user MFA/key-hygiene fields below used to be parsed only to
    // feed the two account-wide counters after this loop, then discarded --
    // real per-identity data (which user lacks MFA, which key is stale)
    // computed and thrown away on every single scan. Now attached directly
    // onto the matching iam_user's own metadata (matched by username, the
    // credential report's `user` column) so it survives into cloud_resources
    // and, from there, into the new cloud_identities table's ingestion step
    // in discovery.ts -- a canonical identity record with no MFA/key
    // hygiene data on it would be far less useful than one with it.
    const userResourceByName = new Map(out.filter((r) => r.resourceTypeKey === 'iam_user' && r.resourceName).map((r) => [r.resourceName as string, r]));
    for (const row of dataRows) {
      if (mfaCol >= 0 && pwEnabledCol >= 0 && row[pwEnabledCol] === 'true' && row[mfaCol] === 'false') usersWithoutMfa++;
      if (isStaleKey(row[key1ActiveCol], row[key1RotatedCol]) || isStaleKey(row[key2ActiveCol], row[key2RotatedCol])) usersWithStaleKeys++;

      const userName = userCol >= 0 ? row[userCol] : undefined;
      const userResource = userName ? userResourceByName.get(userName) : undefined;
      if (!userResource) continue;
      const accessKeys = [
        { index: 1, active: row[key1ActiveCol] === 'true', lastRotated: nullIfNA(row[key1RotatedCol]), lastUsedDate: nullIfNA(row[key1LastUsedCol]) },
        { index: 2, active: row[key2ActiveCol] === 'true', lastRotated: nullIfNA(row[key2RotatedCol]), lastUsedDate: nullIfNA(row[key2LastUsedCol]) },
      ].filter((k) => k.active || k.lastRotated);
      userResource.metadata = {
        ...userResource.metadata,
        mfaActive: mfaCol >= 0 ? row[mfaCol] === 'true' : undefined,
        passwordEnabled: pwEnabledCol >= 0 ? row[pwEnabledCol] === 'true' : undefined,
        credentialReportPasswordLastUsed: nullIfNA(row[pwLastUsedCol]),
        accessKeys,
      };
    }

    out.push({
      resourceTypeKey: 'iam_credential_report', resourceId: 'credential-report', region: null,
      resourceName: 'IAM Credential Report',
      metadata: { generatedTime: field(reportXml, 'GeneratedTime'), totalUsers: dataRows.length, usersWithoutMfa, usersWithStaleAccessKeys: usersWithStaleKeys },
    });
  }

  return out;
}

/** The credential report CSV uses the literal string "N/A" (and "not_supported" for password fields on roles/service-linked contexts) for fields that don't apply — normalized to null so downstream consumers don't have to special-case string sentinels. */
function nullIfNA(value: string | undefined): string | null {
  if (!value || value === 'N/A' || value === 'not_supported') return null;
  return value;
}

export interface CloudIdentityRow {
  connection_id: string; provider: 'aws'; identity_type: 'user' | 'role';
  native_id: string; native_label: string | null; display_name: string | null;
  is_human: boolean; privilege_level: string | null; privilege_reasons: unknown[];
  mfa_enabled: boolean | null; last_used_at: string | null; last_used_source: 'credential_report' | 'provider_api' | null;
  identity_created_at: string | null; metadata: Record<string, unknown>;
  last_seen_at: string; deleted_at: null;
}

/**
 * Prefers the credential report's own per-user data (password-last-used +
 * both access keys' last-used-date, whichever is most recent) over the
 * ListUsers API's bare PasswordLastUsed field, since the credential report
 * is the only source with access-key activity at all -- falls back to
 * PasswordLastUsed only when no credential report data exists yet (a
 * brand-new account, or the very first scan before AWS has finished
 * generating one -- see the GenerateCredentialReport call above).
 */
function latestUsedAt(metadata: Record<string, unknown> | undefined): { at: string | null; source: 'credential_report' | 'provider_api' | null } {
  const accessKeys = (metadata?.accessKeys as { lastUsedDate: string | null }[] | undefined) ?? [];
  const candidates = [metadata?.credentialReportPasswordLastUsed, ...accessKeys.map((k) => k.lastUsedDate)]
    .filter((v): v is string => typeof v === 'string');
  if (candidates.length > 0) {
    return { at: candidates.reduce((a, b) => (new Date(a) > new Date(b) ? a : b)), source: 'credential_report' };
  }
  const passwordLastUsed = metadata?.passwordLastUsed;
  if (typeof passwordLastUsed === 'string') return { at: passwordLastUsed, source: 'provider_api' };
  return { at: null, source: null };
}

/**
 * Derives cloud_identities rows from this scanner's own iam_user/iam_role
 * output -- same "no second API call, just reshape what was already
 * fetched" convention as cloudwatch.ts's extractMonitoringAlarmRows. Groups
 * and instance profiles are deliberately excluded: a group is a permission
 * container, not a principal that can itself authenticate or be assumed,
 * and an instance profile is a wrapper around a role (already captured)
 * rather than a distinct identity.
 */
export function extractCloudIdentityRows(scanned: ScannedResource[], connectionId: string): CloudIdentityRow[] {
  const now = new Date().toISOString();
  return scanned
    .filter((r): r is ScannedResource & { resourceId: string } => r.resourceTypeKey === 'iam_user' || r.resourceTypeKey === 'iam_role')
    .map((r) => {
      const { at, source } = latestUsedAt(r.metadata);
      return {
        connection_id: connectionId, provider: 'aws', identity_type: r.resourceTypeKey === 'iam_user' ? 'user' : 'role',
        native_id: r.resourceId, native_label: (r.metadata?.arn as string) ?? null, display_name: r.resourceName ?? null,
        is_human: r.resourceTypeKey === 'iam_user',
        privilege_level: (r.metadata?.privilegeLevel as string) ?? null, privilege_reasons: (r.metadata?.privilegeReasons as unknown[]) ?? [],
        mfa_enabled: typeof r.metadata?.mfaActive === 'boolean' ? (r.metadata.mfaActive as boolean) : null,
        last_used_at: at, last_used_source: source,
        identity_created_at: (r.metadata?.createDate as string) ?? null,
        metadata: r.metadata ?? {}, last_seen_at: now, deleted_at: null,
      };
    });
}
