import { callQueryApi } from '../awsApi';
import { extractSection, extractListItems, field } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

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

  for (const u of extractListItems(extractSection(users, 'Users'), 'member')) {
    out.push({
      resourceTypeKey: 'iam_user', resourceId: field(u, 'UserId')!, region: null,
      resourceName: field(u, 'UserName') ?? undefined,
      metadata: { arn: field(u, 'Arn'), path: field(u, 'Path'), createDate: field(u, 'CreateDate'), passwordLastUsed: field(u, 'PasswordLastUsed') },
    });
  }
  for (const r of extractListItems(extractSection(roles, 'Roles'), 'member')) {
    out.push({
      resourceTypeKey: 'iam_role', resourceId: field(r, 'RoleId')!, region: null,
      resourceName: field(r, 'RoleName') ?? undefined,
      metadata: { arn: field(r, 'Arn'), path: field(r, 'Path'), createDate: field(r, 'CreateDate'), description: field(r, 'Description'), maxSessionDuration: field(r, 'MaxSessionDuration') },
    });
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
    const mfaCol = col('mfa_active');
    const pwEnabledCol = col('password_enabled');
    const key1ActiveCol = col('access_key_1_active');
    const key1RotatedCol = col('access_key_1_last_rotated');
    const key2ActiveCol = col('access_key_2_active');
    const key2RotatedCol = col('access_key_2_last_rotated');
    const ninetyDaysAgo = Date.now() - 90 * 24 * 60 * 60 * 1000;
    const isStaleKey = (active: string | undefined, rotated: string | undefined) =>
      active === 'true' && !!rotated && rotated !== 'N/A' && new Date(rotated).getTime() < ninetyDaysAgo;
    let usersWithoutMfa = 0;
    let usersWithStaleKeys = 0;
    for (const row of dataRows) {
      if (mfaCol >= 0 && pwEnabledCol >= 0 && row[pwEnabledCol] === 'true' && row[mfaCol] === 'false') usersWithoutMfa++;
      if (isStaleKey(row[key1ActiveCol], row[key1RotatedCol]) || isStaleKey(row[key2ActiveCol], row[key2RotatedCol])) usersWithStaleKeys++;
    }
    out.push({
      resourceTypeKey: 'iam_credential_report', resourceId: 'credential-report', region: null,
      resourceName: 'IAM Credential Report',
      metadata: { generatedTime: field(reportXml, 'GeneratedTime'), totalUsers: dataRows.length, usersWithoutMfa, usersWithStaleAccessKeys: usersWithStaleKeys },
    });
  }

  return out;
}
