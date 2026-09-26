import { callQueryApi } from '../awsApi';
import { incompleteSink, DEFAULT_MAX_PAGES, type PaginationTermination } from '../pagination';
import { extractSection, extractListItems, field } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';
import { analyzePrincipalPolicies, parsePolicyDocument, ROLE_ANALYSIS_CAP, type PrincipalPolicyFetcher, type PrivilegeAnalysisResult } from '../iamPrivilegeAnalysis';
import { accountIdFromArn, summarizePolicy, type PolicySummary } from './policyEvidence';
import { mapWithConcurrency } from './scannerSupport';

const VERSION = '2010-05-08';
/** IAM is a global service with a single endpoint — always signed against us-east-1 regardless of which scan region a caller passes in, same convention AWS's own CLI/SDKs use for IAM/STS. */
const REGION = 'us-east-1';
const ENDPOINT = 'iam.amazonaws.com';

/**
 * Principals analysed at once. IAM's control-plane rate limit is low; this is
 * enough to finish inside a Worker's wall-clock budget without throttling.
 */
const ANALYSIS_CONCURRENCY = 3;

/** Service-linked roles are AWS-owned and not editable by the customer. */
const SERVICE_LINKED_ROLE_PATH = '/aws-service-role/';

/** The credential report's row for the account root user. */
const ROOT_ACCOUNT_ROW = '<root_account>';

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
export interface IamScanOperation {
  action: string;
  /**
   * `partial` and `not_supported` are distinct from `failed` on purpose.
   *
   * `partial` — the walk stopped before AWS ran out of pages (page cap, a
   * marker that did not advance). The rows collected are real; the set is
   * incomplete, and finalize must not read the missing ones as deletions.
   *
   * `not_supported` — AWS retires services and an account can simply not have
   * enabled one. Recording that as a failure permanently marks a healthy scan
   * as failing and teaches operators to ignore the signal. `awsApi.ts` already
   * treats UNSUPPORTED_CAPABILITY this way centrally.
   */
  status: 'success' | 'partial' | 'failed' | 'not_supported';
  pages: number;
  resources: number;
  attempts: number;
  termination?: PaginationTermination;
  error?: string;
}

export interface IamScanDiagnostics {
  scanner: 'iam';
  scanner_version: 'v1';
  status: 'success' | 'partial' | 'failed';
  startedAt: string;
  completedAt: string;
  operations: IamScanOperation[];
}

/**
 * IAM discovery is deliberately fail-closed for primary inventory calls:
 * an AWS API failure must never be represented as an empty inventory.
 *
 * The public scanner contract remains Promise<ScannedResource[]> for
 * compatibility with discovery.ts. Detailed operation telemetry is attached
 * to every returned resource as `iamScanDiagnostics`; callers can therefore
 * distinguish a successful zero-result scan from an API failure without
 * changing the existing ScannedResource contract.
 */
export async function scanIam(ctx: ScannerContext): Promise<ScannedResource[]> {
  const startedAt = new Date().toISOString();
  const operations: IamScanOperation[] = [];

  /**
   * Routes an incomplete walk into the same degraded-coverage sink every AWS
   * failure already uses, so finalize cannot read pages we never fetched as
   * deletions. This is the whole reason stopping beats throwing.
   */
  const onIncomplete = incompleteSink(ctx.creds);



  const call = async (
    action: string,
    params?: Record<string, string>,
    /**
     * `record: false` is for EXPECTED intermediate answers -- the credential
     * report poll answers ReportInProgress until it is ready. Recording those
     * as failed operations marked every healthy scan `partial`.
     */
    options: { required?: boolean; record?: boolean } = {},
  ): Promise<string> => {
    const result = await callQueryApi(ctx.creds, {
      service: 'iam',
      region: REGION,
      host: ENDPOINT,
      action,
      version: VERSION,
      params,
    });

    if (result.ok) return result.body as string;

    const code = result.normalizedCode ?? result.errorCode ?? result.errorMessage ?? String(result.status);

    /**
     * A retired or not-enabled capability is a settled answer, not a failure.
     * `awsApi.ts` already treats UNSUPPORTED_CAPABILITY this way centrally --
     * it is deliberately excluded from degraded coverage, because "this
     * account has not enabled X" must not freeze cleanup for a service nobody
     * uses.
     */
    const retired = code === 'UNSUPPORTED_CAPABILITY';
    if (options.record !== false) {
      operations.push({
        action,
        status: retired ? 'not_supported' : 'failed',
        pages: 0,
        resources: 0,
        attempts: result.attempts ?? 1,
        error: code,
      });
    }

    /**
     * `required` is preserved, and it is load-bearing.
     *
     * If ListUsers is DENIED and this returned '', the scan would parse zero
     * users and report success -- publishing "0 IAM users" for an account
     * whose IAM we were simply not permitted to read. That is precisely what
     * AWS-11 forbids. Throwing fails the step visibly instead.
     *
     * A retired capability never throws: there is nothing to have been denied.
     *
     * The hand-rolled retry loop that wrapped this is gone. `callQueryApi`
     * already applies `withRetry` with the same backoff, jitter and retryable
     * classification, so two layers meant up to 4 x 4 = 16 attempts against a
     * throttled endpoint -- making throttling worse, not better.
     */
    if (options.required !== false && !retired) {
      throw new Error(`IAM ${action} failed: ${code}`);
    }

    return '';
  };

  /**
   * IAM List* APIs use Marker/IsTruncated rather than the newer NextToken
   * convention. This helper centralizes pagination so no account silently
   * loses resources once it grows beyond one API page.
   */
  const listPages = async (
    action: string,
    section: string,
    params?: Record<string, string>,
    options: { required?: boolean } = {},
  ): Promise<{ pages: string[]; attempts: number }> => {
    const pages: string[] = [];
    let marker: string | undefined;
    let attempts = 0;
    let termination: PaginationTermination = 'complete';
    let detail: string | undefined;

    do {
      const pageParams = marker ? { ...(params ?? {}), Marker: marker } : params;
      attempts++;
      const xml = await call(action, pageParams, options);

      // An empty body means `call` already recorded its own failed or
      // not_supported operation. Terminating as `complete` here would claim
      // the list was fully read when the first page never arrived.
      if (!xml) {
        if (pages.length > 0) { termination = 'failed'; detail = `IAM ${action} stopped after a failed page`; }
        else return { pages, attempts };
        break;
      }
      pages.push(xml);

      /**
       * Page cap. An unbounded walk against a hostile or looping endpoint
       * would spin forever inside one worker slice; terminating as
       * `page_cap` keeps the rows we have and marks the set incomplete.
       */
      if (pages.length >= DEFAULT_MAX_PAGES) {
        termination = 'page_cap';
        detail = `IAM ${action} hit the ${DEFAULT_MAX_PAGES}-page cap`;
        console.error(detail);
        onIncomplete('PAGINATION_TRUNCATED', detail);
        break;
      }

      const isTruncated = field(xml, 'IsTruncated') === 'true';
      const nextMarker = field(xml, 'Marker') ?? field(xml, 'NextToken');

      if (!isTruncated) break;

      /**
       * AWS said there is more and then gave us no usable way to ask for it.
       *
       * Throwing here discarded every page already collected and took the
       * whole IAM scan down with it. Stopping is right; losing the rows is
       * not. It terminates as `malformed`, which flows into `partial` below
       * and degrades the resource types, so finalize cannot read the pages we
       * never got as deletions.
       */
      if (!nextMarker || nextMarker === marker) {
        termination = 'malformed';
        detail = `IAM ${action} reported IsTruncated=true without a usable continuation marker`;
        console.error(`${detail}; stopped after ${pages.length} page(s)`);
        onIncomplete('PAGINATION_TRUNCATED', detail);
        break;
      }
      marker = nextMarker;
    } while (true);

    const resources = pages.reduce(
      (count, xml) => count + extractListItems(extractSection(xml, section), 'member').length,
      0,
    );

    operations.push({
      action,
      status: termination === 'complete' ? 'success' : 'partial',
      pages: pages.length,
      resources,
      attempts,
      termination,
      ...(detail ? { error: detail } : {}),
    });

    return { pages, attempts };
  };

  const recordOptionalFailure = (action: string, error: unknown) => {
    operations.push({
      action,
      status: 'failed',
      pages: 0,
      resources: 0,
      attempts: 1,
      error: error instanceof Error ? error.message : String(error),
    });
  };

  const collectMembers = (
    pages: string[],
    section: string,
  ): ReturnType<typeof extractListItems> => pages.flatMap((xml) => extractListItems(extractSection(xml, section), 'member'));

  try {
    // These are independent account-level inventory calls. Promise.all is
    // retained for throughput, while each list call remains fully paginated.
    const [
      usersResult,
      rolesResult,
      policiesResult,
      groupsResult,
      instanceProfilesResult,
      oidcProvidersResult,
      samlProvidersResult,
    ] = await Promise.all([
      listPages('ListUsers', 'Users'),
      listPages('ListRoles', 'Roles'),
      // V1 inventories customer-managed policies only. AWS-managed policies
      // are not customer-owned resources and are still considered when their
      // ARNs appear on principal attachments.
      listPages('ListPolicies', 'Policies', { Scope: 'Local' }),
      listPages('ListGroups', 'Groups'),
      listPages('ListInstanceProfiles', 'InstanceProfiles'),
      listPages('ListOpenIDConnectProviders', 'OpenIDConnectProviderList'),
      listPages('ListSAMLProviders', 'SAMLProviderList'),
    ]);

    const users = collectMembers(usersResult.pages, 'Users');
    const roles = collectMembers(rolesResult.pages, 'Roles');
    const policies = collectMembers(policiesResult.pages, 'Policies');
    const groups = collectMembers(groupsResult.pages, 'Groups');
    const instanceProfiles = collectMembers(instanceProfilesResult.pages, 'InstanceProfiles');
    const oidcProviders = collectMembers(oidcProvidersResult.pages, 'OpenIDConnectProviderList');
    const samlProviders = collectMembers(samlProvidersResult.pages, 'SAMLProviderList');

    const out: ScannedResource[] = [];

    // Principals to run privilege analysis on after the main inventory loops.
    // Direct object references avoid a second pass over `out`.
    const principalsToAnalyze: {
      resource: ScannedResource;
      kind: 'Role' | 'User' | 'Group';
      name: string;
    }[] = [];

    for (const u of users) {
      const userId = field(u, 'UserId');
      if (!userId) continue;
      const userName = field(u, 'UserName') ?? undefined;
      const resource: ScannedResource = {
        resourceTypeKey: 'iam_user',
        resourceId: userId,
        region: null,
        resourceName: userName,
        metadata: {
          arn: field(u, 'Arn'),
          path: field(u, 'Path'),
          createDate: field(u, 'CreateDate'),
          passwordLastUsed: field(u, 'PasswordLastUsed'),
        },
      };
      out.push(resource);
      if (userName) principalsToAnalyze.push({ resource, kind: 'User', name: userName });
    }

    for (const r of roles) {
      const roleId = field(r, 'RoleId');
      if (!roleId) continue;
      const roleName = field(r, 'RoleName') ?? undefined;
      const arn = field(r, 'Arn');
      const path = field(r, 'Path');
      const serviceLinked = (path ?? '').startsWith(SERVICE_LINKED_ROLE_PATH);
      /*
       * WHO CAN ASSUME THIS ROLE. ListRoles already returns the trust policy
       * (URL-encoded) for every role, so this costs no extra call. A role
       * trusting "*" with no condition is assumable by anyone on AWS; one
       * trusting another account without sts:ExternalId is the classic
       * confused-deputy exposure. Evidence only -- posture decides severity.
       */
      const trust: PolicySummary = summarizePolicy(field(r, 'AssumeRolePolicyDocument'), accountIdFromArn(arn));
      const resource: ScannedResource = {
        resourceTypeKey: 'iam_role',
        resourceId: roleId,
        region: null,
        resourceName: roleName,
        metadata: {
          arn,
          path,
          createDate: field(r, 'CreateDate'),
          description: field(r, 'Description'),
          maxSessionDuration: field(r, 'MaxSessionDuration'),
          serviceLinked,
          trustPolicy: trust,
          trustAllowsAnonymous: trust.allowsAnonymous,
          trustExternalAccountIds: trust.externalAccountIds,
          trustRequiresExternalId: trust.conditionKeys.includes('sts:externalid'),
          trustRequiresMfa: trust.conditionKeys.includes('aws:multifactorauthpresent'),
        },
      };
      out.push(resource);
      if (roleName) principalsToAnalyze.push({ resource, kind: 'Role', name: roleName });
    }

    for (const p of policies) {
      const policyId = field(p, 'PolicyId');
      if (!policyId) continue;
      out.push({
        resourceTypeKey: 'iam_policy',
        resourceId: policyId,
        region: null,
        resourceName: field(p, 'PolicyName') ?? undefined,
        metadata: {
          arn: field(p, 'Arn'),
          path: field(p, 'Path'),
          attachmentCount: field(p, 'AttachmentCount'),
          defaultVersionId: field(p, 'DefaultVersionId'),
          createDate: field(p, 'CreateDate'),
          updateDate: field(p, 'UpdateDate'),
          policyScope: 'Local',
          isAttachable: field(p, 'IsAttachable') === null ? null : field(p, 'IsAttachable') === 'true',
          permissionsBoundaryUsageCount: field(p, 'PermissionsBoundaryUsageCount'),
        },
      });
    }

    for (const g of groups) {
      const groupId = field(g, 'GroupId');
      if (!groupId) continue;
      const groupName = field(g, 'GroupName') ?? undefined;
      const resource: ScannedResource = {
        resourceTypeKey: 'iam_group',
        resourceId: groupId,
        region: null,
        resourceName: groupName,
        metadata: {
          arn: field(g, 'Arn'),
          path: field(g, 'Path'),
          createDate: field(g, 'CreateDate'),
        },
      };
      out.push(resource);
      if (groupName) principalsToAnalyze.push({ resource, kind: 'Group', name: groupName });
    }

    for (const ip of instanceProfiles) {
      const instanceProfileId = field(ip, 'InstanceProfileId');
      if (!instanceProfileId) continue;
      out.push({
        resourceTypeKey: 'iam_instance_profile',
        resourceId: instanceProfileId,
        region: null,
        resourceName: field(ip, 'InstanceProfileName') ?? undefined,
        metadata: {
          arn: field(ip, 'Arn'),
          path: field(ip, 'Path'),
          createDate: field(ip, 'CreateDate'),
        },
        relationships: {
          roleNames: extractListItems(extractSection(ip, 'Roles'), 'member')
            .map((r) => field(r, 'RoleName'))
            .filter((name): name is string => !!name),
        },
      });
    }

    for (const oidc of oidcProviders) {
      const arn = field(oidc, 'Arn');
      if (!arn) continue;
      out.push({
        resourceTypeKey: 'iam_oidc_provider',
        resourceId: arn,
        region: null,
        resourceName: arn.split('/').pop(),
        metadata: { arn },
      });
    }

    for (const saml of samlProviders) {
      const arn = field(saml, 'Arn');
      if (!arn) continue;
      out.push({
        resourceTypeKey: 'iam_saml_provider',
        resourceId: arn,
        region: null,
        resourceName: arn.split('/').pop(),
        metadata: {
          arn,
          validUntil: field(saml, 'ValidUntil'),
          createDate: field(saml, 'CreateDate'),
        },
      });
    }

    // Real IAM policy-document analysis for the "is this identity
    // over-privileged" leg. The existing cap is retained, but coverage is
    // explicit in metadata rather than silently looking complete: every
    // principal that was NOT analysed says why, so posture reports it
    // NOT_ASSESSED instead of reading a missing privilegeLevel as "fine".
    //
    // Cached as PROMISES so concurrent principals that share a managed policy
    // (AdministratorAccess, ReadOnlyAccess…) fetch it once, not once each.
    const managedPolicyDocCache = new Map<string, Promise<ReturnType<typeof parsePolicyDocument>>>();

    const fetchManagedPolicyDocument = (policyArn: string) => {
      const cached = managedPolicyDocCache.get(policyArn);
      if (cached) return cached;
      const pending = (async () => {
        const policyXml = await call('GetPolicy', { PolicyArn: policyArn });
        const versionId = field(policyXml, 'DefaultVersionId');
        if (!versionId) return null;
        const versionXml = await call('GetPolicyVersion', {
          PolicyArn: policyArn,
          VersionId: versionId,
        });
        return parsePolicyDocument(field(versionXml, 'Document'));
      })();
      // A failed fetch is not cached as a success: later principals retry it.
      pending.catch(() => managedPolicyDocCache.delete(policyArn));
      managedPolicyDocCache.set(policyArn, pending);
      return pending;
    };

    // Service-linked roles are AWS-owned and uneditable; analysing them spends
    // the cap on findings nobody can act on.
    const analysable = principalsToAnalyze.filter(({ resource }) => resource.metadata?.serviceLinked !== true);
    for (const { resource } of principalsToAnalyze) {
      if (resource.metadata?.serviceLinked === true) {
        resource.metadata = { ...resource.metadata, privilegeAnalysisStatus: 'skipped', privilegeAnalysisSkipReason: 'service_linked_role' };
      }
    }
    const toAnalyze = analysable.slice(0, ROLE_ANALYSIS_CAP);
    for (const { resource } of analysable.slice(ROLE_ANALYSIS_CAP)) {
      resource.metadata = { ...resource.metadata, privilegeAnalysisStatus: 'skipped', privilegeAnalysisSkipReason: 'analysis_cap' };
    }
    const analysisCount = toAnalyze.length;

    await mapWithConcurrency(toAnalyze, ANALYSIS_CONCURRENCY, async ({ resource, kind, name }) => {
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
          return extractListItems(extractSection(xml, 'PolicyNames'), 'member')
            .map((s) => s.trim())
            .filter(Boolean);
        },

        getInlinePolicyDocument: async (policyName: string) => {
          const xml = await call(`Get${kind}Policy`, {
            [`${kind}Name`]: name,
            PolicyName: policyName,
          });
          return parsePolicyDocument(field(xml, 'PolicyDocument'));
        },

        getManagedPolicyDocument: fetchManagedPolicyDocument,
      };

      let result: PrivilegeAnalysisResult;
      try {
        result = await analyzePrincipalPolicies(
          fetcher,
          `${kind.toLowerCase()} ${name}`,
        );
      } catch (err) {
        recordOptionalFailure(`PrivilegeAnalysis:${kind}:${name}`, err);
        resource.metadata = {
          ...resource.metadata,
          privilegeAnalysisStatus: 'failed',
          privilegeAnalysisError: err instanceof Error ? err.message : String(err),
        };
        return;
      }

      resource.metadata = {
        ...resource.metadata,
        privilegeLevel: result.privilegeLevel,
        privilegeReasons: result.privilegeReasons,
        attachedPolicies: result.attachedPolicyNames,
        inlinePolicies: result.inlinePolicyNames,
        privilegeAnalysisStatus: 'success',
      };
    });

    /*
     * Account-level posture evidence (CIS 1.4 root access keys, 1.5 root MFA,
     * 1.8–1.9 password policy). Both are single cheap calls and run alongside
     * the credential report poll below.
     */
    const accountSummaryPromise = (async () => {
      const summaryXml = await call('GetAccountSummary', undefined, { required: false });
      return parseAccountSummary(summaryXml || null);
    })();

    const passwordPolicyPromise = (async (): Promise<PasswordPolicyEvidence> => {
      const res = await callQueryApi(ctx.creds, {
        service: 'iam', region: REGION, host: ENDPOINT, action: 'GetAccountPasswordPolicy', version: VERSION,
      });
      if (res.ok) return parsePasswordPolicy(res.body as string);
      // NoSuchEntity is a real answer: the account has NO password policy,
      // which is itself the finding. It is not missing evidence.
      if (res.errorCode === 'NoSuchEntity' || (res.normalizedCode as string | undefined) === 'NOT_FOUND' || res.status === 404) {
        return { ...EMPTY_PASSWORD_POLICY, collected: true, configured: false };
      }
      const code = res.normalizedCode ?? res.errorCode ?? res.errorMessage ?? String(res.status);
      operations.push({ action: 'GetAccountPasswordPolicy', status: 'failed', pages: 0, resources: 0, attempts: res.attempts ?? 1, error: code });
      return { ...EMPTY_PASSWORD_POLICY };
    })();

    // Credential report: one account-wide resource. AWS generates it
    // asynchronously, so "not ready yet" is represented explicitly instead
    // of being confused with an account that has no IAM users.
    let credentialReportStatus: 'available' | 'not_ready' | 'failed' = 'available';
    let credentialReportError: string | undefined;
    let reportEvidence: CredentialReportEvidence = { ...EMPTY_REPORT_EVIDENCE };

    try {
      /**
       * GenerateCredentialReport is ASYNCHRONOUS. It answers STARTED and the
       * report is not readable for a few seconds; GetCredentialReport reports
       * ReportInProgress until then.
       *
       * This used to work by accident: the hand-rolled retry loop that
       * wrapped every IAM call retried with backoff, and that incidental
       * delay was long enough for the report to become ready. Removing that
       * loop removed the accidental poll with it, and mfa_enabled went NULL
       * for every human in the estate.
       *
       * Polling explicitly is what the API asks for, so it is deliberate
       * rather than a side effect. Bounded: a report still not ready after
       * these attempts is reported `not_ready`, never confused with an
       * account that has no IAM users. Intermediate "not ready" answers are
       * not recorded as failed operations (`record: false`) -- they are the
       * expected shape of an asynchronous API, and recording them marked
       * every healthy scan `partial`.
       */
      await call('GenerateCredentialReport');

      const REPORT_POLL_DELAYS_MS = [0, 500, 1000, 2000, 3000];
      let reportXml = '';
      let content: string | null = null;
      for (const delay of REPORT_POLL_DELAYS_MS) {
        if (delay > 0) await new Promise<void>((r) => setTimeout(r, delay));
        reportXml = await call('GetCredentialReport', undefined, { required: false, record: false });
        content = field(reportXml, 'Content');
        if (content) break;
      }

      if (!content) {
        credentialReportStatus = 'not_ready';
        operations.push({
          action: 'GetCredentialReport', status: 'partial', pages: 0, resources: 0,
          attempts: REPORT_POLL_DELAYS_MS.length, error: 'credential report not ready after polling',
        });
      } else {
        const csv = decodeBase64Text(content);
        const rows = parseCsv(csv);
        const header = rows[0] ?? [];
        const dataRows = rows.slice(1);
        const col = (name: string) => header.indexOf(name);

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
          active === 'true' &&
          !!rotated &&
          rotated !== 'N/A' &&
          Number.isFinite(new Date(rotated).getTime()) &&
          new Date(rotated).getTime() < ninetyDaysAgo;

        let usersWithoutMfa = 0;
        let usersWithStaleKeys = 0;

        const userResourceByName = new Map(
          out
            .filter((r) => r.resourceTypeKey === 'iam_user' && r.resourceName)
            .map((r) => [r.resourceName as string, r]),
        );

        // The root user is reported separately: it is not an IAM user, and
        // counting it among "users" made totalUsers off by one.
        const rootRow = userCol >= 0 ? dataRows.find((row) => row[userCol] === ROOT_ACCOUNT_ROW) : undefined;
        const userRows = userCol >= 0 ? dataRows.filter((row) => row[userCol] !== ROOT_ACCOUNT_ROW) : dataRows;

        for (const row of userRows) {
          if (
            mfaCol >= 0 &&
            pwEnabledCol >= 0 &&
            row[pwEnabledCol] === 'true' &&
            row[mfaCol] === 'false'
          ) {
            usersWithoutMfa++;
          }

          if (
            isStaleKey(row[key1ActiveCol], row[key1RotatedCol]) ||
            isStaleKey(row[key2ActiveCol], row[key2RotatedCol])
          ) {
            usersWithStaleKeys++;
          }

          const userName = userCol >= 0 ? row[userCol] : undefined;
          const userResource = userName ? userResourceByName.get(userName) : undefined;
          if (!userResource) continue;

          const accessKeys = [
            {
              index: 1,
              active: row[key1ActiveCol] === 'true',
              lastRotated: nullIfNA(row[key1RotatedCol]),
              lastUsedDate: nullIfNA(row[key1LastUsedCol]),
            },
            {
              index: 2,
              active: row[key2ActiveCol] === 'true',
              lastRotated: nullIfNA(row[key2RotatedCol]),
              lastUsedDate: nullIfNA(row[key2LastUsedCol]),
            },
          ].filter((k) => k.active || k.lastRotated);

          userResource.metadata = {
            ...userResource.metadata,
            mfaActive: mfaCol >= 0 ? row[mfaCol] === 'true' : undefined,
            passwordEnabled: pwEnabledCol >= 0 ? row[pwEnabledCol] === 'true' : undefined,
            credentialReportPasswordLastUsed: nullIfNA(row[pwLastUsedCol]),
            accessKeys,
          };
        }

        reportEvidence = {
          generatedTime: field(reportXml, 'GeneratedTime'),
          totalUsers: userRows.length,
          usersWithoutMfa,
          usersWithStaleAccessKeys: usersWithStaleKeys,
          root: rootRow
            ? {
              mfaActive: mfaCol >= 0 ? rootRow[mfaCol] === 'true' : null,
              accessKey1Active: key1ActiveCol >= 0 ? rootRow[key1ActiveCol] === 'true' : null,
              accessKey2Active: key2ActiveCol >= 0 ? rootRow[key2ActiveCol] === 'true' : null,
              passwordLastUsed: nullIfNA(rootRow[pwLastUsedCol]),
              accessKey1LastUsedDate: nullIfNA(rootRow[key1LastUsedCol]),
              accessKey2LastUsedDate: nullIfNA(rootRow[key2LastUsedCol]),
            }
            : null,
        };
      }
    } catch (err) {
      credentialReportStatus = 'failed';
      credentialReportError = err instanceof Error ? err.message : String(err);
      recordOptionalFailure('CredentialReport', err);
    }

    const [accountSummary, passwordPolicy] = await Promise.all([accountSummaryPromise, passwordPolicyPromise]);

    /*
     * The account-level row is written on EVERY run. It used to be written
     * only when the report was available -- so a not-ready report made the
     * row vanish, and finalize tombstoned it. Now an unavailable report is an
     * explicit status with null counts (NOT_ASSESSED), never a deletion.
     */
    out.push({
      resourceTypeKey: 'iam_credential_report',
      resourceId: 'credential-report',
      region: null,
      resourceName: 'IAM Credential Report',
      metadata: {
        ...reportEvidence,
        status: credentialReportStatus,
        ...(credentialReportError ? { error: credentialReportError } : {}),
        accountSummary,
        passwordPolicy,
      },
    });

    const completedAt = new Date().toISOString();
    const diagnostics: IamScanDiagnostics = {
      scanner: 'iam',
      scanner_version: 'v1',
      // A page-capped or malformed walk is as incomplete as a failed call.
      status: operations.some((operation) => operation.status === 'failed' || operation.status === 'partial') ? 'partial' : 'success',
      startedAt,
      completedAt,
      operations,
    };

    // Attach identical diagnostics by value to every resource so the current
    // ScannedResource[] contract remains unchanged while production telemetry
    // becomes queryable downstream.
    const finalDiagnostics = {
      ...diagnostics,
      principalAnalysis: {
        totalPrincipals: principalsToAnalyze.length,
        eligiblePrincipals: analysable.length,
        analyzedPrincipals: analysisCount,
        skippedServiceLinkedRoles: principalsToAnalyze.length - analysable.length,
        cap: ROLE_ANALYSIS_CAP,
        capped: analysable.length > ROLE_ANALYSIS_CAP,
      },
      credentialReport: {
        status: credentialReportStatus,
        ...(credentialReportError ? { error: credentialReportError } : {}),
      },
    };

    for (const resource of out) {
      resource.metadata = {
        ...resource.metadata,
        iamScanDiagnostics: finalDiagnostics,
      };
    }

    return out;
  } catch (err) {
    const completedAt = new Date().toISOString();
    const diagnostics: IamScanDiagnostics = {
      scanner: 'iam',
      scanner_version: 'v1',
      status: 'failed',
      startedAt,
      completedAt,
      operations,
    };

    // Fail closed. The existing scanner API cannot carry a top-level failure
    // object, so throwing is intentional: discovery.ts must record the scan
    // execution as failed rather than persisting a misleading empty inventory.
    throw new Error(
      `AWS IAM inventory scan failed: ${err instanceof Error ? err.message : String(err)}. ` +
      `Diagnostics: ${JSON.stringify(diagnostics)}`,
    );
  }
}

/**
 * Decode AWS credential-report Content (base64 CSV). `atob` exists on Workers
 * and on Node 16+. The previous version swallowed a decode error and then
 * reported "No base64 decoder available", which misdirected every
 * investigation of a malformed report.
 */
export function decodeBase64Text(value: string): string {
  if (typeof atob !== 'function') {
    throw new Error('No base64 decoder available in the current runtime');
  }
  let binary: string;
  try {
    binary = atob(value.replace(/\s+/g, ''));
  } catch (err) {
    throw new Error(`Credential report content is not valid base64: ${err instanceof Error ? err.message : String(err)}`);
  }
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

/**
 * Minimal RFC-4180-compatible CSV parser for AWS credential reports.
 * Handles quoted fields, escaped quotes, CRLF and commas/newlines inside quotes.
 */
export function parseCsv(input: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let value = '';
  let inQuotes = false;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];

    if (inQuotes) {
      if (ch === '"') {
        if (input[i + 1] === '"') {
          value += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        value += ch;
      }
      continue;
    }

    if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(value);
      value = '';
    } else if (ch === '\n') {
      row.push(value);
      rows.push(row);
      row = [];
      value = '';
    } else if (ch !== '\r') {
      value += ch;
    }
  }

  if (value.length > 0 || row.length > 0) {
    row.push(value);
    rows.push(row);
  }

  return rows.filter((r) => r.some((v) => v.length > 0));
}

/**
 * The credential report CSV uses literal sentinels for fields that don't
 * apply: "N/A", "not_supported" (password fields on the root row) and
 * "no_information" (a password never used since AWS began tracking it).
 * Normalized to null so downstream consumers don't have to special-case them.
 */
export function nullIfNA(value: string | undefined): string | null {
  if (!value) return null;
  const normalized = value.trim();
  if (!normalized || normalized === 'N/A' || normalized === 'not_supported' || normalized === 'no_information') return null;
  return normalized;
}

// ── Account-level evidence ──────────────────────────────────────────────────

export interface AccountSummaryEvidence {
  collected: boolean;
  /** Root user has MFA (CIS 1.5). */
  accountMfaEnabled: boolean | null;
  /** Root user has access keys (CIS 1.4). */
  accountAccessKeysPresent: boolean | null;
  accountSigningCertificatesPresent: boolean | null;
  users: number | null;
  roles: number | null;
  groups: number | null;
  policies: number | null;
  mfaDevices: number | null;
  mfaDevicesInUse: number | null;
}

/** GetAccountSummary's <SummaryMap><entry><key/><value/></entry>… */
export function parseAccountSummary(xml: string | null): AccountSummaryEvidence {
  const empty: AccountSummaryEvidence = {
    collected: false, accountMfaEnabled: null, accountAccessKeysPresent: null, accountSigningCertificatesPresent: null,
    users: null, roles: null, groups: null, policies: null, mfaDevices: null, mfaDevicesInUse: null,
  };
  if (!xml) return empty;
  const map = new Map<string, number>();
  for (const entry of extractListItems(extractSection(xml, 'SummaryMap'), 'entry')) {
    const key = field(entry, 'key');
    const value = Number(field(entry, 'value'));
    if (key && Number.isFinite(value)) map.set(key, value);
  }
  if (map.size === 0) return empty;
  const flag = (k: string) => (map.has(k) ? (map.get(k) ?? 0) > 0 : null);
  const num = (k: string) => map.get(k) ?? null;
  return {
    collected: true,
    accountMfaEnabled: flag('AccountMFAEnabled'),
    accountAccessKeysPresent: flag('AccountAccessKeysPresent'),
    accountSigningCertificatesPresent: flag('AccountSigningCertificatesPresent'),
    users: num('Users'), roles: num('Roles'), groups: num('Groups'), policies: num('Policies'),
    mfaDevices: num('MFADevices'), mfaDevicesInUse: num('MFADevicesInUse'),
  };
}

export interface PasswordPolicyEvidence {
  /** false when the policy could not be read (NOT_ASSESSED). */
  collected: boolean;
  /** false when the account has no password policy at all. */
  configured: boolean | null;
  minimumPasswordLength: number | null;
  requireSymbols: boolean | null;
  requireNumbers: boolean | null;
  requireUppercaseCharacters: boolean | null;
  requireLowercaseCharacters: boolean | null;
  allowUsersToChangePassword: boolean | null;
  expirePasswords: boolean | null;
  maxPasswordAge: number | null;
  passwordReusePrevention: number | null;
  hardExpiry: boolean | null;
}

export const EMPTY_PASSWORD_POLICY: PasswordPolicyEvidence = {
  collected: false, configured: null, minimumPasswordLength: null, requireSymbols: null, requireNumbers: null,
  requireUppercaseCharacters: null, requireLowercaseCharacters: null, allowUsersToChangePassword: null,
  expirePasswords: null, maxPasswordAge: null, passwordReusePrevention: null, hardExpiry: null,
};

export function parsePasswordPolicy(xml: string): PasswordPolicyEvidence {
  const section = extractSection(xml, 'PasswordPolicy') ?? xml;
  const bool = (k: string): boolean | null => {
    const v = field(section, k);
    return v === null ? null : v === 'true';
  };
  const num = (k: string): number | null => {
    const v = field(section, k);
    const n = v === null ? NaN : Number(v);
    return Number.isFinite(n) ? n : null;
  };
  return {
    collected: true,
    configured: true,
    minimumPasswordLength: num('MinimumPasswordLength'),
    requireSymbols: bool('RequireSymbols'),
    requireNumbers: bool('RequireNumbers'),
    requireUppercaseCharacters: bool('RequireUppercaseCharacters'),
    requireLowercaseCharacters: bool('RequireLowercaseCharacters'),
    allowUsersToChangePassword: bool('AllowUsersToChangePassword'),
    expirePasswords: bool('ExpirePasswords'),
    maxPasswordAge: num('MaxPasswordAge'),
    passwordReusePrevention: num('PasswordReusePrevention'),
    hardExpiry: bool('HardExpiry'),
  };
}

interface RootCredentialEvidence {
  mfaActive: boolean | null;
  accessKey1Active: boolean | null;
  accessKey2Active: boolean | null;
  passwordLastUsed: string | null;
  accessKey1LastUsedDate: string | null;
  accessKey2LastUsedDate: string | null;
}

interface CredentialReportEvidence {
  generatedTime: string | null;
  /** IAM users in the report, excluding the root row. Null when the report was unavailable. */
  totalUsers: number | null;
  usersWithoutMfa: number | null;
  usersWithStaleAccessKeys: number | null;
  /** The account root user (CIS 1.4 / 1.5 / 1.7). Null when unavailable. */
  root: RootCredentialEvidence | null;
}

const EMPTY_REPORT_EVIDENCE: CredentialReportEvidence = {
  generatedTime: null, totalUsers: null, usersWithoutMfa: null, usersWithStaleAccessKeys: null, root: null,
};

export interface CloudIdentityRow {
  connection_id: string; provider: 'aws'; identity_type: 'user' | 'role' | 'group';
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
    .filter((v): v is string => typeof v === 'string' && Number.isFinite(new Date(v).getTime()));

  if (candidates.length > 0) {
    return {
      at: candidates.reduce((a, b) => (new Date(a).getTime() > new Date(b).getTime() ? a : b)),
      source: 'credential_report',
    };
  }

  const passwordLastUsed = metadata?.passwordLastUsed;
  if (typeof passwordLastUsed === 'string' && Number.isFinite(new Date(passwordLastUsed).getTime())) {
    return { at: passwordLastUsed, source: 'provider_api' };
  }

  return { at: null, source: null };
}

const IDENTITY_TYPE_BY_RESOURCE_TYPE: Record<string, CloudIdentityRow['identity_type']> = {
  iam_user: 'user', iam_role: 'role', iam_group: 'group',
};

/**
 * Derives cloud_identities rows from this scanner's own iam_user/iam_role/
 * iam_group output -- same "no second API call, just reshape what was
 * already fetched" convention as cloudwatch.ts's extractMonitoringAlarmRows.
 * Instance profiles are still excluded: a wrapper around a role (already
 * captured), not a distinct identity. A group IS included even though it
 * can't itself authenticate or be assumed -- is_human is always false for
 * it, same as a role, but its attached/inline policies are real permissions
 * its members inherit and worth surfacing here alongside the principals
 * that hold them directly.
 */
export function extractCloudIdentityRows(scanned: ScannedResource[], connectionId: string): CloudIdentityRow[] {
  const now = new Date().toISOString();
  return scanned
    .filter((r): r is ScannedResource & { resourceId: string } => r.resourceTypeKey in IDENTITY_TYPE_BY_RESOURCE_TYPE)
    .map((r) => {
      const { at, source } = latestUsedAt(r.metadata);
      return {
        connection_id: connectionId, provider: 'aws', identity_type: IDENTITY_TYPE_BY_RESOURCE_TYPE[r.resourceTypeKey],
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