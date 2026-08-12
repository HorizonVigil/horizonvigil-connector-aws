import { callQueryApi, callJsonApi, createAwsClient, extractXmlField, type AwsCreds } from './awsApi';

export type CheckStatus = 'granted' | 'denied' | 'error' | 'not_applicable';

export interface PermissionCheckResult {
  service: string;
  label: string;
  status: CheckStatus;
  detail: string;
  /** Whether this check's exact request shape has been confirmed against a
   * live AWS account. Unconfirmed ones follow the same documented pattern
   * as Inspector2 field-casing in the prior build (docs/about-project.md
   * §12) — implemented with reasonable confidence, degrades to an honest
   * `error` status rather than a wrong `granted`/`denied` if the shape is
   * off, but hasn't been verified end-to-end yet. */
  verified: boolean;
}

export interface IdentitySummary {
  arn: string | null;
  accountId: string | null;
  userId: string | null;
}

function isoDaysAgo(days: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - days);
  return d.toISOString().slice(0, 10);
}

/**
 * STS GetCallerIdentity — the one check every connection method needs to
 * pass before anything else means anything: confirms the stored credentials
 * (or an assumed role's temporary ones) actually authenticate as *something*
 * in AWS. Query-protocol, global endpoint, no parameters — the best-known,
 * lowest-risk AWS API call there is, so this one is `verified: true`.
 */
export async function checkCallerIdentity(creds: AwsCreds): Promise<{ result: PermissionCheckResult; identity: IdentitySummary | null }> {
  try {
    const res = await callQueryApi(creds, { service: 'sts', region: 'us-east-1', host: 'sts.amazonaws.com', action: 'GetCallerIdentity', version: '2011-06-15' });
    if (!res.ok) {
      return {
        result: { service: 'sts', label: 'STS (identity)', status: 'denied', detail: res.errorMessage ?? `AWS rejected the credentials (${res.errorCode ?? res.status})`, verified: true },
        identity: null,
      };
    }
    const xml = res.body as string;
    const identity: IdentitySummary = {
      arn: extractXmlField(xml, 'Arn'),
      accountId: extractXmlField(xml, 'Account'),
      userId: extractXmlField(xml, 'UserId'),
    };
    return {
      result: { service: 'sts', label: 'STS (identity)', status: 'granted', detail: identity.arn ? `Authenticated as ${identity.arn}` : 'Authenticated', verified: true },
      identity,
    };
  } catch (err) {
    return { result: { service: 'sts', label: 'STS (identity)', status: 'error', detail: err instanceof Error ? err.message : 'Request failed', verified: true }, identity: null };
  }
}

/** IAM GetAccountSummary — no required parameters, works for both IAM users and assumed roles, so it's a clean read-only permission probe. */
export async function checkIam(creds: AwsCreds): Promise<PermissionCheckResult> {
  try {
    const res = await callQueryApi(creds, { service: 'iam', region: 'us-east-1', host: 'iam.amazonaws.com', action: 'GetAccountSummary', version: '2010-05-08' });
    if (!res.ok) return { service: 'iam', label: 'IAM', status: res.status === 403 ? 'denied' : 'error', detail: res.errorMessage ?? `${res.errorCode ?? res.status}`, verified: true };
    return { service: 'iam', label: 'IAM', status: 'granted', detail: 'Read access to IAM account summary confirmed', verified: true };
  } catch (err) {
    return { service: 'iam', label: 'IAM', status: 'error', detail: err instanceof Error ? err.message : 'Request failed', verified: true };
  }
}

/** Organizations DescribeOrganization — a global service (single us-east-1 endpoint regardless of account region). AWSOrganizationsNotInUseException is a legitimate non-error (account isn't part of an Organization), not a permission failure. */
export async function checkOrganizations(creds: AwsCreds): Promise<PermissionCheckResult> {
  try {
    const res = await callJsonApi(creds, { service: 'organizations', region: 'us-east-1', host: 'organizations.us-east-1.amazonaws.com', target: 'AWSOrganizationsV20161128.DescribeOrganization', body: {} });
    if (!res.ok) {
      if (res.errorCode === 'AWSOrganizationsNotInUseException') return { service: 'organizations', label: 'AWS Organizations', status: 'not_applicable', detail: 'This account is not part of an AWS Organization', verified: true };
      return { service: 'organizations', label: 'AWS Organizations', status: res.status === 403 ? 'denied' : 'error', detail: res.errorMessage ?? res.errorCode ?? `HTTP ${res.status}`, verified: true };
    }
    return { service: 'organizations', label: 'AWS Organizations', status: 'granted', detail: 'Read access to Organizations confirmed', verified: true };
  } catch (err) {
    return { service: 'organizations', label: 'AWS Organizations', status: 'error', detail: err instanceof Error ? err.message : 'Request failed', verified: true };
  }
}

/** CloudWatch ListMetrics — Query-protocol classic API (not JSON), no required parameters. */
export async function checkCloudWatch(creds: AwsCreds, region: string): Promise<PermissionCheckResult> {
  try {
    const res = await callQueryApi(creds, { service: 'monitoring', region, host: `monitoring.${region}.amazonaws.com`, action: 'ListMetrics', version: '2010-08-01' });
    if (!res.ok) return { service: 'cloudwatch', label: 'CloudWatch', status: res.status === 403 ? 'denied' : 'error', detail: res.errorMessage ?? `${res.errorCode ?? res.status}`, verified: false };
    return { service: 'cloudwatch', label: 'CloudWatch', status: 'granted', detail: 'Read access to CloudWatch metrics confirmed', verified: false };
  } catch (err) {
    return { service: 'cloudwatch', label: 'CloudWatch', status: 'error', detail: err instanceof Error ? err.message : 'Request failed', verified: false };
  }
}

/** CloudTrail DescribeTrails — JSON protocol, no required parameters. */
export async function checkCloudTrail(creds: AwsCreds, region: string): Promise<PermissionCheckResult> {
  try {
    const res = await callJsonApi(creds, { service: 'cloudtrail', region, host: `cloudtrail.${region}.amazonaws.com`, target: 'CloudTrail_20131101.DescribeTrails', body: {} });
    if (!res.ok) return { service: 'cloudtrail', label: 'CloudTrail', status: res.status === 403 ? 'denied' : 'error', detail: res.errorMessage ?? res.errorCode ?? `HTTP ${res.status}`, verified: false };
    return { service: 'cloudtrail', label: 'CloudTrail', status: 'granted', detail: 'Read access to CloudTrail confirmed', verified: false };
  } catch (err) {
    return { service: 'cloudtrail', label: 'CloudTrail', status: 'error', detail: err instanceof Error ? err.message : 'Request failed', verified: false };
  }
}

/** Resource Groups Tagging API GetTagKeys — JSON protocol, no required parameters. */
export async function checkTaggingApi(creds: AwsCreds, region: string): Promise<PermissionCheckResult> {
  try {
    const res = await callJsonApi(creds, { service: 'tagging', region, host: `tagging.${region}.amazonaws.com`, target: 'ResourceGroupsTaggingAPI_20170126.GetTagKeys', body: {} });
    if (!res.ok) return { service: 'tagging', label: 'Resource Groups Tagging API', status: res.status === 403 ? 'denied' : 'error', detail: res.errorMessage ?? res.errorCode ?? `HTTP ${res.status}`, verified: false };
    return { service: 'tagging', label: 'Resource Groups Tagging API', status: 'granted', detail: 'Read access to Tagging API confirmed', verified: false };
  } catch (err) {
    return { service: 'tagging', label: 'Resource Groups Tagging API', status: 'error', detail: err instanceof Error ? err.message : 'Request failed', verified: false };
  }
}

/** Cost Explorer GetDimensionValues — JSON protocol. Cost Explorer only ever has a single global-ish endpoint in us-east-1 regardless of account region. */
export async function checkCostExplorer(creds: AwsCreds): Promise<PermissionCheckResult> {
  try {
    const res = await callJsonApi(creds, {
      service: 'ce',
      region: 'us-east-1',
      host: 'ce.us-east-1.amazonaws.com',
      target: 'AWSInsightsIndexService.GetDimensionValues',
      body: { TimePeriod: { Start: isoDaysAgo(7), End: isoDaysAgo(0) }, Dimension: 'SERVICE' },
    });
    if (!res.ok) {
      if (res.errorCode === 'DataUnavailableException') return { service: 'cost_explorer', label: 'Cost Explorer', status: 'not_applicable', detail: 'Cost Explorer has not accumulated data for this account yet', verified: false };
      return { service: 'cost_explorer', label: 'Cost Explorer', status: res.status === 403 ? 'denied' : 'error', detail: res.errorMessage ?? res.errorCode ?? `HTTP ${res.status}`, verified: false };
    }
    return { service: 'cost_explorer', label: 'Cost Explorer', status: 'granted', detail: 'Read access to Cost Explorer confirmed', verified: false };
  } catch (err) {
    return { service: 'cost_explorer', label: 'Cost Explorer', status: 'error', detail: err instanceof Error ? err.message : 'Request failed', verified: false };
  }
}

/**
 * EKS ListClusters — REST-JSON (plain signed GET, same shape as eks.ts's own
 * scanner call), added specifically because that scanner's failures were
 * previously invisible: it caught every error and silently returned an
 * empty cluster list, indistinguishable from an honest zero-cluster
 * account. This surfaces the same call's real status/error here instead,
 * so an account with real EKS infrastructure that keeps showing "0
 * clusters" has an actual answer instead of silence.
 */
export async function checkEks(creds: AwsCreds, region: string): Promise<PermissionCheckResult> {
  try {
    const client = createAwsClient(creds, 'eks', region);
    const res = await client.fetch(`https://eks.${region}.amazonaws.com/clusters`, { method: 'GET' });
    const text = await res.text();
    if (!res.ok) {
      let detail = text.slice(0, 300);
      try {
        const parsed = JSON.parse(text) as { message?: string };
        if (parsed.message) detail = parsed.message;
      } catch { /* not JSON, use raw text above */ }
      return { service: 'eks', label: 'EKS', status: res.status === 403 ? 'denied' : 'error', detail, verified: false };
    }
    const parsed = text ? (JSON.parse(text) as { clusters?: string[] }) : {};
    const count = parsed.clusters?.length ?? 0;
    return { service: 'eks', label: 'EKS', status: 'granted', detail: `Read access to EKS confirmed — ${count} cluster${count === 1 ? '' : 's'} found in ${region}`, verified: false };
  } catch (err) {
    return { service: 'eks', label: 'EKS', status: 'error', detail: err instanceof Error ? err.message : 'Request failed', verified: false };
  }
}

export interface FullValidationResult {
  identity: IdentitySummary | null;
  checks: PermissionCheckResult[];
}

/** Runs every permission check in parallel — each is independently fault-isolated (see individual functions), so one failing/erroring never prevents the others from reporting. */
export async function runFullValidation(creds: AwsCreds, region: string): Promise<FullValidationResult> {
  const { result: stsResult, identity } = await checkCallerIdentity(creds);

  // If STS itself fails, the credentials don't authenticate at all — every
  // other check would just fail the same way, so skip straight to reporting
  // that single root cause instead of 6 more denied/error rows saying nothing new.
  if (stsResult.status !== 'granted') {
    return { identity: null, checks: [stsResult] };
  }

  const [iam, organizations, cloudwatch, cloudtrail, tagging, costExplorer, eks] = await Promise.all([
    checkIam(creds),
    checkOrganizations(creds),
    checkCloudWatch(creds, region),
    checkCloudTrail(creds, region),
    checkTaggingApi(creds, region),
    checkCostExplorer(creds),
    checkEks(creds, region),
  ]);

  return { identity, checks: [stsResult, iam, organizations, cloudwatch, cloudtrail, tagging, costExplorer, eks] };
}
