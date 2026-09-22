import { callJsonApi, createAwsClient, safeFetch, type AwsCreds } from './awsApi';
import type { PermissionCheckResult } from './permissionChecks';

/**
 * AWS-P2 — the six capabilities the matrix requires that had no probe at all.
 *
 * Their state was therefore `unknown` forever, which the frontend had no way
 * to distinguish from "we looked and it is fine". A capability nobody probed
 * is not a capability that works.
 *
 * Every probe here follows the discipline the existing ones established: an
 * ENABLEMENT answer is not a PERMISSION answer. `permission_denied` sends a
 * customer to edit an IAM policy; `not_enabled` sends them to switch a service
 * on; `unsupported` tells them their support plan excludes it. Getting that
 * wrong wastes an afternoon editing a policy that was already correct.
 *
 * They are `verified: false` on the established convention — implemented
 * against the documented API shape, degrading to an honest `error` rather than
 * a wrong `granted` if a response shape turns out to differ.
 *
 * Kept in their own module rather than appended to permissionChecks.ts, which
 * is already 339 lines and carries the original twelve.
 */

/**
 * GuardDuty answers 200 with an EMPTY detector list when it has never been
 * enabled in a region. That is an enablement state, not a clean result:
 * reporting "no threats" for an account GuardDuty never watched is precisely
 * the false-clean this phase exists to remove.
 */
export async function checkGuardDuty(creds: AwsCreds, region: string): Promise<PermissionCheckResult> {
  const base = { service: 'guardduty', label: 'GuardDuty', verified: false };
  try {
    const client = createAwsClient(creds, 'guardduty', region);
    const res = await safeFetch(client, `https://guardduty.${region}.amazonaws.com/detector`, { method: 'GET' });

    if (res.status === 403) return { ...base, status: 'denied', detail: 'guardduty:ListDetectors was denied.' };
    if (!res.ok) return { ...base, status: 'error', detail: `AWS returned HTTP ${res.status} for GuardDuty.` };

    const body = (await res.json().catch(() => ({}))) as { detectorIds?: string[] };
    const detectors = body.detectorIds ?? [];

    if (detectors.length === 0) {
      return { ...base, status: 'not_applicable', detail: 'GuardDuty is not enabled in this region — no detector exists, so there are no findings to read.' };
    }
    return { ...base, status: 'granted', detail: `Read access to GuardDuty confirmed — ${detectors.length} detector(s) in ${region}` };
  } catch (err) {
    return { ...base, status: 'error', detail: err instanceof Error ? err.message : 'Request failed' };
  }
}

/** Inspector reports its own per-account enablement, so it is read directly rather than inferred from an empty finding list. */
export async function checkInspector(creds: AwsCreds, region: string): Promise<PermissionCheckResult> {
  const base = { service: 'inspector', label: 'Inspector', verified: false };
  try {
    const res = await callJsonApi(creds, {
      service: 'inspector2', region, host: `inspector2.${region}.amazonaws.com`,
      target: 'Inspector2.BatchGetAccountStatus', body: {},
    });

    if (!res.ok) {
      if (res.normalizedCode === 'PERMISSION_DENIED') return { ...base, status: 'denied', detail: 'inspector2:BatchGetAccountStatus was denied.' };
      if (res.normalizedCode === 'UNSUPPORTED_CAPABILITY') return { ...base, status: 'not_applicable', detail: 'Inspector is not available in this region.' };
      return { ...base, status: 'error', detail: res.errorMessage ?? res.normalizedCode ?? `HTTP ${res.status}` };
    }

    const accounts = (res.body as { accounts?: { state?: { status?: string } }[] })?.accounts ?? [];
    const status = accounts[0]?.state?.status;

    // ENABLED is the only state that yields findings. DISABLED and SUSPENDED
    // are opt-in states, not faults.
    if (status && status !== 'ENABLED') {
      return { ...base, status: 'not_applicable', detail: `Inspector is not enabled for this account (status: ${status}).` };
    }
    return { ...base, status: 'granted', detail: 'Read access to Inspector confirmed and the account is enabled' };
  } catch (err) {
    return { ...base, status: 'error', detail: err instanceof Error ? err.message : 'Request failed' };
  }
}

/** Access Analyzer produces nothing without an analyzer, so an empty list is an enablement state. */
export async function checkAccessAnalyzer(creds: AwsCreds, region: string): Promise<PermissionCheckResult> {
  const base = { service: 'access_analyzer', label: 'IAM Access Analyzer', verified: false };
  try {
    const client = createAwsClient(creds, 'access-analyzer', region);
    const res = await safeFetch(client, `https://access-analyzer.${region}.amazonaws.com/analyzer`, { method: 'GET' });

    if (res.status === 403) return { ...base, status: 'denied', detail: 'access-analyzer:ListAnalyzers was denied.' };
    if (!res.ok) return { ...base, status: 'error', detail: `AWS returned HTTP ${res.status} for IAM Access Analyzer.` };

    const body = (await res.json().catch(() => ({}))) as { analyzers?: unknown[] };
    const analyzers = body.analyzers ?? [];

    if (analyzers.length === 0) {
      return { ...base, status: 'not_applicable', detail: 'IAM Access Analyzer is not enabled — no analyzer exists in this region, so external-access findings cannot be produced.' };
    }
    return { ...base, status: 'granted', detail: `Read access to IAM Access Analyzer confirmed — ${analyzers.length} analyzer(s) in ${region}` };
  } catch (err) {
    return { ...base, status: 'error', detail: err instanceof Error ? err.message : 'Request failed' };
  }
}

/**
 * ECS is deliberately different from GuardDuty above: there is nothing to
 * "enable". A readable account with no clusters is an AUTHORITATIVE zero, and
 * calling that `not_applicable` would destroy exactly the distinction the
 * container screens need between "no clusters" and "we could not look".
 */
export async function checkEcs(creds: AwsCreds, region: string): Promise<PermissionCheckResult> {
  const base = { service: 'ecs', label: 'ECS', verified: false };
  try {
    const res = await callJsonApi(creds, {
      service: 'ecs', region, host: `ecs.${region}.amazonaws.com`,
      target: 'AmazonEC2ContainerServiceV20141113.ListClusters', body: {},
    });

    if (!res.ok) {
      if (res.normalizedCode === 'PERMISSION_DENIED') return { ...base, status: 'denied', detail: 'ecs:ListClusters was denied.' };
      return { ...base, status: 'error', detail: res.errorMessage ?? res.normalizedCode ?? `HTTP ${res.status}` };
    }

    const clusters = (res.body as { clusterArns?: string[] })?.clusterArns ?? [];
    return { ...base, status: 'granted', detail: `Read access to ECS confirmed — ${clusters.length} cluster(s) in ${region}` };
  } catch (err) {
    return { ...base, status: 'error', detail: err instanceof Error ? err.message : 'Request failed' };
  }
}

/** The Health API is global and answers only on its us-east-1 endpoint. */
export async function checkAwsHealth(creds: AwsCreds): Promise<PermissionCheckResult> {
  const base = { service: 'health', label: 'AWS Health', verified: false };
  try {
    const res = await callJsonApi(creds, {
      service: 'health', region: 'us-east-1', host: 'health.us-east-1.amazonaws.com',
      target: 'AWSHealth_20160804.DescribeEventTypes', body: { maxResults: 1 },
    });

    if (!res.ok) {
      /*
       * SubscriptionRequiredException is AWS's answer for "your support plan
       * does not include this". No policy edit fixes it, so it is an
       * unsupported state rather than a denial — the same distinction Trusted
       * Advisor needs, and the reason both map to `unsupported` in the matrix.
       */
      const code = `${res.errorCode ?? ''} ${res.errorMessage ?? ''}`;
      if (/SubscriptionRequired/i.test(code)) {
        return { ...base, status: 'not_applicable', detail: 'The AWS Health API requires a Business or Enterprise support plan on this account.' };
      }
      if (res.normalizedCode === 'PERMISSION_DENIED') return { ...base, status: 'denied', detail: 'health:DescribeEventTypes was denied.' };
      return { ...base, status: 'error', detail: res.errorMessage ?? res.normalizedCode ?? `HTTP ${res.status}` };
    }
    return { ...base, status: 'granted', detail: 'Read access to the AWS Health API confirmed' };
  } catch (err) {
    return { ...base, status: 'error', detail: err instanceof Error ? err.message : 'Request failed' };
  }
}

/**
 * The Cost & Usage Report API is global and lives only in us-east-1.
 *
 * Permission confirmed but no report defined is the most important state this
 * probe can return: it is exactly the difference between "this account spent
 * nothing" and "nobody ever told us where the bill is" — the distinction the
 * product currently cannot make, and the reason cost reads $0.
 */
export async function checkCur(creds: AwsCreds): Promise<PermissionCheckResult> {
  const base = { service: 'cur', label: 'Cost & Usage Report', verified: false };
  try {
    const res = await callJsonApi(creds, {
      service: 'cur', region: 'us-east-1', host: 'cur.us-east-1.amazonaws.com',
      target: 'AWSOrigamiServiceGatewayService.DescribeReportDefinitions', body: {},
    });

    if (!res.ok) {
      if (res.normalizedCode === 'PERMISSION_DENIED') return { ...base, status: 'denied', detail: 'cur:DescribeReportDefinitions was denied.' };
      return { ...base, status: 'error', detail: res.errorMessage ?? res.normalizedCode ?? `HTTP ${res.status}` };
    }

    const reports = (res.body as { ReportDefinitions?: unknown[] })?.ReportDefinitions ?? [];
    if (reports.length === 0) {
      return { ...base, status: 'not_applicable', detail: 'No Cost and Usage Report is defined in this account, so per-resource cost data is not enabled.' };
    }
    return { ...base, status: 'granted', detail: `Read access to Cost & Usage Reports confirmed — ${reports.length} report definition(s)` };
  } catch (err) {
    return { ...base, status: 'error', detail: err instanceof Error ? err.message : 'Request failed' };
  }
}
