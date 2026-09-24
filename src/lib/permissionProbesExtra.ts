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
      if (res.normalizedCode === 'PERMISSION_DENIED') {
        /*
         * This message must not send someone to fix a policy that is already
         * correct.
         *
         * Measured 2026-09-22: both production connections return AccessDenied
         * here while carrying AdministratorAccess, in accounts belonging to no
         * AWS Organization -- so there is no policy gap and no SCP to explain
         * it. Amazon Inspector returns AccessDenied for this call in accounts
         * where the service has never been activated, which is an account
         * state, not a permission.
         *
         * The probe cannot tell the two apart from the response, so it says
         * so rather than asserting the one that happens to be wrong here.
         * Naming the cheaper check first is the point: activating Inspector is
         * a console toggle, editing an IAM policy is not.
         */
        return {
          ...base,
          status: 'denied',
          detail:
            'inspector2:BatchGetAccountStatus was denied. AWS returns this both when the role lacks the permission '
            + 'and when Amazon Inspector has never been activated in this account — check whether Inspector is '
            + 'enabled before changing the IAM policy.',
        };
      }
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
      /*
       * maxResults MUST be >= 10. This probe sent 1 from the day it was
       * written, so AWS rejected every call with
       *
       *   "1 validation error detected: Value '1' at 'maxResults' failed to
       *    satisfy constraint: Member must have value greater than or equal
       *    to 10"
       *
       * and the probe reported `error` -- for its entire life. It never once
       * tested the permission it exists to test, and "our request was
       * malformed" was indistinguishable from "AWS Health is unavailable".
       *
       * Found 2026-09-22, only after the account was granted admin: while
       * seven services were genuinely denied, one more failure in the list
       * looked like more of the same. Removing the real denials is what made
       * this visible.
       *
       * 10 is the documented minimum, and this probe wants the smallest legal
       * page -- it checks access, it does not read events.
       */
      target: 'AWSHealth_20160804.DescribeEventTypes', body: { maxResults: 10 },
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

/**
 * AWS-I1. The seven services named in the IAM-drift finding.
 *
 * WHY THESE EXIST
 *
 * Six of the seven were not probed by permission validation AT ALL — only
 * securityhub was. So when the deployed roles were missing these permissions,
 * validation reported a clean bill of health while every one of their
 * scanners was being refused, and the only trace was a `degraded_reasons`
 * entry buried in a collection run.
 *
 * It is worse than a gap in coverage: it makes the finding unverifiable by
 * the product. Asked "did re-applying the policy fix it?", validation could
 * not answer, and the absence of these services from its denied list read as
 * success. That misreading is exactly what happened on 2026-09-23 — admin was
 * attached, six services silently stayed denied, and nothing in the
 * validation output said so.
 *
 * Each probe calls the SAME endpoint its scanner calls, so a probe that
 * passes means that scanner can actually read. A probe that used a different
 * action would be answering a different question.
 */

/** One service's read access, probed through the endpoint its scanner uses. */
async function probeRest(
  creds: AwsCreds,
  opts: { service: string; label: string; awsService: string; url: string; method?: 'GET' | 'POST'; action: string },
): Promise<PermissionCheckResult> {
  const base = { service: opts.service, label: opts.label, verified: false };
  try {
    const client = createAwsClient(creds, opts.awsService, opts.url.split('.')[1] ?? 'us-east-1');
    const res = await safeFetch(
      client,
      opts.url,
      opts.method === 'POST'
        ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) }
        : { method: 'GET' },
    );
    if (res.ok) return { ...base, status: 'granted', detail: `Read access to ${opts.label} confirmed` };
    if (res.status === 403 || res.status === 401) {
      /*
       * Some of these services return AccessDenied when they have never been
       * ACTIVATED in the account, not when the principal lacks the permission
       * -- the same behaviour Inspector has. Measured 2026-09-23 against a
       * principal holding AdministratorAccess (`*:*`), which cannot have a
       * policy gap: lambda returned granted, while kafka, imagebuilder,
       * macie2 and license-manager all returned AccessDenied.
       *
       * So for those, the message must not send someone to edit a policy that
       * already allows everything. Lambda is excluded deliberately: it is
       * available in every commercial region and has no activation step, so a
       * denial there IS a policy gap and softening it would hide a real one.
       */
      const mayNeedActivation = opts.service !== 'lambda';
      return {
        ...base,
        status: 'denied',
        detail: mayNeedActivation
          ? `${opts.action} was denied. AWS returns this both when the role lacks the permission and when `
            + `${opts.label} has never been activated in this account — check whether it is enabled before changing the IAM policy.`
          : `${opts.action} was denied.`,
      };
    }
    if (res.status === 404) {
      return { ...base, status: 'not_applicable', detail: `${opts.label} is not available in this region.` };
    }
    return { ...base, status: 'error', detail: `${opts.action} returned HTTP ${res.status}.` };
  } catch (err) {
    return { ...base, status: 'error', detail: err instanceof Error ? err.message : 'Request failed' };
  }
}

/** Lambda. Always available in every commercial region — a denial here is a real policy gap, never an enablement state. */
export async function checkLambda(creds: AwsCreds, region: string): Promise<PermissionCheckResult> {
  return probeRest(creds, {
    service: 'lambda', label: 'Lambda', awsService: 'lambda',
    url: `https://lambda.${region}.amazonaws.com/2015-03-31/functions/?MaxItems=1`,
    action: 'lambda:ListFunctions',
  });
}

/** MSK (Kafka). */
export async function checkKafka(creds: AwsCreds, region: string): Promise<PermissionCheckResult> {
  return probeRest(creds, {
    service: 'kafka', label: 'MSK (Kafka)', awsService: 'kafka',
    url: `https://kafka.${region}.amazonaws.com/v1/clusters/v2?MaxResults=1`,
    action: 'kafka:ListClustersV2',
  });
}

/** EC2 Image Builder. */
export async function checkImageBuilder(creds: AwsCreds, region: string): Promise<PermissionCheckResult> {
  return probeRest(creds, {
    service: 'imagebuilder', label: 'EC2 Image Builder', awsService: 'imagebuilder',
    url: `https://imagebuilder.${region}.amazonaws.com/listImagePipelines`, method: 'POST',
    action: 'imagebuilder:ListImagePipelines',
  });
}

/** Macie. */
export async function checkMacie(creds: AwsCreds, region: string): Promise<PermissionCheckResult> {
  return probeRest(creds, {
    service: 'macie2', label: 'Macie', awsService: 'macie2',
    url: `https://macie2.${region}.amazonaws.com/jobs/list`, method: 'POST',
    action: 'macie2:ListClassificationJobs',
  });
}

/** Firewall Manager. JSON-protocol, and only answers in us-east-1. */
export async function checkFirewallManager(creds: AwsCreds): Promise<PermissionCheckResult> {
  const base = { service: 'fms', label: 'Firewall Manager', verified: false };
  try {
    const res = await callJsonApi(creds, {
      service: 'fms', region: 'us-east-1', host: 'fms.us-east-1.amazonaws.com',
      target: 'AWSFMS_20180101.ListPolicies', body: { MaxResults: 1 },
    });
    if (res.ok) return { ...base, status: 'granted', detail: 'Read access to Firewall Manager confirmed' };
    if (res.normalizedCode === 'PERMISSION_DENIED') return { ...base, status: 'denied', detail: 'fms:ListPolicies was denied.' };
    // FMS answers only for an account designated as the FMS administrator.
    // That is an account state, not a policy gap.
    if (/not.*(admin|associated)/i.test(`${res.errorCode ?? ''} ${res.errorMessage ?? ''}`)) {
      return { ...base, status: 'not_applicable', detail: 'This account is not a Firewall Manager administrator account.' };
    }
    return { ...base, status: 'error', detail: res.errorMessage ?? res.normalizedCode ?? `HTTP ${res.status}` };
  } catch (err) {
    return { ...base, status: 'error', detail: err instanceof Error ? err.message : 'Request failed' };
  }
}

/** License Manager. JSON-protocol, regional. */
export async function checkLicenseManager(creds: AwsCreds, region: string): Promise<PermissionCheckResult> {
  const base = { service: 'license_manager', label: 'License Manager', verified: false };
  try {
    const res = await callJsonApi(creds, {
      service: 'license-manager', region, host: `license-manager.${region}.amazonaws.com`,
      target: 'AWSLicenseManager.ListLicenseConfigurations', body: { MaxResults: 1 },
    });
    if (res.ok) return { ...base, status: 'granted', detail: 'Read access to License Manager confirmed' };
    if (res.normalizedCode === 'PERMISSION_DENIED') return { ...base, status: 'denied', detail: 'license-manager:ListLicenseConfigurations was denied.' };
    return { ...base, status: 'error', detail: res.errorMessage ?? res.normalizedCode ?? `HTTP ${res.status}` };
  } catch (err) {
    return { ...base, status: 'error', detail: err instanceof Error ? err.message : 'Request failed' };
  }
}
