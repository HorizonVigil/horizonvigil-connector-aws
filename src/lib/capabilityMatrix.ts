import type { PermissionCheckResult } from './permissionChecks';

/**
 * AWS-P2 — the capability matrix that replaces a blended pass/fail verdict.
 *
 * THE DEFECT THIS REPLACES
 *
 * `routes/permissions.ts` decided the outcome of a whole validation run from
 * ONE check:
 *
 *     const overallStatus = checks.length > 0 && stsCheck?.status === 'granted'
 *       ? 'succeeded' : 'failed';
 *
 * So a run was "succeeded" whenever STS answered, however many other checks
 * errored. Measured in production on 2026-09-22: both AWS connections report
 * `status: succeeded` while carrying **two `error` checks each** — Security Hub
 * (HTTP 401) and Compute Optimizer (RESOURCE_NOT_FOUND). A customer reading
 * "succeeded" has been told their account is fine when two sources are dark.
 *
 * The opposite failure is just as bad and is why this is a matrix rather than
 * a stricter boolean: if ANY failing check failed the run, then an account
 * without Trusted Advisor (no Business support plan) or without AWS Config
 * enabled would report its whole AWS connection as broken. Neither is broken.
 * They are optional sources that are off.
 *
 * So: required capabilities decide the run's verdict, optional ones decide
 * their own state and nothing else, and EVERY unavailable capability carries
 * an instruction that fixes it.
 *
 * WHY "not enabled" IS NOT "denied"
 *
 * The distinction runs through this whole file. `permission_denied` sends
 * someone to edit an IAM policy. `not_enabled` sends them to switch a service
 * on. `unsupported` tells them their support plan does not include it. Getting
 * this wrong wastes a customer's afternoon editing a policy that was already
 * correct.
 */

/** The state vocabulary. A superset of what any single probe can produce. */
export type CapabilityState =
  /** Probed, permitted, and the service answered. */
  | 'available'
  /** IAM refused. Fixed by editing a policy. */
  | 'permission_denied'
  /** Permitted, but the customer has not switched the service on. */
  | 'not_enabled'
  /** Cannot be switched on here — wrong support plan, wrong region, wrong partition. */
  | 'unsupported'
  /** AWS itself failed or was unreachable. Not the customer's to fix. */
  | 'service_unavailable'
  /** Answered for some scopes and not others. */
  | 'partial'
  /** Last success is older than the freshness policy for this capability. */
  | 'stale'
  /** Never probed, or the probe returned something unrecognised. Never a stand-in for "fine". */
  | 'unknown';

export interface CapabilitySpec {
  /** Stable key stored on `connector_capability_status.capability`. */
  key: string;
  label: string;
  /**
   * A required capability's failure fails the whole validation run, because
   * HorizonVigil cannot do its core job without it. An optional one cannot:
   * an account with no Security Hub subscription is a normal account.
   */
  required: boolean;
  /** The probe's `service` value in PermissionCheckResult, when one exists. */
  probeService: string | null;
  /** What the customer does about it. Shown verbatim when the state is not `available`. */
  setup: string;
}

/**
 * Required = HorizonVigil's core promise. Inventory, identity, tagging,
 * metrics and change history are what every other surface is built from; if
 * any is unavailable the connection genuinely cannot deliver its product.
 *
 * Everything else is a source a customer may or may not run. Its absence is
 * information, not a fault.
 */
export const CAPABILITIES: readonly CapabilitySpec[] = [
  // ---- Required ----
  {
    key: 'identity_sts', label: 'AWS identity (STS)', required: true, probeService: 'sts',
    setup: 'HorizonVigil could not confirm which AWS identity these credentials belong to. Check that the access key or role is active and that sts:GetCallerIdentity is allowed.',
  },
  {
    key: 'identity', label: 'IAM inventory', required: true, probeService: 'iam',
    setup: 'Grant the read-only IAM actions from the HorizonVigil policy (iam:List*, iam:Get*, iam:GenerateCredentialReport) so users, roles and key age can be inventoried.',
  },
  {
    key: 'governance_tags', label: 'Resource Groups Tagging API', required: true, probeService: 'tagging',
    setup: 'Grant tag:GetResources and tag:GetTagKeys. Without the Tagging API, ownership and cost allocation cannot be resolved for most resources.',
  },
  {
    key: 'metrics', label: 'CloudWatch metrics', required: true, probeService: 'cloudwatch',
    setup: 'Grant cloudwatch:GetMetricData and cloudwatch:ListMetrics. Utilisation evidence for rightsizing and idle detection comes from here.',
  },
  {
    key: 'activity_cloudtrail', label: 'CloudTrail change history', required: true, probeService: 'cloudtrail',
    setup: 'Grant cloudtrail:LookupEvents. Every AWS account has 90 days of Event History with no Trail configured, so this needs only the permission.',
  },
  {
    key: 'inventory', label: 'Resource discovery', required: true, probeService: null,
    setup: 'Resource discovery uses the per-service read permissions in the HorizonVigil policy. Re-apply the policy if inventory is incomplete.',
  },

  // ---- Optional: billing ----
  {
    key: 'billing_cost_explorer', label: 'Cost Explorer', required: false, probeService: 'cost_explorer',
    setup: 'Enable Cost Explorer in the AWS Billing console (Billing → Cost Explorer). AWS takes up to 24 hours to publish the first data after enabling it.',
  },
  {
    key: 'billing_cur', label: 'Cost & Usage Report / Data Exports', required: false, probeService: 'cur',
    setup: 'Create a Cost and Usage Report (or a Data Export) with resource IDs enabled, delivered to an S3 bucket HorizonVigil can read. Per-resource cost is unavailable without it.',
  },

  // ---- Optional: security sources ----
  {
    key: 'posture_securityhub', label: 'Security Hub', required: false, probeService: 'securityhub',
    setup: 'Enable AWS Security Hub in each region you want covered. Security Hub answers HTTP 401 until it is subscribed, which is not a permission problem.',
  },
  {
    key: 'posture_guardduty', label: 'GuardDuty', required: false, probeService: 'guardduty',
    setup: 'Enable Amazon GuardDuty in each region you want covered. Threat findings are unavailable until a detector exists.',
  },
  {
    key: 'posture_inspector', label: 'Inspector', required: false, probeService: 'inspector',
    setup: 'Activate Amazon Inspector for EC2, ECR or Lambda scanning. Vulnerability findings are unavailable until it is activated.',
  },
  {
    key: 'exposure_access_analyzer', label: 'IAM Access Analyzer', required: false, probeService: 'access_analyzer',
    setup: 'Create an IAM Access Analyzer analyzer with account or organization scope. External-access findings are unavailable without one.',
  },
  {
    key: 'posture_config', label: 'AWS Config (posture)', required: false, probeService: 'config',
    setup: 'Create an AWS Config configuration recorder and delivery channel in each region. Config records nothing until a recorder exists, so there is no posture evidence to read.',
  },
  {
    key: 'compliance_config', label: 'AWS Config (compliance)', required: false, probeService: 'config',
    setup: 'Deploy at least one AWS Config conformance pack after enabling the recorder. Control evaluations come from conformance-pack results.',
  },

  // ---- Optional: advisory ----
  {
    key: 'recommendations', label: 'Compute Optimizer', required: false, probeService: 'compute_optimizer',
    setup: 'Opt in to AWS Compute Optimizer (Compute Optimizer console → Get started). It answers RESOURCE_NOT_FOUND until the account is enrolled, which is not an error.',
  },
  {
    key: 'advisory_trusted_advisor', label: 'Trusted Advisor', required: false, probeService: 'trusted_advisor',
    setup: 'Trusted Advisor checks require a Business or Enterprise support plan. This cannot be enabled by changing permissions.',
  },
  {
    key: 'advisory_health', label: 'AWS Health', required: false, probeService: 'health',
    setup: 'The AWS Health API requires a Business or Enterprise support plan. Account health events are unavailable on other plans.',
  },

  // ---- Optional: orchestration ----
  {
    key: 'kubernetes_eks', label: 'EKS', required: false, probeService: 'eks',
    setup: 'Grant eks:ListClusters and eks:DescribeCluster. If the account genuinely runs no clusters this will report available with zero clusters, which is a different answer.',
  },
  {
    key: 'containers_ecs', label: 'ECS', required: false, probeService: 'ecs',
    setup: 'Grant ecs:ListClusters, ecs:DescribeClusters and ecs:ListServices to inventory ECS workloads.',
  },
  {
    key: 'organizations', label: 'AWS Organizations', required: false, probeService: 'organizations',
    setup: 'Connect the AWS Organizations management account to discover member accounts. A standalone account is not part of an organization, which is not a fault.',
  },
];

const BY_PROBE = new Map<string, CapabilitySpec[]>();
for (const c of CAPABILITIES) {
  if (!c.probeService) continue;
  const list = BY_PROBE.get(c.probeService);
  if (list) list.push(c);
  else BY_PROBE.set(c.probeService, [c]);
}

export function capabilitiesForProbe(service: string): CapabilitySpec[] {
  return BY_PROBE.get(service) ?? [];
}

export const REQUIRED_CAPABILITIES = CAPABILITIES.filter((c) => c.required);

/**
 * Detail text that means "the service is not switched on", not "you lack
 * permission". Matched on the probe's own wording because the probes return a
 * `not_applicable` status for several distinct reasons and only the text
 * separates them.
 */
const NOT_ENABLED_PHRASES = [
  /not enabled/i,
  /no configuration recorder/i,
  /not enrolled/i,
  /not subscribed/i,
  /not part of an aws organization/i,
  /RESOURCE_NOT_FOUND/i,
];

/** Detail text that means the account can never have it, whatever it changes. */
const UNSUPPORTED_PHRASES = [
  /support plan/i,
  /not available for this account/i,
];

/**
 * Maps one probe result onto the capability vocabulary.
 *
 * `not_applicable` is the interesting case: the probes use it for "service is
 * off", "account is standalone" AND "your support plan excludes this", which
 * are three different instructions to a customer. The detail text is what
 * separates them, so it is read here rather than thrown away.
 */
export function stateFromCheck(check: Pick<PermissionCheckResult, 'status' | 'detail'>): CapabilityState {
  const detail = check.detail ?? '';

  switch (check.status) {
    case 'granted':
      return 'available';

    case 'denied':
      return 'permission_denied';

    case 'not_applicable': {
      if (UNSUPPORTED_PHRASES.some((p) => p.test(detail))) return 'unsupported';
      if (NOT_ENABLED_PHRASES.some((p) => p.test(detail))) return 'not_enabled';
      /*
       * `not_applicable` with wording we do not recognise is NOT quietly
       * downgraded to not_enabled. A reason nobody has classified is exactly
       * the thing that should surface as unknown so it gets classified.
       */
      return 'unknown';
    }

    case 'error': {
      /*
       * An error carrying an enablement signal is an enablement problem, not a
       * fault. Compute Optimizer answers RESOURCE_NOT_FOUND until the account
       * opts in, and Security Hub answers 401 until it is subscribed -- both
       * arrive here as `error` from probes that could not classify them, and
       * both were reported to production customers as errors.
       */
      if (NOT_ENABLED_PHRASES.some((p) => p.test(detail))) return 'not_enabled';
      if (UNSUPPORTED_PHRASES.some((p) => p.test(detail))) return 'unsupported';
      return 'service_unavailable';
    }

    default:
      return 'unknown';
  }
}

/** Does this state mean the capability is delivering data right now? */
export function isUsable(state: CapabilityState): boolean {
  return state === 'available' || state === 'partial';
}

export interface ValidationVerdict {
  status: 'succeeded' | 'failed';
  /** Required capabilities that are not usable. Empty on success. */
  failedRequired: string[];
  /** Optional capabilities that are not usable. Never affects `status`. */
  unavailableOptional: string[];
  /** One sentence naming why, for storage on the run row. */
  summary: string;
}

/**
 * The run's verdict, from REQUIRED capabilities only.
 *
 * Replaces `stsCheck?.status === 'granted'`. Two properties this must hold,
 * and the old line held neither:
 *
 *   - it cannot say `succeeded` while a required capability is unusable;
 *   - it cannot say `failed` because an optional source is switched off.
 *
 * A check that was never run counts as a failure when required: a required
 * capability nobody probed has not been shown to work, and treating silence
 * as success is the defect this whole module exists to remove.
 */
export function verdictFor(checks: readonly Pick<PermissionCheckResult, 'service' | 'status' | 'detail'>[]): ValidationVerdict {
  const byService = new Map(checks.map((c) => [c.service, c]));

  const failedRequired: string[] = [];
  const unavailableOptional: string[] = [];

  for (const cap of CAPABILITIES) {
    // Capabilities with no probe (resource discovery) are judged by collection
    // runs, not here, and are not counted either way.
    if (!cap.probeService) continue;

    const check = byService.get(cap.probeService);
    const state = check ? stateFromCheck(check) : 'unknown';

    if (isUsable(state)) continue;
    if (cap.required) failedRequired.push(cap.label);
    else unavailableOptional.push(cap.label);
  }

  if (failedRequired.length > 0) {
    return {
      status: 'failed',
      failedRequired,
      unavailableOptional,
      summary: `${failedRequired.length} required ${failedRequired.length === 1 ? 'capability is' : 'capabilities are'} unavailable: ${failedRequired.join(', ')}.`,
    };
  }

  return {
    status: 'succeeded',
    failedRequired: [],
    unavailableOptional,
    summary: unavailableOptional.length > 0
      ? `All required capabilities are available. ${unavailableOptional.length} optional ${unavailableOptional.length === 1 ? 'source is' : 'sources are'} not in use: ${unavailableOptional.join(', ')}.`
      : 'All required and optional capabilities are available.',
  };
}

/** The customer-facing instruction for a capability that is not delivering data. */
export function setupFor(capabilityKey: string): string | null {
  return CAPABILITIES.find((c) => c.key === capabilityKey)?.setup ?? null;
}
