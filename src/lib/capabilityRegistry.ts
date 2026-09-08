/**
 * The AWS connector's declared capability registry (connector spec §6, §28).
 *
 * Capabilities were previously implicit: which AWS services are integrated,
 * which are only probed, what each writes and who consumes it existed only as
 * ~120 scanner files plus a permission-check list. Nothing could answer "what
 * does this connector actually support?" without reading the source, which is
 * exactly how a product ends up claiming capabilities it does not have.
 *
 * This is deliberately a DECLARATION checked against the implementation by
 * capabilityRegistry.test.ts, not prose. If a probe is added or removed and
 * this file is not updated, the test fails.
 *
 * Two rules it exists to enforce:
 *  - `implemented` describes what the code does TODAY, never what is planned.
 *  - `actionSupported` is false everywhere on purpose. Direct provider
 *    mutation is gated off in V1 (PROVIDER_REMEDIATION_ENABLED); claiming
 *    otherwise here would be exactly the kind of unearned capability claim the
 *    2026-09-08 audits found across the product.
 */

export type CapabilityLifecycle = 'v1' | 'v2' | 'internal';

export interface AwsCapability {
  /** Stable key. Matches the `service` field of a PermissionCheckResult when a probe exists. */
  key: string;
  label: string;
  /** The AWS API(s) this capability reads. */
  awsApis: readonly string[];
  /** True only if this connector genuinely retrieves the data today. */
  implemented: boolean;
  /**
   * Whether runPermissionChecks() actively probes it. A capability that is
   * scanned but NOT probed can fail silently every night while the connection
   * still reports healthy — the gap §5C forbids.
   */
  probed: boolean;
  /** IAM actions the connected role needs. Used to generate the least-privilege policy. */
  requiredPermissions: readonly string[];
  /** Supabase tables this capability writes. Empty when it only answers live. */
  dataStored: readonly string[];
  /** HorizonVigil module that consumes it. */
  uiConsumer: string;
  /** Provider mutation. False everywhere in V1 by policy — see the file header. */
  actionSupported: boolean;
  lifecycle: CapabilityLifecycle;
}

export const AWS_CAPABILITIES: readonly AwsCapability[] = [
  {
    key: 'sts',
    label: 'Identity & connection validation',
    awsApis: ['sts:GetCallerIdentity', 'sts:AssumeRole'],
    implemented: true,
    probed: true,
    requiredPermissions: ['sts:GetCallerIdentity'],
    dataStored: ['cloud_connections'],
    uiConsumer: 'Cloud Accounts',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'iam',
    label: 'Identity risk & entitlements',
    awsApis: ['iam:GetAccountSummary', 'iam:List*', 'iam:Get*'],
    implemented: true,
    probed: true,
    requiredPermissions: ['iam:GetAccountSummary', 'iam:ListUsers', 'iam:ListRoles', 'iam:ListPolicies', 'iam:GetAccountPasswordPolicy', 'iam:ListMFADevices'],
    dataStored: ['cloud_identities', 'cloud_resources'],
    uiConsumer: 'Cloud Security → Identity & Access Risk',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'organizations',
    label: 'AWS Organizations hierarchy',
    awsApis: ['organizations:ListAccounts', 'organizations:ListRoots', 'organizations:ListOrganizationalUnits'],
    implemented: true,
    probed: true,
    requiredPermissions: ['organizations:ListAccounts', 'organizations:ListRoots', 'organizations:ListOrganizationalUnitsForParent', 'organizations:ListAccountsForParent'],
    dataStored: [],
    uiConsumer: 'Cloud Accounts → Hierarchy',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'resources',
    label: 'Resource discovery',
    awsApis: ['ec2:Describe*', 'rds:Describe*', 's3:List*', 'lambda:List*', 'eks:List*', '+ ~110 more service scanners'],
    implemented: true,
    // Covered indirectly: a failure in any scanner now degrades that
    // scanner's resource types (awsApi.ts creds sink), but there is no single
    // "resources" probe because coverage is per-service.
    probed: false,
    requiredPermissions: ['ec2:Describe*', 'rds:Describe*', 's3:ListAllMyBuckets', 's3:GetBucket*', 'lambda:ListFunctions', 'elasticloadbalancing:Describe*', 'eks:ListClusters', 'dynamodb:ListTables'],
    dataStored: ['cloud_resources', 'resource_lifecycle_events'],
    uiConsumer: 'Asset Inventory, Overview',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'tagging',
    label: 'Resource Groups Tagging API',
    awsApis: ['tag:GetResources'],
    implemented: true,
    probed: true,
    requiredPermissions: ['tag:GetResources'],
    dataStored: ['cloud_resources'],
    uiConsumer: 'Governance → Tags',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'cost_explorer',
    label: 'Cost & billing',
    awsApis: ['ce:GetCostAndUsage', 'ce:GetSavingsPlansUtilization', 'ce:GetReservationUtilization'],
    implemented: true,
    probed: true,
    requiredPermissions: ['ce:GetCostAndUsage', 'ce:GetCostForecast', 'ce:GetSavingsPlansUtilization', 'ce:GetReservationUtilization', 'ce:GetRightsizingRecommendation'],
    dataStored: ['cost_snapshots'],
    uiConsumer: 'FinOps, Cost Optimization',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'cur',
    label: 'Cost & Usage Report ingestion',
    awsApis: ['cur:DescribeReportDefinitions', 's3:GetObject'],
    implemented: true,
    probed: false,
    requiredPermissions: ['cur:DescribeReportDefinitions', 's3:GetObject', 's3:ListBucket'],
    dataStored: ['cost_snapshots'],
    uiConsumer: 'FinOps → Cost Explorer',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'cloudwatch',
    label: 'Operational metrics & alarms',
    awsApis: ['cloudwatch:ListMetrics', 'cloudwatch:GetMetricStatistics', 'cloudwatch:DescribeAlarms'],
    implemented: true,
    probed: true,
    requiredPermissions: ['cloudwatch:ListMetrics', 'cloudwatch:GetMetricStatistics', 'cloudwatch:GetMetricData', 'cloudwatch:DescribeAlarms'],
    dataStored: ['cloud_resources'],
    uiConsumer: 'Cloud Operations → Monitoring',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'cloudtrail',
    label: 'Activity & change history',
    awsApis: ['cloudtrail:LookupEvents', 'cloudtrail:DescribeTrails'],
    implemented: true,
    probed: true,
    requiredPermissions: ['cloudtrail:LookupEvents', 'cloudtrail:DescribeTrails', 'cloudtrail:GetTrailStatus'],
    dataStored: [],
    uiConsumer: 'Cloud Accounts → Activity',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'config',
    label: 'Configuration & compliance evidence',
    awsApis: ['config:DescribeConfigurationRecorders', 'config:DescribeComplianceByConfigRule'],
    implemented: true,
    probed: true,
    requiredPermissions: ['config:DescribeConfigurationRecorders', 'config:DescribeConfigRules', 'config:DescribeComplianceByConfigRule', 'config:GetComplianceDetailsByConfigRule'],
    dataStored: ['vulnerability_findings'],
    uiConsumer: 'Cloud Compliance, Cloud Security → Misconfigurations',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'securityhub',
    label: 'Security Hub findings',
    awsApis: ['securityhub:GetFindings', 'securityhub:DescribeHub'],
    implemented: true,
    probed: true,
    requiredPermissions: ['securityhub:GetFindings', 'securityhub:DescribeHub', 'securityhub:GetEnabledStandards'],
    dataStored: ['vulnerability_findings'],
    uiConsumer: 'Cloud Security',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'access_analyzer',
    label: 'External exposure (IAM Access Analyzer)',
    awsApis: ['access-analyzer:ListAnalyzers', 'access-analyzer:ListFindings'],
    implemented: true,
    probed: false,
    requiredPermissions: ['access-analyzer:ListAnalyzers', 'access-analyzer:ListFindings', 'access-analyzer:GetFinding'],
    dataStored: ['vulnerability_findings'],
    uiConsumer: 'Cloud Security → Exposed Resources',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'guardduty',
    label: 'GuardDuty threat findings',
    awsApis: ['guardduty:ListDetectors', 'guardduty:ListFindings', 'guardduty:GetFindings'],
    implemented: true,
    probed: false,
    requiredPermissions: ['guardduty:ListDetectors', 'guardduty:ListFindings', 'guardduty:GetFindings'],
    dataStored: ['vulnerability_findings'],
    // V2: GuardDuty is threat detection, outside the V1 posture scope the
    // 2026-09-08 audits set for Cloud Security.
    uiConsumer: 'Not surfaced in V1',
    actionSupported: false,
    lifecycle: 'v2',
  },
  {
    key: 'inspector',
    label: 'Inspector vulnerability findings',
    awsApis: ['inspector2:ListFindings', 'inspector2:BatchGetAccountStatus'],
    implemented: true,
    probed: false,
    requiredPermissions: ['inspector2:ListFindings', 'inspector2:BatchGetAccountStatus'],
    dataStored: ['vulnerability_findings'],
    uiConsumer: 'Not surfaced in V1',
    actionSupported: false,
    lifecycle: 'v2',
  },
  {
    key: 'compute_optimizer',
    label: 'Right-sizing recommendations',
    awsApis: ['compute-optimizer:GetEnrollmentStatus', 'compute-optimizer:GetEC2InstanceRecommendations'],
    implemented: true,
    probed: true,
    requiredPermissions: ['compute-optimizer:GetEnrollmentStatus', 'compute-optimizer:GetEC2InstanceRecommendations', 'compute-optimizer:GetEBSVolumeRecommendations', 'compute-optimizer:GetAutoScalingGroupRecommendations'],
    dataStored: ['cost_recommendations'],
    uiConsumer: 'Cost Optimization',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'trusted_advisor',
    label: 'Trusted Advisor checks',
    awsApis: ['support:DescribeTrustedAdvisorChecks', 'support:DescribeTrustedAdvisorCheckResult'],
    implemented: true,
    probed: true,
    requiredPermissions: ['support:DescribeTrustedAdvisorChecks', 'support:DescribeTrustedAdvisorCheckResult'],
    dataStored: ['cost_recommendations', 'vulnerability_findings'],
    uiConsumer: 'Cost Optimization',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'commitments',
    label: 'Savings Plans & Reserved Instances',
    awsApis: ['savingsplans:DescribeSavingsPlans', 'ce:GetSavingsPlansPurchaseRecommendation', 'ec2:DescribeReservedInstances'],
    implemented: true,
    probed: false,
    requiredPermissions: ['savingsplans:DescribeSavingsPlans', 'ce:GetSavingsPlansPurchaseRecommendation', 'ce:GetSavingsPlansUtilization', 'ec2:DescribeReservedInstances'],
    dataStored: ['cost_recommendations', 'cloud_resources'],
    uiConsumer: 'Cost Optimization → Commitments',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'eks',
    label: 'EKS clusters & workloads',
    awsApis: ['eks:ListClusters', 'eks:DescribeCluster', 'eks:ListNodegroups', 'Kubernetes API'],
    implemented: true,
    probed: true,
    requiredPermissions: ['eks:ListClusters', 'eks:DescribeCluster', 'eks:ListNodegroups', 'eks:DescribeNodegroup'],
    dataStored: ['cloud_resources'],
    uiConsumer: 'Kubernetes & Containers',
    actionSupported: false,
    lifecycle: 'v1',
  },
  {
    key: 'remediation',
    label: 'Provider mutation (resize, stop, tag)',
    awsApis: ['ec2:ModifyInstanceAttribute', 'ec2:StopInstances', 'ec2:StartInstances'],
    // The code exists and is reachable only behind PROVIDER_REMEDIATION_ENABLED,
    // which is OFF in production. Reported as implemented-but-disabled rather
    // than absent, because pretending it is not there would be as dishonest as
    // pretending it is on.
    implemented: true,
    probed: false,
    requiredPermissions: ['ec2:ModifyInstanceAttribute', 'ec2:StopInstances', 'ec2:StartInstances', 'ec2:CreateTags'],
    dataStored: ['remediation_requests', 'automation_executions'],
    uiConsumer: 'Disabled in V1',
    actionSupported: false,
    lifecycle: 'v2',
  },
] as const;

/** Every IAM action the connector can need, de-duplicated — the least-privilege policy's source of truth. */
export function allRequiredPermissions(): string[] {
  return [...new Set(AWS_CAPABILITIES.flatMap((c) => c.requiredPermissions))].sort();
}

/** Capabilities a V1 customer can actually see results from. */
export function v1Capabilities(): AwsCapability[] {
  return AWS_CAPABILITIES.filter((c) => c.lifecycle === 'v1');
}
