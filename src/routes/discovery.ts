import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, inFilter, writeAuditLog, guarded, okJson, errJson, type Db, requirePermittedConnection } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { resolveCredentials, type ResolvableConnection } from './permissions';
import { resolveFindingResourceIds } from '../lib/arnResourceLookup';
import { scanEc2, EC2_RESOURCE_TYPES } from '../lib/scanners/ec2';
import { scanRds, RDS_RESOURCE_TYPES } from '../lib/scanners/rds';
import { scanIam, IAM_RESOURCE_TYPES, extractCloudIdentityRows } from '../lib/scanners/iam';
import { materializeResourceEdges } from '../lib/edgeMaterialization';
import { materializeNetworkTopology } from '../lib/networkTopology';
import { scanSns, SNS_RESOURCE_TYPES } from '../lib/scanners/sns';
import { scanSqs, SQS_RESOURCE_TYPES } from '../lib/scanners/sqs';
import { scanDynamoDb, DYNAMODB_RESOURCE_TYPES } from '../lib/scanners/dynamodb';
import { scanS3, S3_RESOURCE_TYPES } from '../lib/scanners/s3';
import { scanLambda, LAMBDA_RESOURCE_TYPES } from '../lib/scanners/lambda';
import { scanEcs, ECS_RESOURCE_TYPES } from '../lib/scanners/ecs';
import { scanEcr, ECR_RESOURCE_TYPES } from '../lib/scanners/ecr';
import { scanEks, EKS_RESOURCE_TYPES } from '../lib/scanners/eks';
import { scanEksWorkloads, EKS_WORKLOAD_RESOURCE_TYPES } from '../lib/scanners/eksWorkloads';
import { scanElb, ELB_RESOURCE_TYPES } from '../lib/scanners/elb';
import { scanRoute53, ROUTE53_RESOURCE_TYPES } from '../lib/scanners/route53';
import { scanCloudFront, CLOUDFRONT_RESOURCE_TYPES } from '../lib/scanners/cloudfront';
import { scanKms, KMS_RESOURCE_TYPES } from '../lib/scanners/kms';
import { scanSecretsManager, SECRETSMANAGER_RESOURCE_TYPES } from '../lib/scanners/secretsmanager';
import { scanAcm, ACM_RESOURCE_TYPES } from '../lib/scanners/acm';
import { scanWaf, WAF_RESOURCE_TYPES } from '../lib/scanners/waf';
import { scanGuardDuty, GUARDDUTY_RESOURCE_TYPES } from '../lib/scanners/guardduty';
import { scanSecurityHub, SECURITYHUB_RESOURCE_TYPES } from '../lib/scanners/securityhub';
import { scanAutoScaling, AUTOSCALING_RESOURCE_TYPES } from '../lib/scanners/autoscaling';
import { scanElastiCache, ELASTICACHE_RESOURCE_TYPES } from '../lib/scanners/elasticache';
import { scanRedshift, REDSHIFT_RESOURCE_TYPES } from '../lib/scanners/redshift';
import { scanCloudFormation, CLOUDFORMATION_RESOURCE_TYPES, scanCloudFormationDeploymentEvents } from '../lib/scanners/cloudformation';
import { scanEfs, EFS_RESOURCE_TYPES } from '../lib/scanners/efs';
import { scanBackup, BACKUP_RESOURCE_TYPES } from '../lib/scanners/backup';
import { scanCloudWatch, CLOUDWATCH_RESOURCE_TYPES, extractMonitoringAlarmRows } from '../lib/scanners/cloudwatch';
import { scanCloudTrail, CLOUDTRAIL_RESOURCE_TYPES } from '../lib/scanners/cloudtrail';
import { scanSsm, SSM_RESOURCE_TYPES } from '../lib/scanners/ssm';
import { scanEvents, EVENTS_RESOURCE_TYPES } from '../lib/scanners/events';
import { scanStates, STATES_RESOURCE_TYPES } from '../lib/scanners/states';
import { scanKinesis, KINESIS_RESOURCE_TYPES } from '../lib/scanners/kinesis';
import { scanAthena, ATHENA_RESOURCE_TYPES } from '../lib/scanners/athena';
import { scanBatch, BATCH_RESOURCE_TYPES } from '../lib/scanners/batch';
import { scanCodeBuild, CODEBUILD_RESOURCE_TYPES } from '../lib/scanners/codebuild';
import { scanCodePipeline, CODEPIPELINE_RESOURCE_TYPES } from '../lib/scanners/codepipeline';
import { scanCognito, COGNITO_RESOURCE_TYPES } from '../lib/scanners/cognito';
import { scanDocDb, DOCDB_RESOURCE_TYPES } from '../lib/scanners/docdb';
import { scanNeptune, NEPTUNE_RESOURCE_TYPES } from '../lib/scanners/neptune';
import { scanElasticBeanstalk, ELASTICBEANSTALK_RESOURCE_TYPES } from '../lib/scanners/elasticbeanstalk';
import { scanEmr, EMR_RESOURCE_TYPES } from '../lib/scanners/emr';
import { scanGlue, GLUE_RESOURCE_TYPES } from '../lib/scanners/glue';
import { scanKafka, KAFKA_RESOURCE_TYPES } from '../lib/scanners/kafka';
import { scanSageMaker, SAGEMAKER_RESOURCE_TYPES } from '../lib/scanners/sagemaker';
import { scanApiGateway, APIGATEWAY_RESOURCE_TYPES } from '../lib/scanners/apigateway';
import { scanAccessAnalyzer, ACCESSANALYZER_RESOURCE_TYPES } from '../lib/scanners/accessanalyzer';
import { scanConfig, CONFIG_RESOURCE_TYPES } from '../lib/scanners/config';
import { scanFms, FMS_RESOURCE_TYPES } from '../lib/scanners/fms';
import { scanNetworkFirewall, NETWORKFIREWALL_RESOURCE_TYPES } from '../lib/scanners/networkfirewall';
import { scanDirectoryService, DIRECTORYSERVICE_RESOURCE_TYPES } from '../lib/scanners/directoryservice';
import { scanRam, RAM_RESOURCE_TYPES } from '../lib/scanners/ram';
import { scanCloudHsm, CLOUDHSM_RESOURCE_TYPES } from '../lib/scanners/cloudhsm';
import { scanDetective, DETECTIVE_RESOURCE_TYPES } from '../lib/scanners/detective';
import { scanControlTower, CONTROLTOWER_RESOURCE_TYPES } from '../lib/scanners/controltower';
import { scanResilienceHub, RESILIENCEHUB_RESOURCE_TYPES } from '../lib/scanners/resiliencehub';
import { scanResourceGroups, RESOURCEGROUPS_RESOURCE_TYPES } from '../lib/scanners/resourcegroups';
import { scanWellArchitected, WELLARCHITECTED_RESOURCE_TYPES } from '../lib/scanners/wellarchitected';
import { scanComputeOptimizer, COMPUTEOPTIMIZER_RESOURCE_TYPES } from '../lib/scanners/computeoptimizer';
import { scanServiceCatalog, SERVICECATALOG_RESOURCE_TYPES } from '../lib/scanners/servicecatalog';
import { scanTrustedAdvisorResource, TRUSTEDADVISOR_RESOURCE_TYPES } from '../lib/scanners/trustedAdvisorResource';
import { scanShield, SHIELD_RESOURCE_TYPES } from '../lib/scanners/shield';
import { scanOrganizations, ORGANIZATIONS_RESOURCE_TYPES } from '../lib/scanners/organizations';
import { scanHealth, HEALTH_RESOURCE_TYPES } from '../lib/scanners/health';
import { scanDataSync, DATASYNC_RESOURCE_TYPES } from '../lib/scanners/datasync';
import { scanDrs, DRS_RESOURCE_TYPES } from '../lib/scanners/drs';
import { scanFsx, FSX_RESOURCE_TYPES } from '../lib/scanners/fsx';
import { scanGlacier, GLACIER_RESOURCE_TYPES } from '../lib/scanners/glacier';
import { scanS3Control, S3CONTROL_RESOURCE_TYPES } from '../lib/scanners/s3control';
import { scanSnowball, SNOWBALL_RESOURCE_TYPES } from '../lib/scanners/snowball';
import { scanStorageGateway, STORAGEGATEWAY_RESOURCE_TYPES } from '../lib/scanners/storagegateway';
import { scanMemoryDb, MEMORYDB_RESOURCE_TYPES } from '../lib/scanners/memorydb';
import { scanRedshiftServerless, REDSHIFTSERVERLESS_RESOURCE_TYPES } from '../lib/scanners/redshiftserverless';
import { scanTimestream, TIMESTREAM_RESOURCE_TYPES } from '../lib/scanners/timestream';
import { scanAppMesh, APPMESH_RESOURCE_TYPES } from '../lib/scanners/appmesh';
import { scanDirectConnect, DIRECTCONNECT_RESOURCE_TYPES } from '../lib/scanners/directconnect';
import { scanGlobalAccelerator, GLOBALACCELERATOR_RESOURCE_TYPES } from '../lib/scanners/globalaccelerator';
import { scanRoute53Resolver, ROUTE53RESOLVER_RESOURCE_TYPES } from '../lib/scanners/route53resolver';
import { scanServiceDiscovery, SERVICEDISCOVERY_RESOURCE_TYPES } from '../lib/scanners/servicediscovery';
import { scanLightsail, LIGHTSAIL_RESOURCE_TYPES } from '../lib/scanners/lightsail';
import { scanOutposts, OUTPOSTS_RESOURCE_TYPES } from '../lib/scanners/outposts';
import { scanAppRunner, APPRUNNER_RESOURCE_TYPES } from '../lib/scanners/apprunner';
import { scanImageBuilder, IMAGEBUILDER_RESOURCE_TYPES } from '../lib/scanners/imagebuilder';
import { scanWorkspaces, WORKSPACES_RESOURCE_TYPES } from '../lib/scanners/workspaces';
import { scanCodeCommit, CODECOMMIT_RESOURCE_TYPES } from '../lib/scanners/codecommit';
import { scanCodeDeploy, CODEDEPLOY_RESOURCE_TYPES } from '../lib/scanners/codedeploy';
import { scanCodeArtifact, CODEARTIFACT_RESOURCE_TYPES } from '../lib/scanners/codeartifact';
import { scanCostExplorer, CE_RESOURCE_TYPES } from '../lib/scanners/ce';
import { scanBudgets, BUDGETS_RESOURCE_TYPES } from '../lib/scanners/budgets';
import { scanInspector2, INSPECTOR2_RESOURCE_TYPES } from '../lib/scanners/inspector2';
import { scanOpenSearch, ES_RESOURCE_TYPES } from '../lib/scanners/es';
import { scanFirehose, FIREHOSE_RESOURCE_TYPES } from '../lib/scanners/firehose';
import { scanDms, DMS_RESOURCE_TYPES } from '../lib/scanners/dms';
import { scanSes, SES_RESOURCE_TYPES } from '../lib/scanners/ses';
import { scanLakeFormation, LAKEFORMATION_RESOURCE_TYPES } from '../lib/scanners/lakeformation';
import { scanLicenseManager, LICENSEMANAGER_RESOURCE_TYPES } from '../lib/scanners/licensemanager';
import { scanMq, MQ_RESOURCE_TYPES } from '../lib/scanners/mq';
import { scanSavingsPlans, SAVINGSPLANS_RESOURCE_TYPES } from '../lib/scanners/savingsplans';
import { scanAcmPca, ACMPCA_RESOURCE_TYPES } from '../lib/scanners/acmpca';
import { scanAppSync, APPSYNC_RESOURCE_TYPES } from '../lib/scanners/appsync';
import { scanMacie, MACIE_RESOURCE_TYPES } from '../lib/scanners/macie';
import { scanGuardDutyFindings } from '../lib/scanners/guarddutyFindings';
import { scanSecurityHubFindings } from '../lib/scanners/securityhubFindings';
import { scanAccessAnalyzerFindings } from '../lib/scanners/accessAnalyzerFindings';
import { scanInspectorFindings } from '../lib/scanners/inspectorFindings';
import { scanAwsConfigFindings } from '../lib/scanners/awsConfigFindings';
import { scanTrustedAdvisorFindings } from '../lib/scanners/trustedAdvisorFindings';
import { scanEc2CpuMetrics } from '../lib/scanners/ec2Metrics';
import type { ScannedResource, ScannerFn } from '../lib/scanners/types';
import type { AwsCallFailure, AwsCallRecord } from '../lib/awsApi';
import { admitObservations } from '../lib/admission';
import { NORMALIZATION_VERSION, SOURCE_SCHEMA_VERSION } from '../lib/lineage';
import { closeBatch, openBatch, recordObservations, recordProviderRequests, recordQuarantine } from '../lib/ingestion';

/**
 * Cap on provider-request rows kept per ingestion batch.
 *
 * A scanner fanning out over hundreds of resources can make hundreds of
 * calls, and a step's lineage should not become the largest thing in the
 * database. When the cap bites it is RECORDED on the batch, not applied
 * silently -- truncated evidence that claims to be complete is the exact
 * failure this phase exists to remove.
 */
const MAX_PROVIDER_REQUESTS_PER_BATCH = 200;
import type { ScannedFinding, FindingScannerFn } from '../lib/scanners/findingTypes';
import type { ScannedMetric } from '../lib/scanners/metricTypes';
import { computeFinalizeResult } from '../lib/discoveryFinalize';
import { resolveGeneration, type ExistingGeneration, type LifecycleState } from '../lib/generations';
import { triggerRecommendationGeneration, triggerAlertEvaluation } from '../lib/postScanHooks';
import { RegionCoverageLedger } from '../lib/regionalAvailability';

export const discoveryRoutes = new Hono<{ Bindings: Env }>();

/**
 * Real resource discovery, restored from the pre-teardown cloud-api (git
 * tag pre-teardown-2026-07-28) — nothing in the current 15-service rebuild
 * wrote to cloud_resources before this. Now covers every resource type
 * currently marked scanner_status='live' in resource_type_catalog: EC2,
 * RDS, IAM, SNS, SQS, DynamoDB, S3, Lambda, ECS, ECR, EKS, ELB (classic +
 * ALB/NLB), Route53, CloudFront, KMS, Secrets Manager, ACM, WAF,
 * GuardDuty, SecurityHub, Auto Scaling, ElastiCache, Redshift,
 * CloudFormation, EFS, Backup, CloudWatch (alarms + log groups),
 * CloudTrail, SSM, EventBridge, and Step Functions. Everything else in the
 * catalog is 'planned' — a real, tracked gap for the remaining resource
 * types AWS has that this taxonomy knows about but no scanner covers yet,
 * not silently dropped — add to REGIONAL_SCANNERS/GLOBAL_SCANNERS below as
 * each is ported.
 *
 * Also runs real security-finding ingestion (GuardDuty, Security Hub, IAM
 * Access Analyzer external-access findings) into vulnerability_findings —
 * see FINDING_SCANNERS below. This is what closes the loop the
 * guardduty.ts/securityhub.ts resource scanners above deliberately left
 * open: those only ever checked whether GuardDuty/Security Hub are
 * *enabled* (a detector/hub as a cloud_resource), never the actual findings
 * inside them, since a finding isn't a resource and vulnerability_findings
 * was sitting unpopulated waiting for exactly this.
 *

 * Same stepped-request design as before: Cloudflare's free plan caps one
 * Worker invocation at ~10ms CPU / ~50 subrequests, and one region's worth
 * of scanning blows through both in a single request with no catchable
 * error (the platform just kills the invocation). So each step here is one
 * scanner × one region, small enough to always fit, driven by a loop in
 * the frontend rather than one big server-side loop.
 *
 * Split into regional vs. global scanners: a regional scanner (ec2, rds)
 * gets one step per scan region, since the data genuinely differs per
 * region. A global scanner (iam) has one account-wide answer regardless of
 * region, so it gets exactly one step total — running it once per scan
 * region would just repeat the same AWS calls up to 17x for nothing.
 */
export const REGIONAL_SCANNERS: Record<string, ScannerFn> = {
  ec2: scanEc2,
  rds: scanRds,
  sns: scanSns,
  sqs: scanSqs,
  dynamodb: scanDynamoDb,
  lambda: scanLambda,
  ecs: scanEcs,
  ecr: scanEcr,
  eks: scanEks,
  eksworkloads: scanEksWorkloads,
  elb: scanElb,
  kms: scanKms,
  secretsmanager: scanSecretsManager,
  acm: scanAcm,
  waf: scanWaf,
  guardduty: scanGuardDuty,
  securityhub: scanSecurityHub,
  autoscaling: scanAutoScaling,
  elasticache: scanElastiCache,
  redshift: scanRedshift,
  cloudformation: scanCloudFormation,
  efs: scanEfs,
  backup: scanBackup,
  cloudwatch: scanCloudWatch,
  cloudtrail: scanCloudTrail,
  ssm: scanSsm,
  events: scanEvents,
  states: scanStates,
  kinesis: scanKinesis,
  athena: scanAthena,
  batch: scanBatch,
  codebuild: scanCodeBuild,
  codepipeline: scanCodePipeline,
  cognito: scanCognito,
  docdb: scanDocDb,
  neptune: scanNeptune,
  elasticbeanstalk: scanElasticBeanstalk,
  emr: scanEmr,
  glue: scanGlue,
  kafka: scanKafka,
  sagemaker: scanSageMaker,
  apigateway: scanApiGateway,
  accessanalyzer: scanAccessAnalyzer,
  config: scanConfig,
  fms: scanFms,
  networkfirewall: scanNetworkFirewall,
  ds: scanDirectoryService,
  ram: scanRam,
  cloudhsm: scanCloudHsm,
  detective: scanDetective,
  controltower: scanControlTower,
  resiliencehub: scanResilienceHub,
  resourcegroups: scanResourceGroups,
  wellarchitected: scanWellArchitected,
  computeoptimizer: scanComputeOptimizer,
  servicecatalog: scanServiceCatalog,
  datasync: scanDataSync,
  drs: scanDrs,
  fsx: scanFsx,
  glacier: scanGlacier,
  snowball: scanSnowball,
  storagegateway: scanStorageGateway,
  memorydb: scanMemoryDb,
  redshiftserverless: scanRedshiftServerless,
  timestream: scanTimestream,
  appmesh: scanAppMesh,
  directconnect: scanDirectConnect,
  route53resolver: scanRoute53Resolver,
  servicediscovery: scanServiceDiscovery,
  lightsail: scanLightsail,
  outposts: scanOutposts,
  apprunner: scanAppRunner,
  imagebuilder: scanImageBuilder,
  workspaces: scanWorkspaces,
  codecommit: scanCodeCommit,
  codedeploy: scanCodeDeploy,
  codeartifact: scanCodeArtifact,
  // Enabled per region like guardduty/securityhub above -- see
  // inspector2.ts's own doc comment for the account-status resource this
  // adds (distinct from inspectorFindings.ts's existing findings scan).
  inspector2: scanInspector2,
  // All regional -- see each scanner file's own doc comment for its
  // researched API shape and confidence level.
  es: scanOpenSearch,
  firehose: scanFirehose,
  dms: scanDms,
  ses: scanSes,
  lakeformation: scanLakeFormation,
  licensemanager: scanLicenseManager,
  mq: scanMq,
  acmpca: scanAcmPca,
  appsync: scanAppSync,
  macie: scanMacie,
};
export const GLOBAL_SCANNERS: Record<string, ScannerFn> = {
  iam: scanIam,
  s3: scanS3,
  route53: scanRoute53,
  cloudfront: scanCloudFront,
  trustedadvisorresource: scanTrustedAdvisorResource,
  shield: scanShield,
  organizations: scanOrganizations,
  health: scanHealth,
  s3control: scanS3Control,
  globalaccelerator: scanGlobalAccelerator,
  // Both account-wide, us-east-1-only services (billing has no regional
  // concept) -- see ce.ts/budgets.ts's own doc comments.
  ce: scanCostExplorer,
  budgets: scanBudgets,
  // Bare hostname, no region suffix, ctx.region ignored -- same billing-
  // wide nature as ce/budgets above, confirmed against AWS's own endpoint
  // reference (see savingsplans.ts's doc comment).
  savingsplans: scanSavingsPlans,
};

/**
 * Findings are a distinct kind of step from REGIONAL_SCANNERS/GLOBAL_SCANNERS
 * above — they write to vulnerability_findings, not cloud_resources, using
 * ScannedFinding's shape, not ScannedResource's (see findingTypes.ts). All
 * three sources here are regional (GuardDuty detectors, Security Hub hubs,
 * and IAM Access Analyzer analyzers are each per-region), so this gets a
 * `finding:` step per scan region, same fan-out as REGIONAL_SCANNERS.
 * vulnerability_findings.finding_source's check constraint already allows
 * ('internal','security_hub','guardduty','inspector','iam_access_analyzer',
 * 'aws_config','trusted_advisor') — all seven are now covered (inspector/
 * aws_config/trusted_advisor added after guardduty/securityhub/
 * accessanalyzer; see each scanner file's own "UNVERIFIED" doc comment,
 * since these three haven't been exercised against a real account with the
 * relevant service/support-plan enabled the way the first three were).
 *
 * trustedadvisor is a real inefficiency here, not just a naming quirk: the
 * Support API only exists in us-east-1 (trustedAdvisorFindings.ts hardcodes
 * it, ignoring ctx.region), but this map fans every scanner out per scan
 * region same as the other two — so a connection scanning 5 regions calls
 * Trusted Advisor 5 times against the same us-east-1 endpoint. Harmless
 * (findings upsert idempotently on their own id) but wasteful; giving
 * FINDING_SCANNERS a per-scanner "regional vs global" flag like
 * REGIONAL_SCANNERS/GLOBAL_SCANNERS already have would fix this properly,
 * not done here to keep this change scoped to adding the three scanners.
 */
export const FINDING_SCANNERS: Record<string, FindingScannerFn> = {
  guardduty: scanGuardDutyFindings,
  securityhub: scanSecurityHubFindings,
  accessanalyzer: scanAccessAnalyzerFindings,
  inspector: scanInspectorFindings,
  awsconfig: scanAwsConfigFindings,
  trustedadvisor: scanTrustedAdvisorFindings,
};

/**
 * Which `vulnerability_findings.finding_source` values each finding scanner
 * can produce — the findings counterpart of SCANNER_RESOURCE_TYPES, and for
 * the same reason.
 *
 * finalize marks an open finding RESOLVED when this run did not see it again.
 * That is only true if the scanner that produces it actually ran and
 * succeeded; otherwise "we could not read GuardDuty" is written to the
 * database as "GuardDuty reports you are clean". Before this map the source
 * list was a hardcoded literal inside finalize, applied unconditionally, so a
 * denied, throttled or simply not-yet-executed finding scanner silently
 * closed every one of its open findings.
 *
 * `iam_access_analyzer_unused` is listed here and was NOT in that literal --
 * the drift a hardcoded list produces. Its findings could never be resolved at
 * all, which is the opposite error: a fixed problem staying open forever.
 */
export const FINDING_SCANNER_SOURCES: Record<string, readonly string[]> = {
  guardduty: ['guardduty'],
  securityhub: ['security_hub'],
  accessanalyzer: ['iam_access_analyzer', 'iam_access_analyzer_unused'],
  inspector: ['inspector'],
  awsconfig: ['aws_config'],
  trustedadvisor: ['trusted_advisor'],
};

/**
 * Metric steps are a fourth kind, alongside REGIONAL/GLOBAL_SCANNERS and
 * FINDING_SCANNERS — they write to resource_metrics (a time-series table),
 * and unlike every other scanner they need to know which resources this
 * connection *already discovered* before they can call AWS at all (a metric
 * is measured "for instance i-0abc", not discovered fresh). Only one exists
 * so far (EC2 CPU utilization, `metric:ec2cpu:<region>`) — not generalized
 * into a map the way FINDING_SCANNERS is, since a second metric scanner
 * might need a genuinely different "which resources need this" query, not
 * just a different AWS call. See runMetricStep below.
 */
export const METRIC_STEP_NAME = 'ec2cpu';
const EC2_METRICS_INSTANCE_CAP = 30;

/**
 * Every resource_type_key at least one currently-implemented scanner
 * covers, aggregated across SCANNERS — this is what "vanished resource"
 * cleanup in /finalize is scoped to. Resource types this rebuild doesn't
 * scan yet (kms_alias, iam_role, s3_bucket, cloudformation_stack, ...,
 * carried over from before the 2026-07-28 teardown) are left completely
 * alone: a run that never checked them can't honestly claim to know
 * whether they still exist, so it must never mark them deleted.
 */
export const SCANNER_RESOURCE_TYPES: Record<string, readonly string[]> = {
  ec2: EC2_RESOURCE_TYPES,
  rds: RDS_RESOURCE_TYPES,
  iam: IAM_RESOURCE_TYPES,
  sns: SNS_RESOURCE_TYPES,
  sqs: SQS_RESOURCE_TYPES,
  dynamodb: DYNAMODB_RESOURCE_TYPES,
  lambda: LAMBDA_RESOURCE_TYPES,
  s3: S3_RESOURCE_TYPES,
  ecs: ECS_RESOURCE_TYPES,
  ecr: ECR_RESOURCE_TYPES,
  eks: EKS_RESOURCE_TYPES,
  eksworkloads: EKS_WORKLOAD_RESOURCE_TYPES,
  elb: ELB_RESOURCE_TYPES,
  route53: ROUTE53_RESOURCE_TYPES,
  cloudfront: CLOUDFRONT_RESOURCE_TYPES,
  kms: KMS_RESOURCE_TYPES,
  secretsmanager: SECRETSMANAGER_RESOURCE_TYPES,
  acm: ACM_RESOURCE_TYPES,
  waf: WAF_RESOURCE_TYPES,
  guardduty: GUARDDUTY_RESOURCE_TYPES,
  securityhub: SECURITYHUB_RESOURCE_TYPES,
  autoscaling: AUTOSCALING_RESOURCE_TYPES,
  elasticache: ELASTICACHE_RESOURCE_TYPES,
  redshift: REDSHIFT_RESOURCE_TYPES,
  cloudformation: CLOUDFORMATION_RESOURCE_TYPES,
  efs: EFS_RESOURCE_TYPES,
  backup: BACKUP_RESOURCE_TYPES,
  cloudwatch: CLOUDWATCH_RESOURCE_TYPES,
  cloudtrail: CLOUDTRAIL_RESOURCE_TYPES,
  ssm: SSM_RESOURCE_TYPES,
  events: EVENTS_RESOURCE_TYPES,
  states: STATES_RESOURCE_TYPES,
  kinesis: KINESIS_RESOURCE_TYPES,
  athena: ATHENA_RESOURCE_TYPES,
  batch: BATCH_RESOURCE_TYPES,
  codebuild: CODEBUILD_RESOURCE_TYPES,
  codepipeline: CODEPIPELINE_RESOURCE_TYPES,
  cognito: COGNITO_RESOURCE_TYPES,
  docdb: DOCDB_RESOURCE_TYPES,
  neptune: NEPTUNE_RESOURCE_TYPES,
  elasticbeanstalk: ELASTICBEANSTALK_RESOURCE_TYPES,
  emr: EMR_RESOURCE_TYPES,
  glue: GLUE_RESOURCE_TYPES,
  kafka: KAFKA_RESOURCE_TYPES,
  sagemaker: SAGEMAKER_RESOURCE_TYPES,
  apigateway: APIGATEWAY_RESOURCE_TYPES,
  accessanalyzer: ACCESSANALYZER_RESOURCE_TYPES,
  config: CONFIG_RESOURCE_TYPES,
  fms: FMS_RESOURCE_TYPES,
  networkfirewall: NETWORKFIREWALL_RESOURCE_TYPES,
  ds: DIRECTORYSERVICE_RESOURCE_TYPES,
  ram: RAM_RESOURCE_TYPES,
  cloudhsm: CLOUDHSM_RESOURCE_TYPES,
  detective: DETECTIVE_RESOURCE_TYPES,
  controltower: CONTROLTOWER_RESOURCE_TYPES,
  resiliencehub: RESILIENCEHUB_RESOURCE_TYPES,
  resourcegroups: RESOURCEGROUPS_RESOURCE_TYPES,
  wellarchitected: WELLARCHITECTED_RESOURCE_TYPES,
  computeoptimizer: COMPUTEOPTIMIZER_RESOURCE_TYPES,
  servicecatalog: SERVICECATALOG_RESOURCE_TYPES,
  trustedadvisorresource: TRUSTEDADVISOR_RESOURCE_TYPES,
  shield: SHIELD_RESOURCE_TYPES,
  organizations: ORGANIZATIONS_RESOURCE_TYPES,
  health: HEALTH_RESOURCE_TYPES,
  datasync: DATASYNC_RESOURCE_TYPES,
  drs: DRS_RESOURCE_TYPES,
  fsx: FSX_RESOURCE_TYPES,
  glacier: GLACIER_RESOURCE_TYPES,
  s3control: S3CONTROL_RESOURCE_TYPES,
  snowball: SNOWBALL_RESOURCE_TYPES,
  storagegateway: STORAGEGATEWAY_RESOURCE_TYPES,
  memorydb: MEMORYDB_RESOURCE_TYPES,
  redshiftserverless: REDSHIFTSERVERLESS_RESOURCE_TYPES,
  timestream: TIMESTREAM_RESOURCE_TYPES,
  appmesh: APPMESH_RESOURCE_TYPES,
  directconnect: DIRECTCONNECT_RESOURCE_TYPES,
  globalaccelerator: GLOBALACCELERATOR_RESOURCE_TYPES,
  route53resolver: ROUTE53RESOLVER_RESOURCE_TYPES,
  servicediscovery: SERVICEDISCOVERY_RESOURCE_TYPES,
  lightsail: LIGHTSAIL_RESOURCE_TYPES,
  outposts: OUTPOSTS_RESOURCE_TYPES,
  apprunner: APPRUNNER_RESOURCE_TYPES,
  imagebuilder: IMAGEBUILDER_RESOURCE_TYPES,
  workspaces: WORKSPACES_RESOURCE_TYPES,
  codecommit: CODECOMMIT_RESOURCE_TYPES,
  codedeploy: CODEDEPLOY_RESOURCE_TYPES,
  codeartifact: CODEARTIFACT_RESOURCE_TYPES,
  ce: CE_RESOURCE_TYPES,
  budgets: BUDGETS_RESOURCE_TYPES,
  inspector2: INSPECTOR2_RESOURCE_TYPES,
  es: ES_RESOURCE_TYPES,
  firehose: FIREHOSE_RESOURCE_TYPES,
  dms: DMS_RESOURCE_TYPES,
  ses: SES_RESOURCE_TYPES,
  lakeformation: LAKEFORMATION_RESOURCE_TYPES,
  licensemanager: LICENSEMANAGER_RESOURCE_TYPES,
  mq: MQ_RESOURCE_TYPES,
  savingsplans: SAVINGSPLANS_RESOURCE_TYPES,
  acmpca: ACMPCA_RESOURCE_TYPES,
  appsync: APPSYNC_RESOURCE_TYPES,
  macie: MACIE_RESOURCE_TYPES,
};
const COVERED_RESOURCE_TYPES = Object.values(SCANNER_RESOURCE_TYPES).flat();

export interface ConnectionForDiscovery extends ResolvableConnection {
  aws_account_id: string;
  scan_regions: string[] | null;
}

export async function loadConnection(db: Db, orgId: string, userId: string | null, id: string): Promise<ConnectionForDiscovery | null> {
  // Compile-enforced authorization: `userId` is required so every call site
  // has to decide. An id + org_id filter proves only that the connection
  // belongs to the caller's org, never that this caller is permitted it.
  // Pass null ONLY from internal/scheduled paths that run without a user.
  if (userId) await requirePermittedConnection(db, orgId, userId, id);
  const rows = await db.select<ConnectionForDiscovery[]>('cloud_connections', {
    select: 'id,aws_account_id,connection_method,credentials_encrypted,role_arn,external_id,default_region,scan_regions',
    filters: { id: `eq.${id}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
  });
  return rows[0] ?? null;
}

export function regionsFor(connection: ConnectionForDiscovery): string[] {
  return connection.scan_regions?.length ? connection.scan_regions : [connection.default_region];
}

/**
 * GET /accounts/:id/discovery/steps was REMOVED (Phase B cleanup, 2026-09-10).
 *
 * It served the browser's step-loop, which Phase 1 removed and Phase 3
 * replaced with durable, server-owned collection runs. `planSteps` in
 * routes/collectionRuns.ts now builds the same plan server-side, so this was
 * a second, unauthenticated-by-the-worker way to enumerate a scan.
 *
 * It also stamped `scan_started_at` as a side effect of a GET. Nothing else
 * writes that column, so the abandoned-scan branch in internalStep.ts that
 * reads it has been inert since the browser stopped calling this -- see the
 * note there, which is now corrected rather than left implying a check that
 * cannot fire.
 */

export interface StepResult {
  stepId: string;
  resourceCount: number;
  created: number;
  error?: string;
  /** 'info' = the account/region just doesn't have this service turned on — not a real failure. */
  errorSeverity?: 'error' | 'info';
  /**
   * Resource types whose coverage this step could not complete (an AWS call
   * failed and the scanner continued with partial data). The caller passes
   * these to finalize, which excludes them from vanished-resource deletion --
   * otherwise a throttled Describe* reads as "everything was deleted".
   */
  degradedResourceTypes?: string[];
  /** Why each degraded type degraded, keyed by resource type. */
  degradedReasons?: Record<string, string>;
}

const EXPECTED_ACCOUNT_STATE_PATTERNS = [/needs a subscription for the service/i, /is not subscribed to/i, /opt.?in/i, /not.{0,20}(enabled|activated)/i];
function classifyError(message: string): 'error' | 'info' {
  return EXPECTED_ACCOUNT_STATE_PATTERNS.some((p) => p.test(message)) ? 'info' : 'error';
}

interface CatalogRow { key: string; category: string; service: string }

/**
 * Handles `finding:` steps — a parallel path to the resource-scanning logic
 * below, since findings target vulnerability_findings with a different
 * upsert key and (crucially) must never overwrite a finding's `status`:
 * that column is omitted from the upsert payload entirely, so a brand new
 * finding gets the table's own DEFAULT 'open' on INSERT, while a finding a
 * user already resolved/suppressed via PATCH /findings/:id keeps that
 * status untouched on every later re-scan that still finds it active in
 * AWS (PostgREST's `resolution=merge-duplicates` only touches columns
 * actually present in the payload).
 */
export async function runFindingStep(db: Db, orgId: string, userId: string | null, env: Env, connectionId: string, stepId: string,
  /**
   * The durable run this step belongs to. Optional so the signature stays
   * compatible, but the durable worker always supplies it -- without it
   * `ingestion_batches.collection_run_id` is NULL and a stored resource
   * cannot be traced back to the run that collected it.
   */
  collectionRunId: string | null = null): Promise<StepResult> {
  const rest = stepId.slice('finding:'.length);
  const sep = rest.indexOf(':');
  if (sep === -1) return { stepId, resourceCount: 0, created: 0, error: `Malformed stepId "${stepId}"`, errorSeverity: 'error' };
  const scannerName = rest.slice(0, sep);
  const region = rest.slice(sep + 1);
  const scanner = FINDING_SCANNERS[scannerName];
  if (!scanner) return { stepId, resourceCount: 0, created: 0, error: `Unknown finding scanner "${scannerName}"`, errorSeverity: 'error' };

  const connection = await loadConnection(db, orgId, userId, connectionId);
  if (!connection) return { stepId, resourceCount: 0, created: 0, error: 'Account not found', errorSeverity: 'error' };

  const resolved = await resolveCredentials(env, connection);
  if ('error' in resolved) return { stepId, resourceCount: 0, created: 0, error: resolved.error, errorSeverity: 'error' };

  /**
   * Finding scanners had NO failure sink at all: they were called with bare
   * credentials, so a denied, throttled or unreachable call returned an empty
   * list and left no trace anywhere. finalize then resolved every open finding
   * from that source, because it could not tell "AWS says this is fixed" from
   * "we never got to ask".
   *
   * Recorded on the STEP ROW rather than in memory, because the step and the
   * finalize that consumes it routinely happen in different worker ticks. The
   * severity is deliberately 'info', not 'error': nothing fatal happened, the
   * run should still report SUCCEEDED, and a service the account has not
   * enabled must not look like a broken connection. What it must do is stop
   * the step counting as proof of absence -- which is exactly what a
   * non-'succeeded' status does in collectionRuns.ts.
   */
  const callFailures: AwsCallFailure[] = [];
  const onCallFailure = (f: AwsCallFailure) => { callFailures.push(f); };

  let scanned: ScannedFinding[];
  try {
    scanned = await scanner({ creds: { ...resolved.creds, onCallFailure }, region });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Scan failed';
    return { stepId, resourceCount: 0, created: 0, error: message, errorSeverity: classifyError(message) };
  }

  const coverage = new RegionCoverageLedger();
  const sources = FINDING_SCANNER_SOURCES[scannerName] ?? [scannerName];
  for (const f of callFailures) coverage.record(f, sources);
  const degradedMap = coverage.degradedTypes();
  // A service AWS does not offer in this region is not a coverage gap -- the
  // ledger already makes that distinction, and treating it as one would keep
  // every finding in a single-region account open forever.
  const incomplete = degradedMap.size > 0
    ? { error: [...degradedMap.values()][0], errorSeverity: 'info' as const }
    : {};

  if (scanned.length === 0) return { stepId, resourceCount: 0, created: 0, ...incomplete };

  const existing = await db.select<{ finding_source: string; aws_finding_id: string }[]>('vulnerability_findings', {
    select: 'finding_source,aws_finding_id',
    filters: { connection_id: `eq.${connection.id}`, finding_source: `eq.${scanned[0].findingSource}` },
  });
  const existingKeys = new Set(existing.map((r) => `${r.finding_source}:${r.aws_finding_id}`));

  // Best-effort resolve each finding's resourceArn back to a real
  // cloud_resources row for this connection — see arnResourceLookup.ts for
  // why this can't be a simple 1:1 parse. A finding whose resourceArn
  // doesn't resolve just gets resource_id: null, same as before this ran.
  const resourceIdByArn = await resolveFindingResourceIds(db, connection.id, scanned.map((f) => f.resourceArn));

  const now = new Date().toISOString();
  let created = 0;
  const rows = scanned.map((f) => {
    if (!existingKeys.has(`${f.findingSource}:${f.awsFindingId}`)) created++;
    return {
      connection_id: connection.id, resource_id: (f.resourceArn && resourceIdByArn.get(f.resourceArn)) ?? null,
      finding_source: f.findingSource, aws_finding_id: f.awsFindingId,
      severity: f.severity, cvss_score: f.cvssScore ?? null, cve: f.cve ?? null, title: f.title, description: f.description ?? null,
      compliance_frameworks: f.complianceFrameworks ?? [], remediation_link: f.remediationLink ?? null,
      discovered_at: f.discoveredAt, region: f.region, resource_arn: f.resourceArn ?? null, last_seen_at: now,
    };
  });

  await db.insert('vulnerability_findings?on_conflict=connection_id,finding_source,aws_finding_id', rows, 'resolution=merge-duplicates,return=minimal');

  // Same reasoning as the empty path above, and the more dangerous case: a
  // step that wrote SOME findings and failed other calls looks complete.
  return { stepId, resourceCount: rows.length, created, ...incomplete };
}

/**
 * Handles `metric:` steps. Unlike finding/resource scanners, this needs a
 * DB read *before* it can call AWS at all — CloudWatch metrics are keyed by
 * an existing AWS instance id, not discovered fresh — so it queries this
 * connection's already-discovered running EC2 instances in the step's
 * region first (capped at EC2_METRICS_INSTANCE_CAP, same subrequest-budget
 * reasoning as every other high-cardinality scanner), then calls
 * scanEc2CpuMetrics for just that batch. Stopped/terminated instances are
 * skipped — CloudWatch has nothing meaningful to report for CPU on an
 * instance that isn't running, so pulling their metrics would just waste
 * subrequests on empty responses.
 */
export async function runMetricStep(db: Db, orgId: string, userId: string | null, env: Env, connectionId: string, stepId: string,
  /**
   * The durable run this step belongs to. Optional so the signature stays
   * compatible, but the durable worker always supplies it -- without it
   * `ingestion_batches.collection_run_id` is NULL and a stored resource
   * cannot be traced back to the run that collected it.
   */
  collectionRunId: string | null = null): Promise<StepResult> {
  const rest = stepId.slice('metric:'.length);
  const sep = rest.indexOf(':');
  if (sep === -1) return { stepId, resourceCount: 0, created: 0, error: `Malformed stepId "${stepId}"`, errorSeverity: 'error' };
  const metricName = rest.slice(0, sep);
  const region = rest.slice(sep + 1);
  if (metricName !== METRIC_STEP_NAME) return { stepId, resourceCount: 0, created: 0, error: `Unknown metric step "${metricName}"`, errorSeverity: 'error' };

  const connection = await loadConnection(db, orgId, userId, connectionId);
  if (!connection) return { stepId, resourceCount: 0, created: 0, error: 'Account not found', errorSeverity: 'error' };

  const resolved = await resolveCredentials(env, connection);
  if ('error' in resolved) return { stepId, resourceCount: 0, created: 0, error: resolved.error, errorSeverity: 'error' };

  const instanceRows = await db.select<{ id: string; resource_id: string }[]>('cloud_resources', {
    select: 'id,resource_id',
    filters: { connection_id: `eq.${connection.id}`, resource_type_key: 'eq.ec2_instance', region: `eq.${region}`, state: 'eq.running', deleted_at: 'is.null' },
    limit: EC2_METRICS_INSTANCE_CAP,
  });
  if (instanceRows.length === 0) return { stepId, resourceCount: 0, created: 0 };

  let scanned: ScannedMetric[];
  try {
    scanned = await scanEc2CpuMetrics(resolved.creds, region, instanceRows.map((r) => ({ dbId: r.id, awsInstanceId: r.resource_id })));
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Scan failed';
    return { stepId, resourceCount: 0, created: 0, error: message, errorSeverity: classifyError(message) };
  }
  if (scanned.length === 0) return { stepId, resourceCount: 0, created: 0 };

  const rows = scanned.map((m) => ({
    connection_id: connection.id, resource_id: m.resourceDbId, resource_type_key: m.resourceTypeKey,
    metric_name: m.metricName, namespace: m.namespace, unit: m.unit ?? null, region: m.region, ts: m.ts, value: m.value,
  }));
  await db.insert('resource_metrics?on_conflict=resource_id,metric_name,ts', rows, 'resolution=merge-duplicates,return=minimal');

  return { stepId, resourceCount: rows.length, created: rows.length };
}

/**
 * Handles `regional:`/`global:` resource-scanning steps — extracted from
 * the POST /run-step handler below (pure extraction, no behavior change) so
 * routes/internalScan.ts's scheduled-scan path can drive the exact same
 * upsert logic server-side instead of duplicating it.
 */
export async function runResourceStep(db: Db, orgId: string, userId: string | null, env: Env, connectionId: string, stepId: string,
  /**
   * The durable run this step belongs to. Optional so the signature stays
   * compatible, but the durable worker always supplies it -- without it
   * `ingestion_batches.collection_run_id` is NULL and a stored resource
   * cannot be traced back to the run that collected it.
   */
  collectionRunId: string | null = null): Promise<StepResult> {
  let scanner: ScannerFn | undefined;
  let region: string;
  let scannerName: string;
  if (stepId.startsWith('regional:')) {
    const rest = stepId.slice('regional:'.length);
    const sep = rest.indexOf(':');
    if (sep === -1) return { stepId, resourceCount: 0, created: 0, error: `Malformed stepId "${stepId}"`, errorSeverity: 'error' };
    scannerName = rest.slice(0, sep);
    region = rest.slice(sep + 1);
    scanner = REGIONAL_SCANNERS[scannerName];
  } else if (stepId.startsWith('global:')) {
    scannerName = stepId.slice('global:'.length);
    region = 'global';
    scanner = GLOBAL_SCANNERS[scannerName];
  } else {
    return { stepId, resourceCount: 0, created: 0, error: `Malformed stepId "${stepId}"`, errorSeverity: 'error' };
  }
  if (!scanner) return { stepId, resourceCount: 0, created: 0, error: `Unknown scanner in stepId "${stepId}"`, errorSeverity: 'error' };

  const connection = await loadConnection(db, orgId, userId, connectionId);
  if (!connection) return { stepId, resourceCount: 0, created: 0, error: 'Account not found', errorSeverity: 'error' };

  const resolved = await resolveCredentials(env, connection);
  if ('error' in resolved) return { stepId, resourceCount: 0, created: 0, error: resolved.error, errorSeverity: 'error' };

  /**
   * Collects sub-call failures the scanner absorbed while continuing with
   * partial data. Without this they were invisible: the step reported success
   * and finalize deleted everything the failed call would have returned.
   *
   * The sink hangs off the CREDENTIALS rather than being reported by each
   * scanner, because creds are the one object all 111 scanners already thread
   * into every AWS call regardless of which helper they use. Any failed call
   * therefore degrades this scanner's resource types automatically -- and a
   * scanner written next month is covered without anyone remembering to wire
   * it.
   *
   * The affected types come from SCANNER_RESOURCE_TYPES, the same map that
   * builds COVERED_RESOURCE_TYPES, so a failure protects exactly what this
   * scanner would have been trusted to delete and nothing else.
   */
  /*
   * AWS-P3. This used to mark every type a scanner owns as degraded on ANY
   * terminal call failure -- including a service that simply has no endpoint
   * in the region being scanned. Discovery fans out over 17 regions and most
   * AWS services are not offered in all of them, so 41 resource types were
   * degraded on every single run, inventory was never authoritative, and those
   * types could never be reconciled for deletion.
   *
   * The ledger classifies each failure instead: absence of an endpoint is a
   * coverage FACT (there is nothing there to read), while a denial, a throttle
   * or a real error is a coverage GAP. Only gaps degrade.
   * See lib/regionalAvailability.ts.
   */
  const coverage = new RegionCoverageLedger();
  const ownedTypes: readonly string[] = SCANNER_RESOURCE_TYPES[scannerName] ?? [];
  const onCallFailure = (f: AwsCallFailure) => {
    coverage.record(f, ownedTypes);
    console.warn(`[degraded] ${f.service}:${f.action} ${f.region} -> ${f.normalizedCode} after ${f.attempts} attempt(s); ${ownedTypes.length} resource type(s) protected from deletion this run`);
  };

  /**
   * Phase 2: every AWS call this step makes, for provider-request lineage.
   *
   * Capped because a scanner fanning out over hundreds of resources can make
   * hundreds of calls, and a step's lineage should not become the largest
   * thing in the database. The cap is recorded on the batch rather than
   * silently applied -- a truncated record that claims to be complete is the
   * failure mode this phase exists to remove.
   */
  const calls: AwsCallRecord[] = [];
  let callsDropped = 0;
  const onCall = (c: AwsCallRecord) => {
    if (calls.length < MAX_PROVIDER_REQUESTS_PER_BATCH) calls.push(c);
    else callsDropped += 1;
  };

  /**
   * The batch is opened BEFORE the scanner runs, so a crash mid-step leaves a
   * visible RUNNING batch rather than no evidence that ingestion was ever
   * attempted. "No batch" and "a batch that failed" must not look the same.
   */
  const batch = await openBatch(db, {
    orgId,
    connectionId: connection.id,
    accountNativeId: connection.aws_account_id ?? null,
    collectionRunId,
    collectionStepId: stepId,
  });

  let scanned: ScannedResource[];
  try {
    scanned = await scanner({ creds: { ...resolved.creds, onCallFailure, onCall }, region });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Scan failed';
    await recordProviderRequests(db, batch, calls).catch(() => {});
    await closeBatch(db, batch.id, {
      observed: 0, accepted: 0, quarantined: 0, rejected: 0,
      errorCount: 1, errorSummary: classifyError(message) === 'error' ? 'Scanner threw' : message, failed: true,
    }).catch(() => {});
    return { stepId, resourceCount: 0, created: 0, error: message, errorSeverity: classifyError(message) };
  }
  const degradedMap = coverage.degradedTypes();
  const degradedResourceTypes = degradedMap.size > 0 ? [...degradedMap.keys()] : undefined;
  // The REASON travels with the type. Production runs stored 41 bare type
  // names with no reason anywhere, so nothing could tell an absent service
  // from an IAM denial -- and those need opposite responses.
  const degradedReasons = degradedMap.size > 0 ? Object.fromEntries(degradedMap) : undefined;
  // Returned even on the zero-resource path: an empty result caused by a
  // failed call is exactly the case finalize must not read as deletion.
  if (scanned.length === 0) {
    await recordProviderRequests(db, batch, calls).catch(() => {});
    await closeBatch(db, batch.id, {
      observed: 0, accepted: 0, quarantined: 0, rejected: 0,
      errorCount: degradedMap.size,
      errorSummary: callsDropped > 0 ? `${callsDropped} provider request(s) not recorded (per-batch cap)` : null,
    }).catch(() => {});
    return { stepId, resourceCount: 0, created: 0, degradedResourceTypes, degradedReasons };
  }

  const typeKeys = [...new Set(scanned.map((r) => r.resourceTypeKey))];
  const [catalogRows, existing] = await Promise.all([
    db.select<CatalogRow[]>('resource_type_catalog', { select: 'key,category,service', filters: { key: inFilter(typeKeys) } }),
    // Phase 4 §2: generation and lifecycle_state are selected because the
    // upsert can no longer be decided from the native id alone -- a deleted
    // id that reappears must open a new generation rather than land back in
    // the dead row.
    db.select<{ id: string; resource_type_key: string; resource_id: string; deleted_at: string | null; generation: number; lifecycle_state: LifecycleState }[]>('cloud_resources', {
      select: 'id,resource_type_key,resource_id,deleted_at,generation,lifecycle_state',
      filters: { connection_id: `eq.${connection.id}`, resource_type_key: inFilter(typeKeys) },
    }),
  ]);
  const catalogByKey = new Map(catalogRows.map((r) => [r.key, r]));
  const existingByKey = new Map(existing.map((r) => [`${r.resource_type_key}:${r.resource_id}`, r]));

  /**
   * All generations held for each identity, so resolveGeneration sees the
   * full history rather than whichever row happened to be last. Grouped once
   * here because the row builder below runs per accepted record.
   */
  const generationsByKey = new Map<string, ExistingGeneration[]>();
  for (const r of existing) {
    const key = `${r.resource_type_key}:${r.resource_id}`;
    const list = generationsByKey.get(key) ?? [];
    list.push({
      id: r.id,
      generation: r.generation ?? 1,
      lifecycle_state: r.lifecycle_state ?? (r.deleted_at ? 'DELETED' : 'ACTIVE'),
      // No AWS scanner supplies a reuse-proof identifier today, so this is
      // null for every type. Stated explicitly rather than left implicit:
      // when a scanner starts providing one (RDS DbiResourceId is the
      // obvious first), this is the single place that changes.
      immutable_identity: null,
    });
    generationsByKey.set(key, list);
  }

  /**
   * Phase 2 admission. Before this, `scanned` went straight into the upsert:
   * an unrecognised resourceTypeKey became a real inventory row in the
   * 'Others' category, an empty resourceId upserted against a conflict key
   * containing an empty string, and a resource belonging to a different AWS
   * account was written under this connection's account id regardless.
   *
   * Every record now ends as exactly ACCEPTED or QUARANTINED, and the batch's
   * accounting constraint makes a record that fell out of the pipeline
   * entirely unrepresentable rather than merely unlikely.
   *
   * The catalog for the WHOLE scan is the authority on known types, not just
   * the types this step happened to return -- otherwise every type would look
   * unknown on a step that returned only unknown types.
   */
  const knownTypes = new Set(catalogRows.map((c) => c.key));
  const admission = await admitObservations(scanned, {
    orgId,
    connectionId: connection.id,
    accountNativeId: connection.aws_account_id ?? null,
    knownResourceTypes: knownTypes,
  });

  const now = new Date().toISOString();
  const createdEvents: Record<string, unknown>[] = [];
  // Only ACCEPTED records reach canonical state. This single substitution is
  // the canonical-admission rule (§7): validated observation -> canonical
  // resource, never raw provider response -> canonical resource.
  const acceptedByIdentity = new Map(admission.accepted.map((a) => [`${a.resource.resourceTypeKey}${a.resource.resourceId}`, a]));
  const rows = admission.accepted.map(({ resource: r }) => {
    const catalog = catalogByKey.get(r.resourceTypeKey);
    const key = `${r.resourceTypeKey}:${r.resourceId}`;
    const prior = existingByKey.get(key);
    if (!prior || prior.deleted_at) {
      createdEvents.push({ connection_id: connection.id, resource_type_key: r.resourceTypeKey, aws_resource_id: r.resourceId, event_type: 'created' });
    }
    const decision = resolveGeneration(generationsByKey.get(key) ?? [], null);
    return {
      connection_id: connection.id, account_id: connection.aws_account_id, resource_type_key: r.resourceTypeKey,
      resource_id: r.resourceId, resource_name: r.resourceName ?? null, region: r.region,
      // Phase 4 §2/§8/§5.
      generation: decision.generation,
      lifecycle_state: decision.lifecycle_state,
      org_id: orgId,
      // §5: a region we hold is REGIONAL; absence of one is UNKNOWN, never a
      // default region and never GLOBAL, which needs the type registry's
      // globality flag to prove.
      location_scope: r.region && r.region.trim() !== '' && r.region.toLowerCase() !== 'unknown' ? 'REGIONAL' : 'UNKNOWN',
      updated_at: now,
      category: catalog?.category ?? 'Others', service: catalog?.service ?? r.resourceTypeKey.split('_')[0],
      state: r.state ?? null, status: r.state === 'terminated' ? 'terminated' : r.state === 'stopped' ? 'stopped' : 'active',
      is_default: r.isDefault ?? false, tags: r.tags ?? {}, metadata: r.metadata ?? {}, relationships: r.relationships ?? {},
      last_seen_at: now, deleted_at: null,
      // Lineage. `lineage_state: 'traced'` is only ever set here, on a row
      // that actually went through admission -- rows that predate this keep
      // 'legacy_unknown', which is the truth about them.
      ingestion_batch_id: batch.id,
      partition: acceptedByIdentity.get(`${r.resourceTypeKey}${r.resourceId}`)?.partition ?? null,
      provider_resource_arn: acceptedByIdentity.get(`${r.resourceTypeKey}${r.resourceId}`)?.arn ?? null,
      source_type: 'aws_api',
      collector_observed_at: now,
      ingested_at: now,
      normalized_at: now,
      source_schema_version: SOURCE_SCHEMA_VERSION,
      normalization_version: NORMALIZATION_VERSION,
      record_fingerprint: acceptedByIdentity.get(`${r.resourceTypeKey}${r.resourceId}`)?.recordFingerprint ?? null,
      configuration_hash: acceptedByIdentity.get(`${r.resourceTypeKey}${r.resourceId}`)?.configurationHash ?? null,
      lineage_state: 'traced',
    };
  });

  // Identity is (connection_id, resource_type_key, resource_id, GENERATION) —
  // upsert via on_conflict rather than delete+insert, so a resource's
  // first_seen_at/created_at (and its row id, which lifecycle events
  // elsewhere may reference) survive a re-scan.
  //
  // Phase 4 §2 added `generation` to the conflict target. Without it, a
  // native id that AWS released and reissued upserted straight into the
  // deleted resource's row and inherited its entire history -- including
  // cost facts and security findings that belonged to a different machine.
  // The four-column unique index backing this was created ahead of the
  // deploy; the older three-column constraint is dropped only afterwards.
  // `return=representation` (not minimal) because the canonical row ids are
  // what link each observation back to the resource it was admitted into --
  // without them, "show me the lineage for this resource" has nothing to
  // join on.
  const upserted = await db.insert<{ id: string; resource_type_key: string; resource_id: string; generation: number }[]>(
    'cloud_resources?on_conflict=connection_id,resource_type_key,resource_id,generation',
    rows,
    'resolution=merge-duplicates,return=representation',
  );
  if (createdEvents.length > 0) {
    await db.insert('resource_lifecycle_events', createdEvents, 'return=minimal');
  }

  /**
   * Evidence, written after canonical state so observations can point at real
   * row ids.
   *
   * Wrapped so a lineage write cannot fail a scan that already succeeded: a
   * missing lineage row is a visible gap, whereas a step that died recording
   * one loses the inventory too. The failure is counted on the batch rather
   * than swallowed silently.
   */
  const canonicalIdByIdentity = new Map((upserted ?? []).map((u) => [`${u.resource_type_key}${u.resource_id}`, u.id]));
  let lineageErrors = 0;
  await Promise.all([
    recordProviderRequests(db, batch, calls).catch(() => { lineageErrors += 1; }),
    recordObservations(db, {
      batch,
      accepted: admission.accepted,
      canonicalIdByIdentity,
      providerService: scannerName,
      providerOperation: null,
      collectorObservedAt: now,
    }).catch(() => { lineageErrors += 1; }),
    recordQuarantine(db, {
      batch,
      quarantined: admission.quarantined,
      providerService: scannerName,
      providerOperation: null,
      collectorObservedAt: now,
    }).catch(() => { lineageErrors += 1; }),
  ]);

  await closeBatch(db, batch.id, {
    observed: admission.counts.observed,
    accepted: admission.counts.accepted,
    quarantined: admission.counts.quarantined,
    rejected: admission.counts.rejected,
    errorCount: degradedMap.size + lineageErrors,
    // expected_count stays null: AWS list operations do not report how many
    // results exist before paging them, so `expected = observed` would be a
    // reconciliation that always passes and means nothing.
    expectedCount: null,
    errorSummary: callsDropped > 0 ? `${callsDropped} provider request(s) not recorded (per-batch cap)` : null,
  }).catch(() => {});

  // monitoring_alarms sync -- piggybacks on the cloudwatch step's own
  // DescribeAlarms results (no second API call) so cloudops-observability's
  // Alerts page and dashboard, which query this table specifically, aren't
  // permanently empty. See horizonvigil-incidents-adjacent plan notes.
  if (scannerName === 'cloudwatch') {
    const alarmRows = extractMonitoringAlarmRows(scanned, connection.id);
    if (alarmRows.length > 0) {
      await db.insert('monitoring_alarms?on_conflict=connection_id,alarm_name', alarmRows, 'resolution=merge-duplicates,return=minimal');
    }
  }

  // deployment_events sync -- real deployment history, Phase 3 of the
  // admin-console investigation-infrastructure roadmap. Needs a second API
  // call per stack (DescribeStackEvents has no account-wide list), so this
  // runs after the main cloudformation_stack rows are known, not derived
  // from `scanned` alone like the alarm sync above.
  if (scannerName === 'cloudformation') {
    const stackNames = scanned.filter((r) => r.resourceTypeKey === 'cloudformation_stack' && r.resourceName).map((r) => r.resourceName as string);
    if (stackNames.length > 0) {
      const events = await scanCloudFormationDeploymentEvents({ creds: resolved.creds, region }, connection.id, stackNames);
      if (events.length > 0) {
        await db.insert('deployment_events?on_conflict=connection_id,provider,event_id', events, 'resolution=merge-duplicates,return=minimal');
      }
    }
  }

  // cloud_identities sync -- piggybacks on the iam step's own iam_user/
  // iam_role results (no second API call), same pattern as the alarm sync
  // above. IAM is a global scanner (see iam.ts's REGION comment) so this
  // runs once per account, not once per scan region.
  if (scannerName === 'iam') {
    const identityRows = extractCloudIdentityRows(scanned, connection.id);
    if (identityRows.length > 0) {
      await db.insert('cloud_identities?on_conflict=connection_id,provider,native_id', identityRows, 'resolution=merge-duplicates,return=minimal');
    }
  }

  /*
   * AWS-P3 (M2). The degraded set travels on the SUCCESS path too, not only on
   * the zero-resource path above.
   *
   * A partial read is the dangerous case, not the empty one. A scanner that
   * covers 17 regions, is denied in 5 of them and returns rows from the other
   * 12 lands here -- and, before this, reported nothing at all about the 5.
   * finalize then reads "this type was covered and these ids did not come
   * back" as deletion and tombstones live infrastructure, which is the exact
   * outcome degradedResourceTypes exists to prevent. The empty case was
   * already guarded; the case that returns SOME data was not.
   */
  return { stepId, resourceCount: rows.length, created: createdEvents.length, degradedResourceTypes, degradedReasons };
}

/**
 * POST /api/aws-accounts/accounts/:id/discovery/run-step — runs exactly one
 * scanner against one region and upserts just its results. Small enough to
 * always fit inside one invocation's CPU/subrequest budget regardless of
 * how many scanners/regions exist in total.
 */


export interface StepErrorInput { message: string; severity: 'error' | 'info' }

/**
 * Both real producers of StepErrorInput (this file's own /run-step loop via
 * internalScan.ts, and the frontend's syncContext.tsx client-orchestrated
 * loop) construct `message` as the literal `${stepId}: ${error}` -- this
 * recovers that stepId rather than widening StepErrorInput's shape (and
 * both callers' request bodies) just to carry a field the message already
 * encodes. Falls back to the full message if a caller ever doesn't follow
 * the convention, rather than throwing away the error entirely.
 */
function extractStepId(message: string): string {
  const idx = message.indexOf(': ');
  return idx === -1 ? message : message.slice(0, idx);
}

/**
 * POST /api/aws-accounts/accounts/:id/discovery/finalize — runs after every
 * step has completed: anything belonging to this connection, of a resource
 * type a scanner actually ran this cycle, not touched by this run
 * (last_seen_at before runStartedAt) has vanished from AWS since the last
 * sync and gets marked deleted instead of lingering forever. Resource
 * types no scanner covers yet (kms_alias, iam_role, s3_bucket, ... — see
 * COVERED_RESOURCE_TYPES) are left untouched, not marked vanished, since a
 * scan that never checked them can't honestly know if they're still there.
 * Then rolls up cloud_connections.resource_summary the way the AWS
 * Accounts dashboard/inventory already expect to read it.
 */
export interface FinalizeOutcome { totalResources: number; deleted: number; findingsResolved: number; categoryCounts: Record<string, number>; errors: StepErrorInput[] }

/**
 * Shared by the HTTP finalize handler and the scheduled-scan path (see
 * routes/internalScan.ts) — extracted the same way runResourceStep was,
 * pure extraction of the existing behavior, actorId nullable since a
 * scheduled run has no human user to attribute the audit log entry to.
 *
 * `coveredResourceTypes` defaults to every type any live scanner can ever
 * produce (COVERED_RESOURCE_TYPES) — correct for the manual HTTP route
 * below, which only ever calls this after the frontend's step loop has run
 * every scanner for every one of the connection's scan_regions. The
 * scheduled path (internalScan.ts) caps how many steps run per invocation
 * and must pass a narrower set — see that file for why: naively reusing
 * COVERED_RESOURCE_TYPES there was a real bug (found 2026-08-12) that mass-
 * deleted resources whose region simply hadn't been re-checked yet this
 * cycle, not resources that had actually vanished from AWS.
 */
export async function runFinalize(db: Db, orgId: string, actorId: string | null, connection: ConnectionForDiscovery, runStartedAt: string, stepErrors: StepErrorInput[], env: Env, coveredResourceTypes: readonly string[] = COVERED_RESOURCE_TYPES, totalSteps = 0, degradedResourceTypes: readonly string[] = [], provenScopes: ReadonlySet<string> | null = null,
  /**
   * Finding sources this run actually proved -- see the resolve call below.
   * Defaults to NONE rather than to every source: a caller that does not know
   * what it covered has not proved anything, and the cost of being wrong here
   * is closing a real security finding nobody looked at.
   */
  coveredFindingSources: readonly string[] = []): Promise<FinalizeOutcome> {
  // `region` is selected for AWS-12: a resource in a region this run did not
  // successfully evaluate must not be tombstoned, however well its resource
  // type fared elsewhere.
  const existing = await db.select<{ id: string; resource_type_key: string; category: string; last_seen_at: string; deleted_at: string | null; region: string | null }[]>('cloud_resources', {
    select: 'id,resource_type_key,category,last_seen_at,deleted_at,region',
    filters: { connection_id: `eq.${connection.id}` },
    limit: 10000,
  });

  // Only resource types a currently-implemented scanner actually checked
  // this run are eligible to be marked vanished — see the coveredResourceTypes
  // param above and lib/discoveryFinalize.ts (extracted so this is unit-testable).
  const { vanishedIds, activeCategoryCounts, activeCount } = computeFinalizeResult(existing, coveredResourceTypes, runStartedAt, degradedResourceTypes, provenScopes);
  const now = new Date().toISOString();
  if (vanishedIds.length > 0) {
    // lifecycle_state moves with deleted_at. If the two could drift, the
    // generation logic -- which reads lifecycle_state -- would keep treating
    // a tombstoned row as live and never open a new generation when the id
    // came back, quietly restoring the bug §2 exists to remove.
    await db.update('cloud_resources', { id: `in.(${vanishedIds.join(',')})` }, { deleted_at: now, status: 'deleted', lifecycle_state: 'DELETED', updated_at: now }, 'return=minimal');
  }

  // Same vanish reasoning as cloud_resources above, scoped to the finding
  // sources FINDING_SCANNERS actually covers this run — a finding
  // AWS itself stopped returning (fixed, archived, or its resource gone)
  // is marked resolved rather than left open forever. Only 'open' rows are
  // touched, so a finding a user already suppressed stays suppressed.
  /*
   * AWS-P3. Only sources a finding scanner actually PROVED this run.
   *
   * This filter used to be a hardcoded literal listing all six sources,
   * applied on every finalize regardless of what ran. So a run whose GuardDuty
   * step was denied, throttled, cancelled by the slice budget, or simply not
   * in this run's plan still closed every open GuardDuty finding -- writing
   * "we could not read this" into the database as "the customer is clean",
   * which is the single worst form of that error the product can make, and it
   * happens silently and irreversibly to security findings.
   *
   * An empty set resolves nothing, which is the safe direction: a finding that
   * stays open one cycle too long is visible and self-correcting; one closed
   * because nobody looked is neither.
   */
  const resolvedFindings = coveredFindingSources.length === 0 ? [] : await db.update<{ id: string }[]>(
    'vulnerability_findings',
    { connection_id: `eq.${connection.id}`, status: 'eq.open', finding_source: inFilter([...coveredFindingSources]), last_seen_at: `lt.${runStartedAt}` },
    { status: 'resolved', resolved_at: now },
  );

  /**
   * Edge materialization runs once per full scan cycle, not per-step, since
   * it joins resources and identities scanned by different, independently-
   * ordered steps (lambda.ts, eks.ts, iam.ts) -- see edgeMaterialization.ts.
   * It runs AFTER tombstoning above so an edge can only bind to the
   * generation that is live now, and BEFORE the summary below so its outcome
   * is recorded rather than only logged.
   *
   * Still best-effort -- a correlation failure must not fail a scan that
   * collected real inventory. But "best-effort" previously meant a single
   * shared try/catch and one console line, and that is how AWS-10 spent its
   * whole life broken: every topology insert raised 23514 against a CHECK
   * constraint, the catch swallowed it, and a 1,904-resource estate rendered
   * as "no relationships" -- a total write failure presented as a fact about
   * the customer's infrastructure.
   *
   * Two changes so that cannot recur silently:
   *  - the two materializers get their own try/catch, so a failure in one no
   *    longer skips the other (that shared catch is why the topology call was
   *    never even reached whenever the identity edges failed first);
   *  - the outcome goes into the stored summary, so an empty graph is
   *    distinguishable from a graph that could not be built.
   */
  const graphOutcome: Record<string, unknown> = {};
  try {
    const { edgeCount } = await materializeResourceEdges(db, connection.id);
    graphOutcome.identityEdges = { state: 'materialized', edges: edgeCount };
  } catch (err) {
    graphOutcome.identityEdges = { state: 'failed', reason: err instanceof Error ? err.message : String(err) };
    console.error(`Identity edge materialization failed for connection ${connection.id} (continuing without it): ${err instanceof Error ? err.message : err}`);
  }
  try {
    const { edgeCount } = await materializeNetworkTopology(db, connection.id);
    graphOutcome.topologyEdges = { state: 'materialized', edges: edgeCount };
  } catch (err) {
    graphOutcome.topologyEdges = { state: 'failed', reason: err instanceof Error ? err.message : String(err) };
    console.error(`Network topology materialization failed for connection ${connection.id} (continuing without it): ${err instanceof Error ? err.message : err}`);
  }

  const realErrors = stepErrors.filter((e) => e.severity !== 'info');
  // A handful of transient failures (a couple of "fetch failed" network
  // blips late in a long multi-region run, say) shouldn't flip a connection
  // that mostly succeeded to a scary "error" badge. A fixed count threshold
  // was tried first and failed on the real case that motivated this: a
  // persistent, reproducible cluster of 15 "fetch failed" steps out of
  // 1,100+ (1.3%) that shows up on every single run, with 428 real
  // resources landing cleanly regardless. 15 exceeded any fixed threshold
  // low enough to still catch genuinely broken connections, so this uses a
  // ratio of totalSteps instead -- >10% real failures, or the old fixed
  // floor of 10 when totalSteps isn't known (callers that don't pass it).
  const connectionIsBroken = totalSteps > 0 ? realErrors.length / totalSteps > 0.1 : realErrors.length > 10;
  const summary = {
    scannedAt: now, totalResources: activeCount, categoryCounts: activeCategoryCounts,
    servicesTotal: `${Object.keys(REGIONAL_SCANNERS).length + Object.keys(GLOBAL_SCANNERS).length} live / 245 catalogued`,
    regionsScanned: regionsFor(connection), errors: stepErrors.slice(0, 20),
    // Present so a reader can tell "this estate has no relationships" from
    // "the graph could not be built this run". Those render identically
    // without it, and for AWS-10 the second was true for every run.
    graph: graphOutcome,
  };

  await db.update(
    'cloud_connections',
    { id: `eq.${connection.id}` },
    {
      last_discovery_at: now, last_full_scan_at: now, last_sync_at: now, resource_summary: summary,
      status: connectionIsBroken ? 'error' : 'connected',
      error_message: realErrors.length > 0 ? `${realErrors.length} scan step(s) failed: ${realErrors.slice(0, 3).map((e) => e.message).join('; ')}` : null,
      // Scan reached a real, committed conclusion (however it finished) --
      // clears the "started but not yet finished" marker so the
      // abandoned-scan sweep in internalScan.ts doesn't try to re-run it.
      scan_started_at: null,
    },
    'return=minimal',
  );

  await writeAuditLog(db, { orgId, actorId, action: 'aws_account.discovery_completed', targetType: 'cloud_connection', targetId: connection.id, metadata: { totalResources: activeCount, deleted: vanishedIds.length, findingsResolved: resolvedFindings.length, errors: realErrors.length } });

  // Sync History used to only ever show permission-validation runs (see
  // permissions.ts) -- a Discover Resources run never left a trace there at
  // all, which looked like discovery silently wasn't happening even when it
  // was. run_type distinguishes the two kinds of row on the same table
  // rather than needing a second history endpoint.
  await db.insert(
    'connection_validation_runs',
    {
      connection_id: connection.id, run_type: 'discovery', status: connectionIsBroken ? 'failed' : 'succeeded',
      started_at: runStartedAt, finished_at: now, triggered_by: actorId,
      error_message: realErrors.length > 0 ? `${realErrors.length} scan step(s) failed: ${realErrors.slice(0, 3).map((e) => e.message).join('; ')}` : null,
      // Full per-step detail (not just the first 3, and not just a
      // concatenated string) so recurring-failure detection can look back
      // across runs and name exactly which steps keep failing -- the
      // >10% threshold above deliberately keeps these runs "succeeded"
      // (see its comment), so this is the only place that history survives.
      failed_steps: realErrors.length > 0 ? realErrors.map((e) => ({ step: extractStepId(e.message), message: e.message })) : null,
    },
    'return=minimal',
  );

  // Both best-effort, server-to-server — see postScanHooks.ts's doc comment
  // for why these live here rather than as a client-side post-scan step:
  // this is the one function every scan path (interactive, daily sweep,
  // abandoned-scan recovery) already funnels through, so triggering here
  // covers all of them instead of just the browser-driven one.
  /**
   * Recorded, not just awaited. Both hooks return `not_configured` when this
   * service carries no hook URL or secret — which is the case in production
   * today — and a silently skipped hook is indistinguishable from one that
   * ran and found nothing to do. Stale cost recommendations survived three
   * weeks behind exactly that ambiguity.
   *
   * Written after the summary above rather than folded into it, because these
   * calls must happen last: they notify downstream services about inventory
   * that has to be committed first.
   */
  const hooks = {
    recommendations: await triggerRecommendationGeneration(env, connection.id, orgId),
    alerts: await triggerAlertEvaluation(env, connection.id, orgId),
  };
  if (hooks.recommendations.state !== 'called' || hooks.alerts.state !== 'called') {
    console.warn(`Post-scan hooks did not all fire for connection ${connection.id}: ${JSON.stringify(hooks)}`);
  }
  await db.update(
    'cloud_connections',
    { id: `eq.${connection.id}` },
    { resource_summary: { ...summary, hooks } },
    'return=minimal',
  );

  return { totalResources: activeCount, deleted: vanishedIds.length, findingsResolved: resolvedFindings.length, categoryCounts: activeCategoryCounts, errors: stepErrors };
}

/**
 * REMOVED (Phase 12 verification pass): the browser-era worker endpoints
 * `POST .../discovery/run-step` and `POST .../discovery/finalize`.
 *
 * The audit's disposition for both was "internal worker operation only" /
 * "remove; server computes terminal result". Phase 1 removed the browser's
 * calls and Phase 3 replaced the whole loop with durable collection runs,
 * but the ROUTES stayed mounted. I previously reported them as removed --
 * that was wrong. I probed with GET on POST-only routes, read the 404 as
 * "gone", and did not check the source.
 *
 * They were not merely redundant. A hand-crafted authenticated request
 * could drive a scan step outside the durable job machinery entirely: no
 * lease, no checkpoint, no run row. The partial unique index that makes
 * "one job despite repeated clicks" true guards `collection_runs`, and a
 * caller who never creates one is not covered by it.
 *
 * The step FUNCTIONS (runResourceStep, runFindingStep, runMetricStep,
 * runFinalize) are exported and unchanged -- collectionRuns.ts imports them
 * directly. Only the HTTP surface is gone.
 */
