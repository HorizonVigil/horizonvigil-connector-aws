import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, inFilter, writeAuditLog, guarded, okJson, errJson, type Db } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { resolveCredentials, type ResolvableConnection } from './permissions';
import { resolveFindingResourceIds } from '../lib/arnResourceLookup';
import { scanEc2, EC2_RESOURCE_TYPES } from '../lib/scanners/ec2';
import { scanRds, RDS_RESOURCE_TYPES } from '../lib/scanners/rds';
import { scanIam, IAM_RESOURCE_TYPES, extractCloudIdentityRows } from '../lib/scanners/iam';
import { materializeResourceEdges } from '../lib/edgeMaterialization';
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
import { scanGuardDutyFindings } from '../lib/scanners/guarddutyFindings';
import { scanSecurityHubFindings } from '../lib/scanners/securityhubFindings';
import { scanAccessAnalyzerFindings } from '../lib/scanners/accessAnalyzerFindings';
import { scanInspectorFindings } from '../lib/scanners/inspectorFindings';
import { scanAwsConfigFindings } from '../lib/scanners/awsConfigFindings';
import { scanTrustedAdvisorFindings } from '../lib/scanners/trustedAdvisorFindings';
import { scanEc2CpuMetrics } from '../lib/scanners/ec2Metrics';
import type { ScannedResource, ScannerFn } from '../lib/scanners/types';
import type { ScannedFinding, FindingScannerFn } from '../lib/scanners/findingTypes';
import type { ScannedMetric } from '../lib/scanners/metricTypes';
import { computeFinalizeResult } from '../lib/discoveryFinalize';

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
};
const COVERED_RESOURCE_TYPES = Object.values(SCANNER_RESOURCE_TYPES).flat();

export interface ConnectionForDiscovery extends ResolvableConnection {
  aws_account_id: string;
  scan_regions: string[] | null;
}

export async function loadConnection(db: Db, orgId: string, id: string): Promise<ConnectionForDiscovery | null> {
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
 * GET /api/aws-accounts/accounts/:id/discovery/steps — the ordered step
 * list this account's scan regions require, for the frontend's step-loop.
 * Also stamps scan_started_at, even though this is nominally a GET — this
 * is genuinely the first call of every interactive scan (see
 * syncContext.tsx's startDiscovery), so it's the one reliable place to
 * record "a scan began here" for the abandoned-scan sweep in
 * internalScan.ts to detect a tab that closed before finishing. Bumped to
 * requiring 'write' rather than 'read' to match that real side effect.
 */
discoveryRoutes.get('/accounts/:id/discovery/steps', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    const connection = await loadConnection(db, orgId, c.req.param('id'));
    if (!connection) return errJson(404, 'Account not found');

    const regionalNames = Object.keys(REGIONAL_SCANNERS);
    const globalNames = Object.keys(GLOBAL_SCANNERS);
    const findingNames = Object.keys(FINDING_SCANNERS);
    const regions = regionsFor(connection);
    const steps = [
      ...regions.flatMap((region) => regionalNames.map((name) => `regional:${name}:${region}`)),
      ...globalNames.map((name) => `global:${name}`),
      ...regions.flatMap((region) => findingNames.map((name) => `finding:${name}:${region}`)),
      ...regions.map((region) => `metric:${METRIC_STEP_NAME}:${region}`),
    ];

    await db.update('cloud_connections', { id: `eq.${connection.id}` }, { scan_started_at: new Date().toISOString() }, 'return=minimal');

    return okJson({ steps, regions, scannerCount: regionalNames.length + globalNames.length + findingNames.length + 1 });
  }),
);

export interface StepResult {
  stepId: string;
  resourceCount: number;
  created: number;
  error?: string;
  /** 'info' = the account/region just doesn't have this service turned on — not a real failure. */
  errorSeverity?: 'error' | 'info';
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
export async function runFindingStep(db: Db, orgId: string, env: Env, connectionId: string, stepId: string): Promise<StepResult> {
  const rest = stepId.slice('finding:'.length);
  const sep = rest.indexOf(':');
  if (sep === -1) return { stepId, resourceCount: 0, created: 0, error: `Malformed stepId "${stepId}"`, errorSeverity: 'error' };
  const scannerName = rest.slice(0, sep);
  const region = rest.slice(sep + 1);
  const scanner = FINDING_SCANNERS[scannerName];
  if (!scanner) return { stepId, resourceCount: 0, created: 0, error: `Unknown finding scanner "${scannerName}"`, errorSeverity: 'error' };

  const connection = await loadConnection(db, orgId, connectionId);
  if (!connection) return { stepId, resourceCount: 0, created: 0, error: 'Account not found', errorSeverity: 'error' };

  const resolved = await resolveCredentials(env, connection);
  if ('error' in resolved) return { stepId, resourceCount: 0, created: 0, error: resolved.error, errorSeverity: 'error' };

  let scanned: ScannedFinding[];
  try {
    scanned = await scanner({ creds: resolved.creds, region });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Scan failed';
    return { stepId, resourceCount: 0, created: 0, error: message, errorSeverity: classifyError(message) };
  }
  if (scanned.length === 0) return { stepId, resourceCount: 0, created: 0 };

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
      severity: f.severity, cvss_score: f.cvssScore ?? null, title: f.title, description: f.description ?? null,
      compliance_frameworks: f.complianceFrameworks ?? [], remediation_link: f.remediationLink ?? null,
      discovered_at: f.discoveredAt, region: f.region, resource_arn: f.resourceArn ?? null, last_seen_at: now,
    };
  });

  await db.insert('vulnerability_findings?on_conflict=connection_id,finding_source,aws_finding_id', rows, 'resolution=merge-duplicates,return=minimal');

  return { stepId, resourceCount: rows.length, created };
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
export async function runMetricStep(db: Db, orgId: string, env: Env, connectionId: string, stepId: string): Promise<StepResult> {
  const rest = stepId.slice('metric:'.length);
  const sep = rest.indexOf(':');
  if (sep === -1) return { stepId, resourceCount: 0, created: 0, error: `Malformed stepId "${stepId}"`, errorSeverity: 'error' };
  const metricName = rest.slice(0, sep);
  const region = rest.slice(sep + 1);
  if (metricName !== METRIC_STEP_NAME) return { stepId, resourceCount: 0, created: 0, error: `Unknown metric step "${metricName}"`, errorSeverity: 'error' };

  const connection = await loadConnection(db, orgId, connectionId);
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
export async function runResourceStep(db: Db, orgId: string, env: Env, connectionId: string, stepId: string): Promise<StepResult> {
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

  const connection = await loadConnection(db, orgId, connectionId);
  if (!connection) return { stepId, resourceCount: 0, created: 0, error: 'Account not found', errorSeverity: 'error' };

  const resolved = await resolveCredentials(env, connection);
  if ('error' in resolved) return { stepId, resourceCount: 0, created: 0, error: resolved.error, errorSeverity: 'error' };

  let scanned: ScannedResource[];
  try {
    scanned = await scanner({ creds: resolved.creds, region });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Scan failed';
    return { stepId, resourceCount: 0, created: 0, error: message, errorSeverity: classifyError(message) };
  }
  if (scanned.length === 0) return { stepId, resourceCount: 0, created: 0 };

  const typeKeys = [...new Set(scanned.map((r) => r.resourceTypeKey))];
  const [catalogRows, existing] = await Promise.all([
    db.select<CatalogRow[]>('resource_type_catalog', { select: 'key,category,service', filters: { key: inFilter(typeKeys) } }),
    db.select<{ resource_type_key: string; resource_id: string; deleted_at: string | null }[]>('cloud_resources', {
      select: 'resource_type_key,resource_id,deleted_at',
      filters: { connection_id: `eq.${connection.id}`, resource_type_key: inFilter(typeKeys) },
    }),
  ]);
  const catalogByKey = new Map(catalogRows.map((r) => [r.key, r]));
  const existingByKey = new Map(existing.map((r) => [`${r.resource_type_key}:${r.resource_id}`, r]));

  const now = new Date().toISOString();
  const createdEvents: Record<string, unknown>[] = [];
  const rows = scanned.map((r) => {
    const catalog = catalogByKey.get(r.resourceTypeKey);
    const key = `${r.resourceTypeKey}:${r.resourceId}`;
    const prior = existingByKey.get(key);
    if (!prior || prior.deleted_at) {
      createdEvents.push({ connection_id: connection.id, resource_type_key: r.resourceTypeKey, aws_resource_id: r.resourceId, event_type: 'created' });
    }
    return {
      connection_id: connection.id, account_id: connection.aws_account_id, resource_type_key: r.resourceTypeKey,
      resource_id: r.resourceId, resource_name: r.resourceName ?? null, region: r.region,
      category: catalog?.category ?? 'Others', service: catalog?.service ?? r.resourceTypeKey.split('_')[0],
      state: r.state ?? null, status: r.state === 'terminated' ? 'terminated' : r.state === 'stopped' ? 'stopped' : 'active',
      is_default: r.isDefault ?? false, tags: r.tags ?? {}, metadata: r.metadata ?? {}, relationships: r.relationships ?? {},
      last_seen_at: now, deleted_at: null,
    };
  });

  // cloud_resources has a unique constraint on (connection_id, resource_type_key,
  // resource_id) — upsert via on_conflict rather than delete+insert, so a
  // resource's first_seen_at/created_at (and its row id, which lifecycle
  // events elsewhere may reference) survive a re-scan.
  await db.insert('cloud_resources?on_conflict=connection_id,resource_type_key,resource_id', rows, 'resolution=merge-duplicates,return=minimal');
  if (createdEvents.length > 0) {
    await db.insert('resource_lifecycle_events', createdEvents, 'return=minimal');
  }

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

  return { stepId, resourceCount: rows.length, created: createdEvents.length };
}

/**
 * POST /api/aws-accounts/accounts/:id/discovery/run-step — runs exactly one
 * scanner against one region and upserts just its results. Small enough to
 * always fit inside one invocation's CPU/subrequest budget regardless of
 * how many scanners/regions exist in total.
 */
discoveryRoutes.post('/accounts/:id/discovery/run-step', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    const body = (await c.req.json().catch(() => ({}))) as { stepId?: string };
    const stepId = body.stepId;
    if (!stepId) return errJson(400, 'stepId is required, e.g. "regional:ec2:us-east-1", "global:iam", or "finding:guardduty:us-east-1"');

    if (stepId.startsWith('finding:')) {
      return okJson(await runFindingStep(db, orgId, c.env, c.req.param('id'), stepId));
    }
    if (stepId.startsWith('metric:')) {
      return okJson(await runMetricStep(db, orgId, c.env, c.req.param('id'), stepId));
    }
    return okJson(await runResourceStep(db, orgId, c.env, c.req.param('id'), stepId));
  }),
);

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
export async function runFinalize(db: Db, orgId: string, actorId: string | null, connection: ConnectionForDiscovery, runStartedAt: string, stepErrors: StepErrorInput[], coveredResourceTypes: readonly string[] = COVERED_RESOURCE_TYPES, totalSteps = 0): Promise<FinalizeOutcome> {
  const existing = await db.select<{ id: string; resource_type_key: string; category: string; last_seen_at: string; deleted_at: string | null }[]>('cloud_resources', {
    select: 'id,resource_type_key,category,last_seen_at,deleted_at',
    filters: { connection_id: `eq.${connection.id}` },
    limit: 10000,
  });

  // Only resource types a currently-implemented scanner actually checked
  // this run are eligible to be marked vanished — see the coveredResourceTypes
  // param above and lib/discoveryFinalize.ts (extracted so this is unit-testable).
  const { vanishedIds, activeCategoryCounts, activeCount } = computeFinalizeResult(existing, coveredResourceTypes, runStartedAt);
  const now = new Date().toISOString();
  if (vanishedIds.length > 0) {
    await db.update('cloud_resources', { id: `in.(${vanishedIds.join(',')})` }, { deleted_at: now, status: 'deleted' }, 'return=minimal');
  }

  // Same vanish reasoning as cloud_resources above, scoped to the finding
  // sources FINDING_SCANNERS actually covers this run — a finding
  // AWS itself stopped returning (fixed, archived, or its resource gone)
  // is marked resolved rather than left open forever. Only 'open' rows are
  // touched, so a finding a user already suppressed stays suppressed.
  const resolvedFindings = await db.update<{ id: string }[]>(
    'vulnerability_findings',
    { connection_id: `eq.${connection.id}`, status: 'eq.open', finding_source: 'in.(guardduty,security_hub,iam_access_analyzer,inspector,aws_config,trusted_advisor)', last_seen_at: `lt.${runStartedAt}` },
    { status: 'resolved', resolved_at: now },
  );

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

  // Edge materialization runs once per full scan cycle, not per-step, since
  // it joins resources and identities scanned by different, independently-
  // ordered steps (lambda.ts, eks.ts, iam.ts) -- see edgeMaterialization.ts.
  // Best-effort: a resource that briefly can't be correlated into an edge
  // (e.g. its role hasn't been scanned yet this run) is picked up cleanly
  // on the next cycle, so a failure here must never fail the whole scan.
  try {
    await materializeResourceEdges(db, connection.id);
  } catch (err) {
    console.error(`Edge materialization failed for connection ${connection.id} (continuing without it): ${err instanceof Error ? err.message : err}`);
  }

  return { totalResources: activeCount, deleted: vanishedIds.length, findingsResolved: resolvedFindings.length, categoryCounts: activeCategoryCounts, errors: stepErrors };
}

discoveryRoutes.post('/accounts/:id/discovery/finalize', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    const body = (await c.req.json().catch(() => ({}))) as { runStartedAt?: string; stepErrors?: StepErrorInput[]; totalSteps?: number };
    if (!body.runStartedAt) return errJson(400, 'runStartedAt is required');

    const connection = await loadConnection(db, orgId, c.req.param('id'));
    if (!connection) return errJson(404, 'Account not found');

    const outcome = await runFinalize(db, orgId, auth.userId, connection, body.runStartedAt, body.stepErrors ?? [], COVERED_RESOURCE_TYPES, body.totalSteps ?? 0);
    return okJson(outcome);
  }),
);
