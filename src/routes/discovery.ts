import { Hono, getAuthContext, requireOrgId, createDb, requireRole, requireMember, inFilter, writeAuditLog, guarded, okJson, errJson, type Db } from '@cloudops360/shared-lib';
import type { Env } from '../env';
import { resolveCredentials, type ResolvableConnection } from './permissions';
import { scanEc2, EC2_RESOURCE_TYPES } from '../lib/scanners/ec2';
import { scanRds, RDS_RESOURCE_TYPES } from '../lib/scanners/rds';
import { scanIam, IAM_RESOURCE_TYPES } from '../lib/scanners/iam';
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
import { scanCloudFormation, CLOUDFORMATION_RESOURCE_TYPES } from '../lib/scanners/cloudformation';
import { scanEfs, EFS_RESOURCE_TYPES } from '../lib/scanners/efs';
import { scanBackup, BACKUP_RESOURCE_TYPES } from '../lib/scanners/backup';
import { scanCloudWatch, CLOUDWATCH_RESOURCE_TYPES } from '../lib/scanners/cloudwatch';
import { scanCloudTrail, CLOUDTRAIL_RESOURCE_TYPES } from '../lib/scanners/cloudtrail';
import { scanSsm, SSM_RESOURCE_TYPES } from '../lib/scanners/ssm';
import { scanEvents, EVENTS_RESOURCE_TYPES } from '../lib/scanners/events';
import { scanStates, STATES_RESOURCE_TYPES } from '../lib/scanners/states';
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
};
export const GLOBAL_SCANNERS: Record<string, ScannerFn> = {
  iam: scanIam,
  s3: scanS3,
  route53: scanRoute53,
  cloudfront: scanCloudFront,
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
const SCANNER_RESOURCE_TYPES: Record<string, readonly string[]> = {
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

/** GET /api/aws-accounts/accounts/:id/discovery/steps — the ordered step list this account's scan regions require, for the frontend's step-loop. */
discoveryRoutes.get('/accounts/:id/discovery/steps', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMember(db, auth.userId, orgId);

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

  const now = new Date().toISOString();
  let created = 0;
  const rows = scanned.map((f) => {
    if (!existingKeys.has(`${f.findingSource}:${f.awsFindingId}`)) created++;
    return {
      connection_id: connection.id, resource_id: null, finding_source: f.findingSource, aws_finding_id: f.awsFindingId,
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
  if (stepId.startsWith('regional:')) {
    const rest = stepId.slice('regional:'.length);
    const sep = rest.indexOf(':');
    if (sep === -1) return { stepId, resourceCount: 0, created: 0, error: `Malformed stepId "${stepId}"`, errorSeverity: 'error' };
    const scannerName = rest.slice(0, sep);
    region = rest.slice(sep + 1);
    scanner = REGIONAL_SCANNERS[scannerName];
  } else if (stepId.startsWith('global:')) {
    const scannerName = stepId.slice('global:'.length);
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
    await requireRole(db, auth.userId, orgId, ['editor'], true);

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
 */
export async function runFinalize(db: Db, orgId: string, actorId: string | null, connection: ConnectionForDiscovery, runStartedAt: string, stepErrors: StepErrorInput[]): Promise<FinalizeOutcome> {
  const existing = await db.select<{ id: string; resource_type_key: string; category: string; last_seen_at: string; deleted_at: string | null }[]>('cloud_resources', {
    select: 'id,resource_type_key,category,last_seen_at,deleted_at',
    filters: { connection_id: `eq.${connection.id}` },
    limit: 10000,
  });

  // Only resource types a currently-implemented scanner actually checked
  // this run are eligible to be marked vanished — see COVERED_RESOURCE_TYPES
  // and lib/discoveryFinalize.ts (extracted so this is unit-testable).
  const { vanishedIds, activeCategoryCounts, activeCount } = computeFinalizeResult(existing, COVERED_RESOURCE_TYPES, runStartedAt);
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
  const summary = {
    scannedAt: now, totalResources: activeCount, categoryCounts: activeCategoryCounts,
    servicesTotal: `${Object.keys(REGIONAL_SCANNERS).length + Object.keys(GLOBAL_SCANNERS).length} live / 241 catalogued`,
    regionsScanned: regionsFor(connection), errors: stepErrors.slice(0, 20),
  };

  await db.update(
    'cloud_connections',
    { id: `eq.${connection.id}` },
    {
      last_discovery_at: now, last_full_scan_at: now, last_sync_at: now, resource_summary: summary,
      status: realErrors.length > 0 ? 'error' : 'connected',
      error_message: realErrors.length > 0 ? `${realErrors.length} scan step(s) failed: ${realErrors.slice(0, 3).map((e) => e.message).join('; ')}` : null,
    },
    'return=minimal',
  );

  await writeAuditLog(db, { orgId, actorId, action: 'aws_account.discovery_completed', targetType: 'cloud_connection', targetId: connection.id, metadata: { totalResources: activeCount, deleted: vanishedIds.length, findingsResolved: resolvedFindings.length, errors: realErrors.length } });

  return { totalResources: activeCount, deleted: vanishedIds.length, findingsResolved: resolvedFindings.length, categoryCounts: activeCategoryCounts, errors: stepErrors };
}

discoveryRoutes.post('/accounts/:id/discovery/finalize', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireRole(db, auth.userId, orgId, ['editor'], true);

    const body = (await c.req.json().catch(() => ({}))) as { runStartedAt?: string; stepErrors?: StepErrorInput[] };
    if (!body.runStartedAt) return errJson(400, 'runStartedAt is required');

    const connection = await loadConnection(db, orgId, c.req.param('id'));
    if (!connection) return errJson(404, 'Account not found');

    const outcome = await runFinalize(db, orgId, auth.userId, connection, body.runStartedAt, body.stepErrors ?? []);
    return okJson(outcome);
  }),
);
