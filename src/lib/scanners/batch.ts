import { createAwsClient } from '../awsApi';
import { postJson, reportWalk, walkPages, type PageWalk } from './restJson';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const BATCH_RESOURCE_TYPES = ['batch_compute_environment', 'batch_job_queue', 'batch_job_definition'] as const;

interface ComputeEnvironmentDetail {
  computeEnvironmentName: string; computeEnvironmentArn?: string; type?: string; state?: string; status?: string;
  serviceRole?: string;
  computeResources?: {
    type?: string; minvCpus?: number; maxvCpus?: number;
    subnets?: string[]; securityGroupIds?: string[]; instanceRole?: string; ec2KeyPair?: string;
    launchTemplate?: { launchTemplateId?: string; launchTemplateName?: string; version?: string };
  };
}
interface JobQueueDetail {
  jobQueueName: string; jobQueueArn?: string; state?: string; status?: string; priority?: number;
  schedulingPolicyArn?: string;
  computeEnvironmentOrder?: { order?: number; computeEnvironment?: string }[];
}
interface ContainerProperties {
  privileged?: boolean;
  readonlyRootFilesystem?: boolean;
  user?: string;
  jobRoleArn?: string;
  executionRoleArn?: string;
  environment?: { name?: string; value?: string }[];
  secrets?: { name?: string }[];
  networkConfiguration?: { assignPublicIp?: string };
}
interface JobDefinition {
  jobDefinitionName: string; jobDefinitionArn?: string; revision?: number; status?: string; type?: string;
  platformCapabilities?: string[];
  containerProperties?: ContainerProperties;
}

/**
 * Environment variable NAMES that suggest a secret passed in plain text.
 * Values are NEVER read into metadata; only the names are recorded.
 */
const SECRET_NAME_PATTERN = /(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|access[_-]?key)/i;

/** Container-security evidence for one job definition. */
export function jobDefinitionEvidence(d: JobDefinition) {
  const c = d.containerProperties;
  const envNames = (c?.environment ?? []).map((e) => e.name).filter((n): n is string => !!n);
  return {
    revision: d.revision,
    type: d.type,
    platformCapabilities: d.platformCapabilities ?? [],
    // Privileged containers get root on the host.
    privileged: c?.privileged ?? false,
    readonlyRootFilesystem: c?.readonlyRootFilesystem ?? false,
    runsAsRoot: c ? (c.user === undefined || c.user === '' || c.user === 'root' || c.user === '0') : null,
    jobRoleArn: c?.jobRoleArn ?? null,
    executionRoleArn: c?.executionRoleArn ?? null,
    secretsManagedCount: c?.secrets?.length ?? 0,
    // Names only -- a hint that a secret may be in plain-text environment.
    plaintextSecretLikeEnvNames: envNames.filter((n) => SECRET_NAME_PATTERN.test(n)),
    assignPublicIp: c?.networkConfiguration?.assignPublicIp ?? null,
  };
}

/**
 * AWS Batch (REST-JSON, POST with JSON body).
 *
 * What changed: all three describes paginate (nextToken; job definitions
 * stopped at 100, compute environments and queues at their default page),
 * failures are reported rather than returned as [], and each resource
 * carries security evidence -- compute environment network placement and
 * roles, queue ordering, and job-definition container posture (privileged,
 * root user, read-only root filesystem, plain-text secret-like env names).
 * Job definitions remain ACTIVE-only: Batch keeps every revision forever.
 */
export async function scanBatch(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'batch', ctx.region);
  const base = `https://batch.${ctx.region}.amazonaws.com`;
  const list = <T>(path: string, key: string, body: Record<string, unknown>): Promise<PageWalk<T>> => walkPages<T>(
    (token) => postJson(client, `${base}${path}`, { ...body, ...(token ? { nextToken: token } : {}) }),
    (b) => b[key],
    (b) => b.nextToken,
  );

  const [envs, queues, defs] = await Promise.all([
    list<ComputeEnvironmentDetail>('/v1/describecomputeenvironments', 'computeEnvironments', { maxResults: 100 }),
    list<JobQueueDetail>('/v1/describejobqueues', 'jobQueues', { maxResults: 100 }),
    list<JobDefinition>('/v1/describejobdefinitions', 'jobDefinitions', { status: 'ACTIVE', maxResults: 100 }),
  ]);
  reportWalk(ctx, envs, 'batch', 'DescribeComputeEnvironments');
  reportWalk(ctx, queues, 'batch', 'DescribeJobQueues');
  reportWalk(ctx, defs, 'batch', 'DescribeJobDefinitions');

  const out: ScannedResource[] = [];

  for (const env of envs.items) {
    if (!env?.computeEnvironmentName) continue;
    const cr = env.computeResources;
    out.push({
      resourceTypeKey: 'batch_compute_environment', resourceId: env.computeEnvironmentArn ?? env.computeEnvironmentName, region: ctx.region,
      resourceName: env.computeEnvironmentName, state: env.status ?? env.state,
      metadata: {
        type: env.type, computeType: cr?.type, minvCpus: cr?.minvCpus, maxvCpus: cr?.maxvCpus,
        enabled: env.state === 'ENABLED',
        ec2KeyPair: cr?.ec2KeyPair ?? null,
      },
      relationships: {
        subnetIds: cr?.subnets ?? [],
        securityGroupIds: cr?.securityGroupIds ?? [],
        serviceRoleArn: env.serviceRole ?? null,
        instanceRole: cr?.instanceRole ?? null,
        launchTemplateId: cr?.launchTemplate?.launchTemplateId ?? null,
      },
    });
  }

  for (const q of queues.items) {
    if (!q?.jobQueueName) continue;
    out.push({
      resourceTypeKey: 'batch_job_queue', resourceId: q.jobQueueArn ?? q.jobQueueName, region: ctx.region,
      resourceName: q.jobQueueName, state: q.status ?? q.state,
      metadata: { priority: q.priority, enabled: q.state === 'ENABLED', schedulingPolicyArn: q.schedulingPolicyArn ?? null },
      relationships: {
        computeEnvironmentArns: [...(q.computeEnvironmentOrder ?? [])]
          .sort((a, b) => (a.order ?? 0) - (b.order ?? 0))
          .map((o) => o.computeEnvironment)
          .filter((v): v is string => !!v),
      },
    });
  }

  for (const d of defs.items) {
    if (!d?.jobDefinitionName) continue;
    const evidence = jobDefinitionEvidence(d);
    out.push({
      resourceTypeKey: 'batch_job_definition', resourceId: d.jobDefinitionArn ?? `${d.jobDefinitionName}:${d.revision}`, region: ctx.region,
      resourceName: d.jobDefinitionName, state: d.status,
      metadata: evidence,
      relationships: { jobRoleArn: evidence.jobRoleArn, executionRoleArn: evidence.executionRoleArn },
    });
  }

  return out;
}