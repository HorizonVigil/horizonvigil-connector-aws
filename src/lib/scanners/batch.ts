import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const BATCH_RESOURCE_TYPES = ['batch_compute_environment', 'batch_job_queue', 'batch_job_definition'] as const;

interface ComputeEnvironmentDetail {
  computeEnvironmentName: string; computeEnvironmentArn?: string; type?: string; state?: string; status?: string;
  computeResources?: { type?: string; minvCpus?: number; maxvCpus?: number };
}
interface JobQueueDetail {
  jobQueueName: string; jobQueueArn?: string; state?: string; status?: string; priority?: number;
}
interface JobDefinition {
  jobDefinitionName: string; jobDefinitionArn?: string; revision?: number; status?: string; type?: string;
}

/**
 * Batch is REST-JSON like Lambda (POST with a JSON body, no X-Amz-Target
 * header) — createAwsClient's raw signed fetch. Job definitions are filtered
 * to ACTIVE only; Batch keeps every revision of every definition forever,
 * so an unfiltered list grows unbounded over an account's lifetime.
 */
export async function scanBatch(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'batch', ctx.region);
  const base = `https://batch.${ctx.region}.amazonaws.com`;
  const post = async (path: string, body: Record<string, unknown>): Promise<Record<string, unknown> | null> => {
    const res = await safeFetch(client, `${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const text = await res.text();
    if (!res.ok) {
      console.error(`Batch POST ${path} failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };

  const out: ScannedResource[] = [];

  const envBody = await post('/v1/describecomputeenvironments', {});
  for (const env of (envBody?.computeEnvironments as ComputeEnvironmentDetail[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'batch_compute_environment', resourceId: env.computeEnvironmentArn ?? env.computeEnvironmentName, region: ctx.region,
      resourceName: env.computeEnvironmentName, state: env.status ?? env.state,
      metadata: { type: env.type, computeType: env.computeResources?.type, minvCpus: env.computeResources?.minvCpus, maxvCpus: env.computeResources?.maxvCpus },
    });
  }

  const queueBody = await post('/v1/describejobqueues', {});
  for (const q of (queueBody?.jobQueues as JobQueueDetail[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'batch_job_queue', resourceId: q.jobQueueArn ?? q.jobQueueName, region: ctx.region,
      resourceName: q.jobQueueName, state: q.status ?? q.state,
      metadata: { priority: q.priority },
    });
  }

  const defBody = await post('/v1/describejobdefinitions', { status: 'ACTIVE', maxResults: 100 });
  for (const d of (defBody?.jobDefinitions as JobDefinition[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'batch_job_definition', resourceId: d.jobDefinitionArn ?? `${d.jobDefinitionName}:${d.revision}`, region: ctx.region,
      resourceName: d.jobDefinitionName, state: d.status,
      metadata: { revision: d.revision, type: d.type },
    });
  }

  return out;
}
