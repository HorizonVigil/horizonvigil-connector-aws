import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AWSGlue';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const GLUE_RESOURCE_TYPES = ['glue_database', 'glue_job', 'glue_crawler', 'glue_workflow'] as const;

interface GlueDatabase { Name: string; Description?: string; CreateTime?: number }
interface GlueJob { Name: string; Role?: string; CreatedOn?: number; GlueVersion?: string; WorkerType?: string }
interface GlueCrawler { Name: string; State?: string; DatabaseName?: string; CreationTime?: number }

/** Four independent list/get calls, none needing a fan-out — each already returns everything this catalog entry uses. Workflow names only (GetWorkflow per name would add run-state detail, not built here). */
export async function scanGlue(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `glue.${ctx.region}.amazonaws.com`;
  const call = async (op: string, body: Record<string, unknown> = {}) => {
    const result = await callJsonApi(ctx.creds, { service: 'glue', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.${op}`, body });
    if (!result.ok) {
      console.error(`Glue ${op} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return null;
    }
    return result.body as Record<string, unknown>;
  };

  const out: ScannedResource[] = [];

  const databases = await call('GetDatabases');
  for (const db of (databases?.DatabaseList as GlueDatabase[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'glue_database', resourceId: db.Name, region: ctx.region, resourceName: db.Name,
      metadata: { description: db.Description, createdAt: db.CreateTime },
    });
  }

  const jobs = await call('GetJobs');
  for (const job of (jobs?.Jobs as GlueJob[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'glue_job', resourceId: job.Name, region: ctx.region, resourceName: job.Name,
      metadata: { glueVersion: job.GlueVersion, workerType: job.WorkerType, createdAt: job.CreatedOn },
      relationships: { roleArn: job.Role },
    });
  }

  const crawlers = await call('GetCrawlers');
  for (const cr of (crawlers?.Crawlers as GlueCrawler[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'glue_crawler', resourceId: cr.Name, region: ctx.region, resourceName: cr.Name,
      state: cr.State, metadata: { createdAt: cr.CreationTime },
      relationships: { databaseName: cr.DatabaseName },
    });
  }

  const workflows = await call('ListWorkflows');
  for (const name of (workflows?.Workflows as string[] | undefined) ?? []) {
    out.push({ resourceTypeKey: 'glue_workflow', resourceId: name, region: ctx.region, resourceName: name });
  }

  return out;
}
