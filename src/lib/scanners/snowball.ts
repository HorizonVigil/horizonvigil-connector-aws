import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SNOWBALL_RESOURCE_TYPES = ['snowball_job'] as const;

interface JobListEntry { JobId: string; JobState?: string; JobType?: string; SnowballType?: string; CreationDate?: number }
interface ListJobsResponse { JobListEntries?: JobListEntry[] }

/** AWS Snow Family — target prefix (AWSIESnowballJobManagementService) is a best-effort guess against AWS's internal naming, UNVERIFIED against a real account. */
export async function scanSnowball(ctx: ScannerContext): Promise<ScannedResource[]> {
  const result = await callJsonApi(ctx.creds, {
    service: 'snowball', region: ctx.region, host: `snowball.${ctx.region}.amazonaws.com`,
    target: 'AWSIESnowballJobManagementService.ListJobs', body: { MaxResults: 100 },
  });
  if (!result.ok) {
    console.error(`Snowball ListJobs failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const jobs = (result.body as ListJobsResponse).JobListEntries ?? [];
  return jobs.filter((j) => j.JobState !== 'Cancelled').map((j) => ({
    resourceTypeKey: 'snowball_job', resourceId: j.JobId, region: ctx.region,
    state: j.JobState, metadata: { jobType: j.JobType, snowballType: j.SnowballType, creationDate: j.CreationDate },
  }));
}
