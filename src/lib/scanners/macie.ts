import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const MACIE_RESOURCE_TYPES = ['macie_classification_job'] as const;

interface LastRunErrorStatus { code?: string }
interface UserPausedDetails { jobExpiresAt?: string; jobImminentExpirationHealthEventArn?: string; jobPausedAt?: string }
interface S3BucketDefinitionForJob { accountId?: string; buckets?: string[] }
interface JobSummary {
  jobId?: string;
  name?: string;
  jobStatus?: string;
  jobType?: string;
  createdAt?: string;
  lastRunErrorStatus?: LastRunErrorStatus;
  userPausedDetails?: UserPausedDetails;
  bucketDefinitions?: S3BucketDefinitionForJob[];
  // Property- and tag-based bucket selection criteria (the alternative to
  // bucketDefinitions — a job's definition uses one or the other, never
  // both). Left as an opaque blob in metadata rather than typed out here:
  // it's a deeply nested include/exclude/AND-of-conditions structure the UI
  // has no immediate use for beyond "does this job use criteria-based
  // selection", which `metadata.usesBucketCriteria` below answers directly.
  bucketCriteria?: unknown;
}
interface ListClassificationJobsResponse { items?: JobSummary[]; nextToken?: string }

/**
 * Amazon Macie classification-job inventory — REST-JSON (POST /jobs/list),
 * same request-shape family as Inspector2/GuardDuty/SecurityHub's own APIs.
 * This is Macie's own RESOURCE inventory (what sensitive-data-discovery
 * jobs exist and their status/schedule/target buckets) — a distinct,
 * separate scanner from Macie's *findings* (the sensitive-data matches a
 * job turns up), which is out of scope here and not yet built.
 *
 * Confirmed via AWS's own published docs (not guessed):
 *  - Host: `macie2.<region>.amazonaws.com`, per AWS's "Amazon Macie
 *    endpoints and quotas" general-reference page.
 *  - Operation: ListClassificationJobs, POST `/jobs/list`, per AWS's Macie
 *    API Reference "Classification Job List" resource page.
 *  - Response shape: `{ items: JobSummary[], nextToken }`, where each
 *    JobSummary carries jobId, jobStatus (RUNNING | PAUSED | CANCELLED |
 *    COMPLETE | IDLE | USER_PAUSED), jobType (ONE_TIME | SCHEDULED), name,
 *    createdAt, lastRunErrorStatus.code, userPausedDetails,
 *    bucketDefinitions, and bucketCriteria — all per that same reference
 *    page's documented `ListClassificationJobsResponse`/`JobSummary`
 *    schema.
 *
 * One deliberate deviation from this task's own field guidance: `jobArn` is
 * NOT part of the documented ListClassificationJobs response (the schema
 * above is the complete `JobSummary` shape AWS publishes for this
 * operation — no jobArn property exists on it). It's therefore omitted
 * below rather than fabricated; a per-job GetClassificationJob follow-up
 * call would presumably return one, but that's a separate operation this
 * task didn't ask for and would turn a single list call into an N+1 fan-out.
 * `resourceId` uses the bare jobId instead, matching guardduty_detector's
 * same choice of AWS's opaque unique id over a constructed ARN.
 *
 * Signing service name `'macie2'` is convention (matches the host prefix,
 * same as every other scanner here — inspector2.ts/guardduty.ts), not
 * separately confirmed against an SDK source file the way
 * licensemanager.ts's signing name was.
 *
 * UNVERIFIED against a real account's actual response shape until this
 * runs against a live connection and gets checked — same disclosed
 * uncertainty as inspector2.ts/licensemanager.ts. Macie requires an
 * explicit "enable Macie" opt-in step most accounts never take, so an
 * AccessDeniedException-style "account is not enrolled" failure here is
 * the expected, honest case (mirroring inspectorFindings.ts's own wording
 * for Inspector's equivalent not-enabled case), logged and skipped rather
 * than thrown.
 */
export async function scanMacie(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'macie2', ctx.region);
  const base = `https://macie2.${ctx.region}.amazonaws.com`;

  const out: ScannedResource[] = [];
  let nextToken: string | undefined;
  // Bounded pagination loop, same shape as inspectorFindings.ts's — capped
  // rather than followed to exhaustion so one account with an unusually
  // large job backlog can't turn a single scan into an unbounded number of
  // sequential calls. 5 pages * 100 covers up to 500 jobs, generous for
  // what's normally a handful of recurring/one-time jobs per account.
  for (let page = 0; page < 5; page++) {
    const res = await safeFetch(client, `${base}/jobs/list`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ maxResults: 100, ...(nextToken ? { nextToken } : {}) }),
    });
    const text = await res.text();
    if (!res.ok) {
      console.error(`Macie ListClassificationJobs failed in ${ctx.region} (continuing without it — likely just not enabled there): HTTP ${res.status} ${text.slice(0, 200)}`);
      return page === 0 ? [] : out;
    }

    const body = text ? (JSON.parse(text) as ListClassificationJobsResponse) : {};
    for (const job of body.items ?? []) {
      if (!job.jobId) continue;
      out.push({
        resourceTypeKey: 'macie_classification_job', resourceId: job.jobId, region: ctx.region,
        resourceName: job.name ?? job.jobId,
        state: job.jobStatus,
        metadata: {
          jobType: job.jobType,
          createdAt: job.createdAt,
          lastRunErrorStatus: job.lastRunErrorStatus?.code ?? null,
          userPausedDetails: job.userPausedDetails ?? null,
          bucketDefinitions: job.bucketDefinitions ?? [],
          usesBucketCriteria: job.bucketCriteria != null,
        },
      });
    }

    nextToken = body.nextToken;
    if (!nextToken) break;
  }
  return out;
}
