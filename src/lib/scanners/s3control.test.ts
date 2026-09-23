import { beforeEach, describe, expect, it, vi } from 'vitest';

const fetchMock = vi.fn();
vi.mock('aws4fetch', () => ({
  AwsClient: class {
    fetch(url: string, init?: RequestInit) {
      return fetchMock(url, init);
    }
  },
}));

import { accountPublicAccessBlockResource, jobItems, scanS3Control } from './s3control';

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ACCOUNT = '111122223333';

const ok = (body: string) => Promise.resolve(new Response(body, { status: 200 }));
const status = (code: number, body = '') => Promise.resolve(new Response(body, { status: code }));
const sts = () => ok(`<GetCallerIdentityResponse><GetCallerIdentityResult><Account>${ACCOUNT}</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`);

const PAB_XML = `<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`;

const job = (id: string, tag = 'member') =>
  `<${tag}><JobId>${id}</JobId><Operation>S3PutObjectTagging</Operation><Status>Complete</Status>` +
  `<ProgressSummary><TotalNumberOfTasks>10</TotalNumberOfTasks><NumberOfTasksSucceeded>9</NumberOfTasksSucceeded><NumberOfTasksFailed>1</NumberOfTasksFailed></ProgressSummary></${tag}>`;

function serve(handlers: { jobs?: (url: string) => Promise<Response>; pab?: () => Promise<Response>; sts?: () => Promise<Response> }) {
  fetchMock.mockImplementation((url: string) => {
    if (url.includes('sts.amazonaws.com')) return (handlers.sts ?? sts)();
    if (url.includes('/jobs')) return (handlers.jobs ?? (() => ok('<ListJobsResult><Jobs/></ListJobsResult>')))(url);
    if (url.includes('publicAccessBlock')) return (handlers.pab ?? (() => ok(PAB_XML)))();
    return status(404);
  });
}

beforeEach(() => { fetchMock.mockReset(); });

describe('S3 account public access evidence', () => {
  it('retains all four account-level guardrails', () => {
    const row = accountPublicAccessBlockResource('111122223333', `
      <PublicAccessBlockConfiguration>
        <BlockPublicAcls>true</BlockPublicAcls>
        <IgnorePublicAcls>true</IgnorePublicAcls>
        <BlockPublicPolicy>false</BlockPublicPolicy>
        <RestrictPublicBuckets>true</RestrictPublicBuckets>
      </PublicAccessBlockConfiguration>`);
    expect(row.resourceTypeKey).toBe('s3_account_public_access_block');
    expect(row.metadata).toMatchObject({ configured: true, blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: false, restrictPublicBuckets: true });
  });

  it('records a missing configuration as an explicit unsafe state', () => {
    expect(accountPublicAccessBlockResource('111122223333', '', false).metadata)
      .toEqual({ configured: false, blockPublicAcls: false, ignorePublicAcls: false, blockPublicPolicy: false, restrictPublicBuckets: false });
  });

  it('records a 404 NoSuchPublicAccessBlockConfiguration as configured:false', async () => {
    serve({ pab: () => status(404, '<Error><Code>NoSuchPublicAccessBlockConfiguration</Code></Error>') });
    const rows = await scanS3Control({ creds, region: 'us-east-1' });
    const pab = rows.find((r) => r.resourceTypeKey === 's3_account_public_access_block');
    expect(pab?.metadata).toMatchObject({ configured: false });
  });

  it('reports (and does not fabricate) the guardrail row when access is denied', async () => {
    const failures: { action?: string; normalizedCode?: string }[] = [];
    serve({ pab: () => status(403, '<Error><Code>AccessDenied</Code></Error>') });
    const rows = await scanS3Control({ creds: { ...creds, onCallFailure: (f: { action?: string; normalizedCode?: string }) => failures.push(f) }, region: 'us-east-1' });
    expect(rows.some((r) => r.resourceTypeKey === 's3_account_public_access_block')).toBe(false);
    expect(failures.some((f) => f.action === 'GetPublicAccessBlock' && f.normalizedCode === 'PERMISSION_DENIED')).toBe(true);
  });
});

describe('S3 Batch Operations jobs', () => {
  it('accepts both the <member> wire shape and the <JobListDescriptor> shape', () => {
    expect(jobItems(`<ListJobsResult><Jobs>${job('a')}</Jobs></ListJobsResult>`)).toHaveLength(1);
    expect(jobItems(`<ListJobsResult><Jobs>${job('b', 'JobListDescriptor')}</Jobs></ListJobsResult>`)).toHaveLength(1);
  });

  it('reads every page of ListJobs', async () => {
    serve({
      jobs: (url) => url.includes('nextToken=p2')
        ? ok(`<ListJobsResult><Jobs>${job('job-2')}</Jobs></ListJobsResult>`)
        : ok(`<ListJobsResult><NextToken>p2</NextToken><Jobs>${job('job-1')}</Jobs></ListJobsResult>`),
    });
    const rows = await scanS3Control({ creds, region: 'us-east-1' });
    expect(rows.filter((r) => r.resourceTypeKey === 's3_batch_job').map((r) => r.resourceId)).toEqual(['job-1', 'job-2']);
  });

  it('keeps job progress evidence', async () => {
    serve({ jobs: () => ok(`<ListJobsResult><Jobs>${job('job-1')}</Jobs></ListJobsResult>`) });
    const [row] = (await scanS3Control({ creds, region: 'us-east-1' })).filter((r) => r.resourceTypeKey === 's3_batch_job');
    expect(row.metadata).toMatchObject({ totalNumberOfTasks: 10, numberOfTasksFailed: 1 });
  });

  it('reports a failed ListJobs instead of returning a silently empty list', async () => {
    const failures: { action?: string }[] = [];
    serve({ jobs: () => status(500, '<Error><Code>InternalError</Code></Error>') });
    await scanS3Control({ creds: { ...creds, onCallFailure: (f: { action?: string }) => failures.push(f) }, region: 'us-east-1' });
    expect(failures.some((f) => f.action === 'ListJobs')).toBe(true);
  });

  it('reports truncation when AWS keeps repeating the same token', async () => {
    const failures: { action?: string; normalizedCode?: string }[] = [];
    serve({ jobs: () => ok(`<ListJobsResult><NextToken>same</NextToken><Jobs>${job('job-1')}</Jobs></ListJobsResult>`) });
    await scanS3Control({ creds: { ...creds, onCallFailure: (f: { action?: string; normalizedCode?: string }) => failures.push(f) }, region: 'us-east-1' });
    expect(failures.some((f) => f.action === 'ListJobs' && f.normalizedCode === 'PAGINATION_TRUNCATED')).toBe(true);
  });

  it('reports BOTH types as degraded when the account ID cannot be resolved', async () => {
    const failures: { action?: string }[] = [];
    serve({ sts: () => status(403, '<ErrorResponse/>') });
    const rows = await scanS3Control({ creds: { ...creds, onCallFailure: (f: { action?: string }) => failures.push(f) }, region: 'us-east-1' });
    expect(rows).toEqual([]);
    expect(failures.some((f) => f.action === 'ListJobs')).toBe(true);
    expect(failures.some((f) => f.action === 'GetPublicAccessBlock')).toBe(true);
  });

  it('survives a transport-level failure without throwing', async () => {
    serve({ jobs: () => Promise.reject(new Error('socket hang up')) });
    const rows = await scanS3Control({ creds, region: 'us-east-1' });
    expect(rows.some((r) => r.resourceTypeKey === 's3_account_public_access_block')).toBe(true);
  });
});