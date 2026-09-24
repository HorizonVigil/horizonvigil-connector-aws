import { beforeEach, describe, expect, it, vi } from 'vitest';

/** CodeBuild, CodeCommit, CodeDeploy, CodePipeline, CodeArtifact. */
const callJsonApiMock = vi.fn();
const fetchMock = vi.fn();
vi.mock('aws4fetch', () => ({
  AwsClient: class {
    fetch(url: string, init?: RequestInit) {
      return fetchMock(url, init);
    }
  },
}));
vi.mock('../awsApi', async (importOriginal: () => Promise<Record<string, unknown>>) => ({
  ...(await importOriginal()),
  callJsonApi: (...args: unknown[]) => callJsonApiMock(...args),
}));

import { projectEvidence, redactUrl, scanCodeBuild } from './codebuild';
import { scanCodeCommit } from './codecommit';
import { scanCodeDeploy } from './codedeploy';
import { pipelineEvidence, scanCodePipeline } from './codepipeline';
import { scanCodeArtifact } from './codeartifact';

type Req = { target: string; body: Record<string, unknown> };
type Failure = { action?: string };

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ctx = { creds, region: 'eu-west-1' };
const withSink = (failures: Failure[]) => ({ creds: { ...creds, onCallFailure: (f: Failure) => failures.push(f) }, region: 'eu-west-1' });
const ok = (body: unknown) => Promise.resolve({ ok: true, status: 200, body });
const denied = () => Promise.resolve({ ok: false, status: 400, body: null, errorCode: 'AccessDeniedException' });
const op = (req: Req) => req.target.split('.').pop();
const json = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status }));

beforeEach(() => { callJsonApiMock.mockReset(); fetchMock.mockReset(); });

describe('CodeBuild', () => {
  const names = Array.from({ length: 150 }, (_, i) => `p${i}`);

  it('describes EVERY project, in batches of 100 (it used to stop at 100)', async () => {
    const batches: number[] = [];
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'ListProjects') return req.body.nextToken === 't2' ? ok({ projects: names.slice(100) }) : ok({ projects: names.slice(0, 100), nextToken: 't2' });
      const batch = req.body.names as string[];
      batches.push(batch.length);
      return ok({ projects: batch.map((n) => ({ name: n, arn: `arn:cb:${n}` })) });
    });
    const out = await scanCodeBuild(ctx);
    expect(out).toHaveLength(150);
    expect(batches.sort()).toEqual([100, 50].sort());
  });

  it('keeps name-only rows for a failed batch and reports it', async () => {
    const failures: Failure[] = [];
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => (op(req) === 'ListProjects' ? ok({ projects: ['a'] }) : denied()));
    const [row] = await scanCodeBuild(withSink(failures));
    expect(row).toMatchObject({ resourceId: 'a', metadata: { detailsCollected: false } });
    expect(failures.some((f) => f.action === 'BatchGetProjects')).toBe(true);
  });

  it('records FSBP CodeBuild evidence without storing secrets', () => {
    const e = projectEvidence({
      name: 'build',
      source: { type: 'GITHUB', location: 'https://ghp_SECRET123@github.com/org/repo.git' },
      environment: { privilegedMode: true, environmentVariables: [{ name: 'AWS_SECRET_ACCESS_KEY', value: 'wJalr', type: 'PLAINTEXT' }, { name: 'DB_PASSWORD', value: 'x', type: 'SECRETS_MANAGER' }] },
      projectVisibility: 'PUBLIC_READ',
      logsConfig: { cloudWatchLogs: { status: 'DISABLED' } },
      artifacts: { encryptionDisabled: true },
    });
    expect(e).toMatchObject({
      sourceLocationHasCredentials: true, privilegedMode: true, isPublic: true, cloudWatchLogsEnabled: false,
      artifactsEncryptionDisabled: true, plaintextSecretLikeEnvNames: ['AWS_SECRET_ACCESS_KEY'],
    });
    const serialized = JSON.stringify(e);
    expect(serialized.includes('ghp_SECRET123')).toBe(false);
    expect(serialized.includes('wJalr')).toBe(false);
    expect(redactUrl('https://user:pw@host/x')).toBe('https://***@host/x');
  });
});

describe('CodeCommit / CodeDeploy', () => {
  it('CodeCommit describes every repository in batches of 25', async () => {
    const repos = Array.from({ length: 30 }, (_, i) => ({ repositoryName: `r${i}`, repositoryId: `id${i}` }));
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'ListRepositories') return ok({ repositories: repos });
      return ok({ repositories: (req.body.repositoryNames as string[]).map((n) => ({ repositoryName: n, repositoryId: `id-${n}`, Arn: `arn:cc:${n}` })) });
    });
    expect(await scanCodeCommit(ctx)).toHaveLength(30);
  });

  it('CodeCommit reports a failed batch instead of returning [] for everything', async () => {
    const failures: Failure[] = [];
    let call = 0;
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'ListRepositories') return ok({ repositories: Array.from({ length: 30 }, (_, i) => ({ repositoryName: `r${i}`, repositoryId: `id${i}` })) });
      call += 1;
      return call === 1 ? denied() : ok({ repositories: (req.body.repositoryNames as string[]).map((n) => ({ repositoryName: n, repositoryId: n, Arn: `arn:${n}` })) });
    });
    const out = await scanCodeCommit(withSink(failures));
    expect(out.length).toBeGreaterThan(0);
    expect(failures.some((f) => f.action === 'BatchGetRepositories')).toBe(true);
  });

  it('CodeDeploy reads every page and never asserts a missing name', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'ListApplications') return req.body.nextToken === 't2' ? ok({ applications: ['b'] }) : ok({ applications: ['a'], nextToken: 't2' });
      return ok({ applicationsInfo: [{ applicationId: 'app-a', applicationName: 'a' }, { applicationId: 'app-b', applicationName: 'b' }, {}] });
    });
    const out = await scanCodeDeploy(ctx);
    expect(out.map((r) => r.resourceId)).toEqual(['app-a', 'app-b', '']);
    expect((callJsonApiMock.mock.calls.find((c: unknown[]) => op(c[1] as Req) === 'BatchGetApplications')?.[1] as Req).body.applicationNames).toEqual(['a', 'b']);
  });
});

describe('CodePipeline', () => {
  it('flags deprecated GitHub v1 OAuth sources and missing customer KMS', () => {
    const e = pipelineEvidence({
      roleArn: 'arn:role', artifactStore: { type: 'S3', location: 'bucket' },
      stages: [{ name: 'Source', actions: [{ actionTypeId: { category: 'Source', owner: 'ThirdParty', provider: 'GitHub' } }] }],
    });
    expect(e).toMatchObject({ detailsCollected: true, usesGitHubV1OAuth: true, artifactStoreCustomerKms: false, sourceProviders: ['GitHub'] });
  });

  it('reads every page of pipelines', async () => {
    callJsonApiMock.mockImplementation((_c: unknown, req: Req) => {
      if (op(req) === 'ListPipelines') return req.body.nextToken === 't2' ? ok({ pipelines: [{ name: 'b' }] }) : ok({ pipelines: [{ name: 'a' }], nextToken: 't2' });
      return ok({ pipeline: { name: req.body.name, roleArn: 'arn:role' } });
    });
    const out = await scanCodePipeline(ctx);
    expect(out.map((r) => r.resourceId)).toEqual(['a', 'b']);
    expect(out[0].relationships?.roleArn).toBe('arn:role');
  });
});

describe('CodeArtifact', () => {
  it('reads every page and records a public repository policy', async () => {
    fetchMock.mockImplementation((url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
      if (url.endsWith('/v1/repositories')) {
        return body.nextToken === 't2'
          ? json({ repositories: [{ name: 'r2', domainName: 'd', arn: 'arn:aws:codeartifact:eu-west-1:111122223333:repository/d/r2' }] })
          : json({ repositories: [{ name: 'r1', domainName: 'd', arn: 'arn:aws:codeartifact:eu-west-1:111122223333:repository/d/r1' }], nextToken: 't2' });
      }
      if (url.endsWith('/v1/domains')) return json({ domains: [{ name: 'd', encryptionKey: 'arn:kms:k' }] });
      if (url.includes('repository=r1')) return json({ policy: { document: JSON.stringify({ Statement: [{ Effect: 'Allow', Principal: '*', Action: 'codeartifact:ReadFromRepository' }] }) } });
      return json({}, 404);
    });
    const out = await scanCodeArtifact(ctx);
    expect(out.map((r) => r.resourceName)).toEqual(['r1', 'r2']);
    expect(out[0].metadata).toMatchObject({ hasResourcePolicy: true, resourcePolicy: { allowsAnonymous: true } });
    expect(out[1].metadata).toMatchObject({ policyCollected: true, hasResourcePolicy: false });
  });
});