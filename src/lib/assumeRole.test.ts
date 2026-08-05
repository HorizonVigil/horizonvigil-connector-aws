import { describe, it, expect, vi, afterEach } from 'vitest';
import { assumeConnectionRole } from './assumeRole';

const ROLE_ARN = 'arn:aws:iam::123456789012:role/cloudops360-readonly';
const EXTERNAL_ID = 'ext-abc123';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('assumeConnectionRole', () => {
  it('returns an honest ok:false when platform credentials are not configured, without making a network call', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    const result = await assumeConnectionRole({}, ROLE_ARN, EXTERNAL_ID);

    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/not configured/i);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('returns an honest ok:false when only one of the two credential fields is set', async () => {
    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST' }, ROLE_ARN, EXTERNAL_ID);
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/not configured/i);
  });

  it('surfaces the AWS error Code/Message when STS returns a non-ok response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      '<ErrorResponse><Error><Code>AccessDenied</Code><Message>User is not authorized to perform sts:AssumeRole</Message></Error></ErrorResponse>',
      { status: 403 },
    )));

    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST', secretAccessKey: 'secret' }, ROLE_ARN, EXTERNAL_ID);

    expect(result.ok).toBe(false);
    expect(result.reason).toBe('User is not authorized to perform sts:AssumeRole');
  });

  it('falls back to the Code and HTTP status when the error response has no Message', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      '<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>',
      { status: 403 },
    )));

    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST', secretAccessKey: 'secret' }, ROLE_ARN, EXTERNAL_ID);

    expect(result.ok).toBe(false);
    expect(result.reason).toBe('AssumeRole failed (AccessDenied)');
  });

  it('returns ok:false when the response is 200 but missing expected credential fields', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      '<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>AKIAABC</AccessKeyId></Credentials></AssumeRoleResult></AssumeRoleResponse>',
      { status: 200 },
    )));

    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST', secretAccessKey: 'secret' }, ROLE_ARN, EXTERNAL_ID);

    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/missing expected credential fields/);
  });

  it('returns the temporary credentials on a well-formed success response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      '<AssumeRoleResponse><AssumeRoleResult><Credentials>' +
      '<AccessKeyId>AKIAABC</AccessKeyId><SecretAccessKey>secretXYZ</SecretAccessKey><SessionToken>tok123</SessionToken>' +
      '</Credentials></AssumeRoleResult></AssumeRoleResponse>',
      { status: 200 },
    )));

    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST', secretAccessKey: 'secret' }, ROLE_ARN, EXTERNAL_ID);

    expect(result.ok).toBe(true);
    expect(result.credentials).toEqual({ accessKeyId: 'AKIAABC', secretAccessKey: 'secretXYZ', sessionToken: 'tok123' });
  });

  it('returns an honest ok:false when the request itself throws', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network unreachable')));

    const result = await assumeConnectionRole({ accessKeyId: 'AKIATEST', secretAccessKey: 'secret' }, ROLE_ARN, EXTERNAL_ID);

    expect(result.ok).toBe(false);
    expect(result.reason).toBe('network unreachable');
  });
});
