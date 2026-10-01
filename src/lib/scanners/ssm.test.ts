import { beforeEach, describe, expect, it, vi } from 'vitest';

const callJsonApiMock = vi.fn();
vi.mock('../awsApi', async (importOriginal: () => Promise<Record<string, unknown>>) => ({
  ...(await importOriginal()),
  callJsonApi: (...args: unknown[]) => callJsonApiMock(...args),
}));

import { scanSsm } from './ssm';
import type { AwsCallFailure } from '../awsApi';

type Req = { target: string; body: Record<string, unknown> };
const ok = (body: Record<string, unknown>) => Promise.resolve({ ok: true, status: 200, body });
const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };

beforeEach(() => { callJsonApiMock.mockReset(); });

describe('Systems Manager production collection', () => {
  it('paginates every list and preserves resources from all pages', async () => {
    callJsonApiMock.mockImplementation((...args: unknown[]) => {
      const req = args.find((arg): arg is Req => !!arg && typeof arg === 'object' && 'target' in arg);
      if (!req) throw new Error('AWS request was not supplied to callJsonApi');
      const action = req.target.split('.').at(-1)!;
      const second = req.body.NextToken === 'page-2';
      const shapes: Record<string, [string, unknown]> = {
        DescribeParameters: ['Parameters', [{ Name: second ? '/two' : '/one' }]],
        DescribeAutomationExecutions: ['AutomationExecutionMetadataList', [{ AutomationExecutionId: second ? 'a2' : 'a1' }]],
        ListDocuments: ['DocumentIdentifiers', [{ Name: second ? 'd2' : 'd1' }]],
        DescribeInstanceInformation: ['InstanceInformationList', [{ InstanceId: second ? 'i-2' : 'i-1' }]],
        DescribeMaintenanceWindows: ['WindowIdentities', [{ WindowId: second ? 'mw-2' : 'mw-1' }]],
        DescribePatchBaselines: ['BaselineIdentities', [{ BaselineId: second ? 'pb-2' : 'pb-1', BaselineName: second ? 'Custom2' : 'Custom1' }]],
        GetInventory: ['Entities', [{ Id: second ? 'i-2' : 'i-1', Data: { 'AWS:Application': {} } }]],
      };
      const [key, items] = shapes[action];
      return ok({ [key]: items, ...(second ? {} : { NextToken: 'page-2' }) });
    });

    const out = await scanSsm({ creds, region: 'eu-west-1' });
    expect(out.filter((r) => r.resourceTypeKey === 'ssm_parameter').map((r) => r.resourceName)).toEqual(['/one', '/two']);
    expect(callJsonApiMock).toHaveBeenCalledTimes(14);
  });

  it('reports an incomplete walk so missing pages cannot be treated as deletions', async () => {
    const failures: AwsCallFailure[] = [];
    callJsonApiMock.mockImplementation((...args: unknown[]) => {
      const req = args.find((arg): arg is Req => !!arg && typeof arg === 'object' && 'target' in arg);
      if (!req) throw new Error('AWS request was not supplied to callJsonApi');
      const action = req.target.split('.').at(-1)!;
      if (action === 'DescribeParameters') return ok({ Parameters: [{ Name: '/one' }], NextToken: 'same' });
      return ok({});
    });

    const out = await scanSsm({
      creds: { ...creds, onCallFailure: (failure) => { failures.push(failure); } },
      region: 'eu-west-1',
    });
    expect(out.some((r) => r.resourceName === '/one')).toBe(true);
    expect(failures.some((f) => f.service === 'ssm' && f.action === 'DescribeParameters' && f.normalizedCode === 'PAGINATION_TRUNCATED')).toBe(true);
  });
});
