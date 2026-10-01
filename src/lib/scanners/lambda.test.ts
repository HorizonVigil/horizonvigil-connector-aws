import { beforeEach, describe, expect, it, vi } from 'vitest';

const fetchMock = vi.fn();
vi.mock('aws4fetch', () => ({
  AwsClient: class { fetch(url: string, init?: RequestInit) { return fetchMock(url, init); } },
}));

import { scanLambda } from './lambda';
import type { AwsCallFailure } from '../awsApi';

const json = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status }));
const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };

beforeEach(() => { fetchMock.mockReset(); });

describe('Lambda production collection', () => {
  it('reads every page of functions, event-source mappings, and layers', async () => {
    fetchMock.mockImplementation((url: string) => {
      const u = new URL(url);
      const second = u.searchParams.get('Marker') === 'next';
      if (u.pathname.includes('/functions/')) return json({ Functions: [{ FunctionName: second ? 'fn-2' : 'fn-1' }], ...(second ? {} : { NextMarker: 'next' }) });
      if (u.pathname.includes('/event-source-mappings/')) return json({ EventSourceMappings: [{ UUID: second ? 'esm-2' : 'esm-1' }], ...(second ? {} : { NextMarker: 'next' }) });
      if (u.pathname.includes('/layers')) return json({ Layers: [{ LayerName: second ? 'layer-2' : 'layer-1' }], ...(second ? {} : { NextMarker: 'next' }) });
      return json({}, 404);
    });

    const out = await scanLambda({ creds, region: 'us-east-1' });
    expect(out.filter((r) => r.resourceTypeKey === 'lambda_function').map((r) => r.resourceName)).toEqual(['fn-1', 'fn-2']);
    expect(out.filter((r) => r.resourceTypeKey === 'lambda_event_source_mapping')).toHaveLength(2);
    expect(out.filter((r) => r.resourceTypeKey === 'lambda_layer').map((r) => r.resourceName)).toEqual(['layer-1', 'layer-2']);
    expect(fetchMock).toHaveBeenCalledTimes(6);
  });

  it('reports a failed or truncated list and keeps successfully read rows', async () => {
    const failures: AwsCallFailure[] = [];
    fetchMock.mockImplementation((url: string) => {
      const u = new URL(url);
      if (u.pathname.includes('/functions/')) return json({ Functions: [{ FunctionName: 'fn-1' }], NextMarker: 'same' });
      if (u.pathname.includes('/event-source-mappings/')) return json({}, 403);
      return json({ Layers: [] });
    });

    const out = await scanLambda({ creds: { ...creds, onCallFailure: (f) => { failures.push(f); } }, region: 'us-east-1' });
    expect(out.some((r) => r.resourceName === 'fn-1')).toBe(true);
    expect(failures.some((f) => f.action === 'ListFunctions' && f.normalizedCode === 'PAGINATION_TRUNCATED')).toBe(true);
    expect(failures.some((f) => f.action === 'ListEventSourceMappings' && f.normalizedCode === 'PERMISSION_DENIED')).toBe(true);
  });
});
