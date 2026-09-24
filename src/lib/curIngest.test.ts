import { describe, expect, it, vi } from 'vitest';

vi.mock('./awsApi', () => ({
  createAwsClient: vi.fn(() => ({})),
  safeFetch: vi.fn(),
  callJsonApi: vi.fn(),
}));

import { safeFetch } from './awsApi';
import { parseCurBatch } from './curIngest';

describe('parseCurBatch', () => {
  it('preserves a quoted newline instead of shifting subsequent CUR columns', async () => {
    const csv = [
      'lineItem/LineItemDescription,lineItem/ResourceId,lineItem/UnblendedCost,lineItem/UsageStartDate',
      '"first line\nsecond line",i-123,1.25,2026-09-01T00:00:00Z',
    ].join('\n');
    vi.mocked(safeFetch).mockResolvedValue(new Response(csv));

    const result = await parseCurBatch(
      { accessKeyId: 'AKIA0000000000000000', secretAccessKey: 'secret' },
      'cur-bucket',
      'us-east-1',
      'report.csv',
      0,
    );

    expect(result).toEqual({
      done: true,
      rowsProcessed: 1,
      rowsIngestedThisBatch: 1,
      costRows: [{ resource_id: 'i-123', service: 'unknown', region: null, usage_date: '2026-09-01', unblended_cost: 1.25 }],
    });
  });

  it('keeps quoted records intact when the field crosses response chunks', async () => {
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode('lineItem/LineItemDescription,lineItem/ResourceId,lineItem/UnblendedCost,lineItem/UsageStartDate\n"first'));
        controller.enqueue(encoder.encode(' line\nsecond line",i-456,2.5,2026-09-02T00:00:00Z\n'));
        controller.close();
      },
    });
    vi.mocked(safeFetch).mockResolvedValue(new Response(stream));

    const result = await parseCurBatch(
      { accessKeyId: 'AKIA0000000000000000', secretAccessKey: 'secret' },
      'cur-bucket', 'us-east-1', 'report.csv', 0,
    );

    expect(result).toMatchObject({ done: true, rowsProcessed: 1, rowsIngestedThisBatch: 1 });
    expect('costRows' in result && result.costRows[0]).toMatchObject({ resource_id: 'i-456', unblended_cost: 2.5 });
  });

  it('fails explicitly when the report does not have the columns needed for resource cost attribution', async () => {
    vi.mocked(safeFetch).mockResolvedValue(new Response('lineItem/ResourceId\ni-123'));

    await expect(parseCurBatch(
      { accessKeyId: 'AKIA0000000000000000', secretAccessKey: 'secret' },
      'cur-bucket', 'us-east-1', 'report.csv', 0,
    )).resolves.toEqual({ error: 'CUR file is missing required columns: lineItem/UnblendedCost, lineItem/UsageStartDate' });
  });
});
