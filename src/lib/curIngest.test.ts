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

    const result = await parseCurBatch(
      { accessKeyId: 'AKIA0000000000000000', secretAccessKey: 'secret' },
      'cur-bucket', 'us-east-1', 'report.csv', 0,
    );

    // Still names the columns that are missing -- now for BOTH generations,
    // because a file that matches neither could be either one misconfigured.
    expect(result).toHaveProperty('error');
    const { error } = result as { error: string };
    expect(error).toContain('lineItem/UnblendedCost');
    expect(error).toContain('lineItem/UsageStartDate');
    expect(error).toContain('line_item_unblended_cost');
    // The overwhelmingly common real cause, and it is fixed in the Billing
    // console rather than here.
    expect(error).toContain('Include resource IDs');
  });

  /**
   * CUR 2.0 (Data Exports) is what templates/horizonvigil-cur-setup.yaml
   * creates, and its columns are snake_case. Before this, parseCurBatch
   * hardcoded the v1 spellings, so the report our own CloudFormation produces
   * was unreadable by our own ingester.
   */
  it('reads a CUR 2.0 header and produces the same cost rows as v1', async () => {
    const csv = [
      'bill_billing_period_start_date,line_item_usage_account_id,line_item_product_code,line_item_resource_id,line_item_unblended_cost,line_item_usage_start_date,product_servicecode,product_region_code',
      '2026-09-01,111122223333,AmazonEC2,arn:aws:ec2:us-east-1:111122223333:instance/i-0abc,41.30,2026-09-14T00:00:00Z,AmazonEC2,us-east-1',
    ].join('\n');
    vi.mocked(safeFetch).mockResolvedValue(new Response(csv));

    const result = await parseCurBatch(
      { accessKeyId: 'AKIA0000000000000000', secretAccessKey: 'secret' },
      'cur-bucket', 'us-east-1', 'report.csv.gz'.replace('.gz', ''), 0,
    );

    expect(result).toMatchObject({ done: true, rowsProcessed: 1, rowsIngestedThisBatch: 1 });
    expect('costRows' in result && result.costRows[0]).toEqual({
      // The ARN is reduced to the bare id so it joins to cloud_resources.
      resource_id: 'i-0abc',
      service: 'AmazonEC2',
      region: 'us-east-1',
      usage_date: '2026-09-14',
      unblended_cost: 41.3,
    });
  });

  it('does not confuse a v2 file for a v1 one when only some columns overlap', async () => {
    // line_item_resource_id present but the cost/date columns are v1-spelled:
    // a genuinely malformed file, which must be rejected rather than
    // half-read into rows with undefined costs.
    vi.mocked(safeFetch).mockResolvedValue(new Response('line_item_resource_id,lineItem/UnblendedCost\ni-1,5'));

    const result = await parseCurBatch(
      { accessKeyId: 'AKIA0000000000000000', secretAccessKey: 'secret' },
      'cur-bucket', 'us-east-1', 'report.csv', 0,
    );
    expect(result).toHaveProperty('error');
  });
});
