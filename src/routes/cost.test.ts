import { describe, it, expect } from 'vitest';
import { buildCostSnapshotRows, type SyncTarget } from './cost';

const connection: SyncTarget = { id: 'conn-1', aws_account_id: '111111111111' };

describe('buildCostSnapshotRows', () => {
  it('builds one row per non-zero service/day group', () => {
    const body = {
      ResultsByTime: [
        {
          TimePeriod: { Start: '2026-09-01', End: '2026-09-02' },
          Groups: [
            { Keys: ['Amazon EC2'], Metrics: { UnblendedCost: { Amount: '12.50', Unit: 'USD' } } },
            { Keys: ['Amazon S3'], Metrics: { UnblendedCost: { Amount: '0.75', Unit: 'USD' } } },
          ],
        },
      ],
    };
    const rows = buildCostSnapshotRows(body, connection);
    expect(rows).toEqual([
      { connection_id: 'conn-1', account_id: '111111111111', usage_date: '2026-09-01', service: 'Amazon EC2', unblended_cost: 12.5, currency: 'USD' },
      { connection_id: 'conn-1', account_id: '111111111111', usage_date: '2026-09-01', service: 'Amazon S3', unblended_cost: 0.75, currency: 'USD' },
    ]);
  });

  it('drops zero-cost rows -- AWS returns one row per service per day even at $0', () => {
    const body = {
      ResultsByTime: [
        { TimePeriod: { Start: '2026-09-01', End: '2026-09-02' }, Groups: [{ Keys: ['Amazon EC2'], Metrics: { UnblendedCost: { Amount: '0', Unit: 'USD' } } }] },
      ],
    };
    expect(buildCostSnapshotRows(body, connection)).toEqual([]);
  });

  it('falls back to "Unknown" service and "USD" currency when AWS omits them', () => {
    const body = {
      ResultsByTime: [
        { TimePeriod: { Start: '2026-09-01', End: '2026-09-02' }, Groups: [{ Keys: [], Metrics: { UnblendedCost: { Amount: '5', Unit: '' } } }] },
      ],
    };
    const rows = buildCostSnapshotRows(body, connection);
    expect(rows).toEqual([{ connection_id: 'conn-1', account_id: '111111111111', usage_date: '2026-09-01', service: 'Unknown', unblended_cost: 5, currency: 'USD' }]);
  });

  it('handles multiple days across ResultsByTime', () => {
    const body = {
      ResultsByTime: [
        { TimePeriod: { Start: '2026-09-01', End: '2026-09-02' }, Groups: [{ Keys: ['Amazon EC2'], Metrics: { UnblendedCost: { Amount: '10', Unit: 'USD' } } }] },
        { TimePeriod: { Start: '2026-09-02', End: '2026-09-03' }, Groups: [{ Keys: ['Amazon EC2'], Metrics: { UnblendedCost: { Amount: '11', Unit: 'USD' } } }] },
      ],
    };
    const rows = buildCostSnapshotRows(body, connection);
    expect(rows.map((r) => r.usage_date)).toEqual(['2026-09-01', '2026-09-02']);
  });

  it('returns an empty array for a response with no ResultsByTime at all', () => {
    expect(buildCostSnapshotRows({}, connection)).toEqual([]);
  });
});
