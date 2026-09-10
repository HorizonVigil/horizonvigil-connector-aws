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
    const { rows } = buildCostSnapshotRows(body, connection);
    /**
     * Amounts are now the exact decimal STRING AWS sent, not `Number(...)`.
     * This assertion is STRONGER than the one it replaces (which expected
     * 12.5): `cost_snapshots.unblended_cost` is Postgres `numeric` and was
     * being handed an already-lossy double, so precision was lost before the
     * value ever reached the exact column meant to hold it. '12.50' also
     * preserves the scale AWS reported, which '12.5' would not.
     */
    expect(rows).toEqual([
      { connection_id: 'conn-1', account_id: '111111111111', usage_date: '2026-09-01', service: 'Amazon EC2', unblended_cost: '12.50', currency: 'USD' },
      { connection_id: 'conn-1', account_id: '111111111111', usage_date: '2026-09-01', service: 'Amazon S3', unblended_cost: '0.75', currency: 'USD' },
    ]);
  });

  it('skips zero-cost rows but COUNTS them, so the omission is not silent', () => {
    /**
     * AWS returns a row per service per day including every service billing
     * nothing, so storing them would multiply this table by an order of
     * magnitude. Skipping is a deliberate storage trade-off -- but it means
     * the stored row count is NOT the number of rows AWS returned, so it
     * cannot on its own establish a proven zero or satisfy an
     * observed-vs-expected reconciliation. The count makes that difference
     * recoverable instead of lost.
     */
    const body = {
      ResultsByTime: [
        { TimePeriod: { Start: '2026-09-01', End: '2026-09-02' }, Groups: [
          { Keys: ['Amazon EC2'], Metrics: { UnblendedCost: { Amount: '0', Unit: 'USD' } } },
          { Keys: ['Amazon S3'], Metrics: { UnblendedCost: { Amount: '0.000', Unit: 'USD' } } },
        ] },
      ],
    };
    const built = buildCostSnapshotRows(body, connection);
    expect(built.rows).toEqual([]);
    expect(built.zeroCostRowsSkipped).toBe(2);
    expect(built.unreadableRows).toBe(0);
  });

  it('never turns an unreadable amount into zero', () => {
    /**
     * This previously read `Number(amount ?? 0)`: a missing amount became 0,
     * and the zero-filter then dropped the row entirely -- so a value AWS
     * failed to report vanished without trace. An amount we could not read is
     * not an amount of nothing.
     */
    const body = {
      ResultsByTime: [
        { TimePeriod: { Start: '2026-09-01', End: '2026-09-02' }, Groups: [
          { Keys: ['Amazon EC2'], Metrics: {} as never },
          { Keys: ['Amazon S3'], Metrics: { UnblendedCost: { Amount: 'not-a-number', Unit: 'USD' } } },
        ] },
      ],
    };
    const built = buildCostSnapshotRows(body, connection);
    expect(built.rows).toEqual([]);
    expect(built.unreadableRows).toBe(2);
    expect(built.zeroCostRowsSkipped).toBe(0);
  });

  it('preserves sub-cent precision that a double would round away', () => {
    const body = {
      ResultsByTime: [
        { TimePeriod: { Start: '2026-09-01', End: '2026-09-02' }, Groups: [
          { Keys: ['AWS Lambda'], Metrics: { UnblendedCost: { Amount: '0.0000001234', Unit: 'USD' } } },
        ] },
      ],
    };
    const { rows } = buildCostSnapshotRows(body, connection);
    expect(rows[0].unblended_cost).toBe('0.0000001234');
  });

  it('falls back to "Unknown" service and "USD" currency when AWS omits them', () => {
    const body = {
      ResultsByTime: [
        { TimePeriod: { Start: '2026-09-01', End: '2026-09-02' }, Groups: [{ Keys: [], Metrics: { UnblendedCost: { Amount: '5', Unit: '' } } }] },
      ],
    };
    const { rows } = buildCostSnapshotRows(body, connection);
    expect(rows).toEqual([{ connection_id: 'conn-1', account_id: '111111111111', usage_date: '2026-09-01', service: 'Unknown', unblended_cost: '5', currency: 'USD' }]);
  });

  it('handles multiple days across ResultsByTime', () => {
    const body = {
      ResultsByTime: [
        { TimePeriod: { Start: '2026-09-01', End: '2026-09-02' }, Groups: [{ Keys: ['Amazon EC2'], Metrics: { UnblendedCost: { Amount: '10', Unit: 'USD' } } }] },
        { TimePeriod: { Start: '2026-09-02', End: '2026-09-03' }, Groups: [{ Keys: ['Amazon EC2'], Metrics: { UnblendedCost: { Amount: '11', Unit: 'USD' } } }] },
      ],
    };
    const { rows } = buildCostSnapshotRows(body, connection);
    expect(rows.map((r) => r.usage_date)).toEqual(['2026-09-01', '2026-09-02']);
  });

  it('returns an empty array for a response with no ResultsByTime at all', () => {
    expect(buildCostSnapshotRows({}, connection).rows).toEqual([]);
  });
});
