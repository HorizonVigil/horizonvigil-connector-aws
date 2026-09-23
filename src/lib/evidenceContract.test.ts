import { describe, expect, it } from 'vitest';
import { costSourceEvidence, inventoryEvidence, normalizedCapabilityState } from './evidenceContract';

describe('AWS Advisor evidence contract', () => {
  it('never promotes a degraded successful scan to authoritative inventory', () => {
    const evidence = inventoryEvidence({
      orgId: 'org-1', connectionId: 'conn-1', awsAccountId: '123456789012', retrievedAt: '2026-09-22T12:00:00Z', now: Date.parse('2026-09-22T12:00:00Z'),
      run: { id: 'run-1', status: 'SUCCEEDED', total_steps: 1628, completed_steps: 1628, failed_steps: 0, degraded_resource_types: ['ec2_instance'], finished_at: '2026-09-22T11:00:00Z', started_at: '2026-09-22T10:00:00Z' },
    });
    expect(evidence.capabilityState).toBe('partial');
    expect(evidence.completeness).toBe('partial');
    expect(evidence.limitation).toContain('lower bounds');
  });

  it('decays an otherwise available capability to stale', () => {
    expect(normalizedCapabilityState('available', 'stale')).toBe('stale');
    expect(normalizedCapabilityState('available', 'unknown')).toBe('unknown');
  });

  it('does not describe an unconfigured billing source as verified zero', () => {
    const evidence = costSourceEvidence({
      orgId: 'org-1', connectionId: 'conn-1', awsAccountId: '123456789012', retrievedAt: '2026-09-22T12:00:00Z',
      row: { source_type: 'COST_EXPLORER', state: 'NOT_CONFIGURED', reason_code: 'cost_explorer_not_enabled', covered_period_start: null, covered_period_end: null, last_attempt_at: '2026-09-22T11:00:00Z', last_success_at: null, source_observed_at: null, freshness_slo_seconds: 172800, record_count: null, updated_at: '2026-09-22T11:00:00Z' },
    });
    expect(evidence.capabilityState).toBe('not_enabled');
    expect(evidence.limitation).toContain('numeric zero is not verified');
  });
});
