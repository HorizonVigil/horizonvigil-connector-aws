import { describe, it, expect } from 'vitest';
import { readinessFromProbe } from './costReadiness';

/**
 * AWS-13. "Cost Explorer, account-owner action" is not an actionable
 * statement — these states each imply a DIFFERENT remedy, and conflating
 * them sends someone to fix the wrong thing.
 */
describe('readinessFromProbe', () => {
  it('granted is READY with nothing to do', () => {
    const r = readinessFromProbe('granted', 'Read access to Cost Explorer confirmed');
    expect(r.state).toBe('READY');
    expect(r.requiredAction).toBeNull();
  });

  /**
   * The distinction that matters most, and the one this account actually
   * hits. Reporting it as PERMISSION_DENIED would send an engineer to widen
   * an IAM policy that is already correct.
   */
  it('"not enabled" is an ACCOUNT setting, not an IAM problem', () => {
    const r = readinessFromProbe('not_applicable', 'Cost Explorer is not enabled for this AWS account. Enable it in the Billing console; data appears within ~24 hours.');
    expect(r.state).toBe('NOT_ENABLED');
    expect(r.requiredAction).toMatch(/Billing/);
    expect(r.requiredAction).toMatch(/not an IAM permission/);
    expect(r.actionOwner).toMatch(/root user|ModifyBilling/);
  });

  it('distinguishes a genuine permission denial from non-enablement', () => {
    const r = readinessFromProbe('denied', 'AccessDeniedException');
    expect(r.state).toBe('PERMISSION_DENIED');
    expect(r.requiredAction).toMatch(/ce:GetCostAndUsage/);
    expect(r.requiredAction).toMatch(/IAM POLICY/);
  });

  /** Enabled but unpopulated needs no action at all — saying otherwise sends someone chasing nothing. */
  it('awaiting data requires no action', () => {
    const r = readinessFromProbe('not_applicable', 'Cost Explorer has not accumulated data for this account yet');
    expect(r.state).toBe('AWAITING_DATA');
    expect(r.requiredAction).toMatch(/No action/);
  });

  it('an unrecognised verdict is UNKNOWN, never READY', () => {
    const r = readinessFromProbe('error', 'some novel failure');
    expect(r.state).toBe('UNKNOWN');
    expect(r.state).not.toBe('READY');
  });

  /** The four remedies must not collapse into one another. */
  it('every state maps to a distinct remedy', () => {
    const states = [
      readinessFromProbe('granted', 'ok').state,
      readinessFromProbe('not_applicable', 'not enabled for cost explorer').state,
      readinessFromProbe('denied', 'AccessDenied').state,
      readinessFromProbe('not_applicable', 'has not accumulated data').state,
    ];
    expect(new Set(states).size).toBe(4);
  });
});
