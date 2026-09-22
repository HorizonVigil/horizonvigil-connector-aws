import { describe, it, expect, vi, beforeEach } from 'vitest';

const fetchMock = vi.fn();
vi.mock('aws4fetch', () => ({
  AwsClient: class {
    fetch(url: string, init?: RequestInit) {
      return fetchMock(url, init);
    }
  },
}));

import {
  checkGuardDuty, checkInspector, checkAccessAnalyzer, checkEcs, checkAwsHealth, checkCur,
} from './permissionProbesExtra';
import { stateFromCheck } from './capabilityMatrix';

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const REGION = 'eu-west-1';

const json = (body: unknown, status = 200) =>
  Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }));

const denied = () =>
  Promise.resolve(new Response(JSON.stringify({ __type: 'AccessDeniedException', message: 'not allowed' }), { status: 403 }));

beforeEach(() => { fetchMock.mockReset(); });

/**
 * The property every one of these probes exists to hold: an ENABLEMENT answer
 * must never be reported as a PERMISSION answer. `permission_denied` sends a
 * customer to edit an IAM policy; `not_enabled` sends them to switch a service
 * on. Each test below asserts the probe status AND the capability state it
 * maps to, because the mapping is what the product actually shows.
 */
describe('GuardDuty', () => {
  it('reads an empty detector list as not enabled, never as clean', () => {
    // GuardDuty answers 200 with no detectors when it was never enabled.
    // Reporting "no threats" for an account it never watched is the exact
    // false-clean this phase removes.
    fetchMock.mockImplementation(() => json({ detectorIds: [] }));

    return checkGuardDuty(creds, REGION).then((r) => {
      expect(r.status).toBe('not_applicable');
      expect(r.detail).toMatch(/not enabled/i);
      expect(stateFromCheck(r)).toBe('not_enabled');
    });
  });

  it('is available when a detector exists', async () => {
    fetchMock.mockImplementation(() => json({ detectorIds: ['d-1'] }));
    const r = await checkGuardDuty(creds, REGION);
    expect(r.status).toBe('granted');
    expect(stateFromCheck(r)).toBe('available');
  });

  it('separates an IAM denial from being switched off', async () => {
    fetchMock.mockImplementation(() => denied());
    const r = await checkGuardDuty(creds, REGION);
    expect(r.status).toBe('denied');
    expect(stateFromCheck(r)).toBe('permission_denied');
  });

  it('calls an AWS outage service_unavailable, not the customer fault', async () => {
    fetchMock.mockImplementation(() => json({}, 503));
    expect(stateFromCheck(await checkGuardDuty(creds, REGION))).toBe('service_unavailable');
  });
});

describe('Inspector', () => {
  it('reads a DISABLED account status as not enabled', async () => {
    fetchMock.mockImplementation(() => json({ accounts: [{ state: { status: 'DISABLED' } }] }));
    const r = await checkInspector(creds, REGION);
    expect(r.status).toBe('not_applicable');
    expect(stateFromCheck(r)).toBe('not_enabled');
  });

  it('reads SUSPENDED as not enabled too', async () => {
    fetchMock.mockImplementation(() => json({ accounts: [{ state: { status: 'SUSPENDED' } }] }));
    expect(stateFromCheck(await checkInspector(creds, REGION))).toBe('not_enabled');
  });

  it('is available only when ENABLED', async () => {
    fetchMock.mockImplementation(() => json({ accounts: [{ state: { status: 'ENABLED' } }] }));
    expect(stateFromCheck(await checkInspector(creds, REGION))).toBe('available');
  });

  it('separates denial from disablement', async () => {
    fetchMock.mockImplementation(() => denied());
    expect(stateFromCheck(await checkInspector(creds, REGION))).toBe('permission_denied');
  });
});

describe('IAM Access Analyzer', () => {
  it('reads no analyzer as not enabled — findings cannot exist without one', async () => {
    fetchMock.mockImplementation(() => json({ analyzers: [] }));
    const r = await checkAccessAnalyzer(creds, REGION);
    expect(stateFromCheck(r)).toBe('not_enabled');
    expect(r.detail).toMatch(/no analyzer exists/i);
  });

  it('is available when an analyzer exists', async () => {
    fetchMock.mockImplementation(() => json({ analyzers: [{ name: 'a' }] }));
    expect(stateFromCheck(await checkAccessAnalyzer(creds, REGION))).toBe('available');
  });

  it('separates denial from absence', async () => {
    fetchMock.mockImplementation(() => denied());
    expect(stateFromCheck(await checkAccessAnalyzer(creds, REGION))).toBe('permission_denied');
  });
});

/**
 * ECS is deliberately NOT like GuardDuty: there is nothing to enable. A
 * readable account with no clusters is an authoritative zero, and calling it
 * not_enabled would destroy the distinction the container screens need between
 * "no clusters" and "we could not look".
 */
describe('ECS', () => {
  it('treats an empty cluster list as an AUTHORITATIVE zero, not as disabled', async () => {
    fetchMock.mockImplementation(() => json({ clusterArns: [] }));
    const r = await checkEcs(creds, REGION);

    expect(r.status).toBe('granted');
    expect(stateFromCheck(r)).toBe('available');
    expect(r.detail).toMatch(/0 cluster/);
  });

  it('is available with clusters', async () => {
    fetchMock.mockImplementation(() => json({ clusterArns: ['arn:aws:ecs:::cluster/a'] }));
    expect(stateFromCheck(await checkEcs(creds, REGION))).toBe('available');
  });

  it('separates a denial from an empty account', async () => {
    fetchMock.mockImplementation(() => denied());
    expect(stateFromCheck(await checkEcs(creds, REGION))).toBe('permission_denied');
  });
});

describe('AWS Health', () => {
  /**
   * No policy edit buys a Business support plan, so this must be
   * `unsupported`, not `denied` — the same distinction Trusted Advisor needs.
   */
  it('reads SubscriptionRequired as unsupported, not as a denial', async () => {
    fetchMock.mockImplementation(() =>
      json({ __type: 'SubscriptionRequiredException', message: 'subscription required' }, 400));

    const r = await checkAwsHealth(creds);
    expect(r.status).toBe('not_applicable');
    expect(r.detail).toMatch(/support plan/i);
    expect(stateFromCheck(r)).toBe('unsupported');
  });

  it('is available on a supported plan', async () => {
    fetchMock.mockImplementation(() => json({ eventTypes: [] }));
    expect(stateFromCheck(await checkAwsHealth(creds))).toBe('available');
  });

  it('separates a real denial from an unsupported plan', async () => {
    fetchMock.mockImplementation(() => denied());
    expect(stateFromCheck(await checkAwsHealth(creds))).toBe('permission_denied');
  });
});

describe('Cost & Usage Report', () => {
  /**
   * The most important state in this whole file: it is the difference between
   * "this account spent nothing" and "nobody ever told us where the bill is" —
   * the distinction the product currently cannot make, and the reason cost
   * reads $0.
   */
  it('reads no report definition as not enabled, which is not zero spend', async () => {
    fetchMock.mockImplementation(() => json({ ReportDefinitions: [] }));
    const r = await checkCur(creds);

    expect(stateFromCheck(r)).toBe('not_enabled');
    expect(r.detail).toMatch(/no cost and usage report is defined/i);
    /*
     * It must not imply anything about SPEND. Matched narrowly on purpose:
     * an earlier version of this assertion used /no cost/ and tripped on the
     * product name "Cost and Usage Report" inside the message itself.
     */
    expect(r.detail).not.toMatch(/zero spend|\$0|spent nothing|no charges/i);
  });

  it('is available when a report is defined', async () => {
    fetchMock.mockImplementation(() => json({ ReportDefinitions: [{ ReportName: 'hv' }] }));
    expect(stateFromCheck(await checkCur(creds))).toBe('available');
  });

  it('separates a denial from an undefined report', async () => {
    fetchMock.mockImplementation(() => denied());
    expect(stateFromCheck(await checkCur(creds))).toBe('permission_denied');
  });
});

describe('credential material never reaches a check detail', () => {
  /**
   * Redaction is applied once, in runFullValidation, rather than in nineteen
   * separate probes -- so a probe added later cannot forget it. These assert
   * the helper and the wiring, which is where the property actually holds.
   */
  it('redacts long-lived and temporary key ids while keeping the message', async () => {
    const { redactAwsText } = await import('./redactAws');

    const msg = 'User: arn:aws:iam::123456789012:user/ci AKIAIOSFODNN7EXAMPLE is not authorized to perform: guardduty:ListDetectors';
    const out = redactAwsText(msg);

    expect(out).not.toMatch(/AKIA[A-Z0-9]{16}/);
    expect(out).toContain('[redacted access key]');
    // The actionable part survives -- it names the exact permission to add.
    expect(out).toContain('guardduty:ListDetectors');

    expect(redactAwsText('token ASIAY34FZKBOKMUTVV7A here')).toContain('[redacted access key]');
    expect(redactAwsText(null)).toBeNull();
  });

  it('is applied to every check runFullValidation returns', async () => {
    const { readFileSync } = await import('node:fs');
    const source = readFileSync('src/lib/permissionChecks.ts', 'utf8');

    // Both return paths -- the normal one and the early STS failure.
    expect(source).toContain('redactAwsText(check.detail)');
    expect(source).toContain('redactAwsText(stsResult.detail)');
  });
});
