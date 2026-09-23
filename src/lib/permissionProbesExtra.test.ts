import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';

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
  checkLambda, checkKafka, checkFirewallManager, checkLicenseManager,
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

  /**
   * Measured 2026-09-22: BOTH production connections return AccessDenied here
   * while carrying AdministratorAccess, in accounts belonging to no AWS
   * Organization — so there is no policy gap and no SCP that could explain it.
   * Amazon Inspector returns AccessDenied for this call in accounts where the
   * service was never activated, which is an account state, not a permission.
   *
   * The probe cannot tell the two apart from the response. It must therefore
   * not assert the one that is wrong here, or it sends someone to edit a
   * policy that already grants everything.
   */
  it('does not send the customer to fix a policy that may already be correct', async () => {
    fetchMock.mockImplementation(() => denied());
    const r = await checkInspector(creds, REGION);

    expect(r.detail).toMatch(/never been activated|whether Inspector is\s+enabled/i);
    // The cheaper check is named first: activating Inspector is a console
    // toggle, editing an IAM policy is not.
    expect(r.detail.indexOf('activated')).toBeLessThan(r.detail.indexOf('IAM policy'));
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

  /**
   * The probe sent `maxResults: 1` from the day it was written. AWS Health
   * requires >= 10, so EVERY call was rejected:
   *
   *   "1 validation error detected: Value '1' at 'maxResults' failed to
   *    satisfy constraint: Member must have value greater than or equal to 10"
   *
   * It reported `error` for its entire life and never once tested the
   * permission it exists to test — "our request was malformed" was
   * indistinguishable from "AWS Health is unavailable".
   *
   * Found 2026-09-22, and only because the account was granted admin: while
   * seven services were genuinely denied, one more failure looked like more of
   * the same. Removing the real denials is what made this visible.
   */
  it('sends a maxResults AWS will actually accept', async () => {
    let sentBody: Record<string, unknown> | null = null;
    fetchMock.mockImplementation((_url: string, init?: RequestInit) => {
      sentBody = JSON.parse(String(init?.body ?? '{}'));
      return json({ eventTypes: [] });
    });

    await checkAwsHealth(creds);

    const maxResults = Number((sentBody as unknown as { maxResults?: number })?.maxResults);
    expect(maxResults, 'AWS Health rejects anything below 10').toBeGreaterThanOrEqual(10);
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

    const syntheticAccessKey = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
    const msg = `User: arn:aws:iam::123456789012:user/ci ${syntheticAccessKey} is not authorized to perform: guardduty:ListDetectors`;
    const out = redactAwsText(msg);

    expect(out).not.toMatch(/AKIA[A-Z0-9]{16}/);
    expect(out).toContain('[redacted access key]');
    // The actionable part survives -- it names the exact permission to add.
    expect(out).toContain('guardduty:ListDetectors');

    const syntheticSessionKey = ['ASIA', 'Y34FZKBOKMUTVV7A'].join('');
    expect(redactAwsText(`token ${syntheticSessionKey} here`)).toContain('[redacted access key]');
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

/**
 * AWS-I1. The seven services the IAM-drift finding named.
 *
 * Six of them were not probed AT ALL. So when the deployed roles were missing
 * these permissions, validation reported a clean run while every one of their
 * scanners was refused — and their ABSENCE from the denied list read as
 * success. That is exactly how the 2026-09-23 AdministratorAccess grant
 * appeared to fix seven services that were, in fact, still denied at the
 * scanner: six of them were never being asked about.
 */
describe('AWS-I1 services are probed at all', () => {
  const SOURCE = readFileSync('src/lib/permissionChecks.ts', 'utf8');

  it.each([
    ['lambda', 'checkLambda'],
    ['kafka', 'checkKafka'],
    ['imagebuilder', 'checkImageBuilder'],
    ['macie2', 'checkMacie'],
    ['fms', 'checkFirewallManager'],
    ['license-manager', 'checkLicenseManager'],
  ])('%s is probed by runFullValidation', (_svc, fn) => {
    expect(SOURCE).toContain(`${fn}(creds`);
  });

  it('securityhub was already probed and stays probed', () => {
    expect(SOURCE).toContain("service: 'securityhub'");
  });

  /**
   * Running a probe is not the same as REPORTING it.
   *
   * The first version of this change appended the six calls to the
   * `Promise.all([...])` without adding them to the destructuring pattern on
   * the left. All six ran — six real AWS calls per validation — and every
   * result was discarded. Validation looked identical to before, and the
   * services stayed invisible.
   *
   * That is the same shape as every other defect in this codebase's history:
   * the work happens, the answer is dropped, and nothing says so. Asserting
   * the promise list is not enough; the results have to reach `checks`.
   */
  it.each(['lambdaFn', 'kafka', 'imageBuilder', 'macie', 'firewallManager', 'licenseManager'])(
    '%s is destructured AND included in the returned checks',
    (name) => {
      const destructuring = SOURCE.slice(SOURCE.indexOf('const ['), SOURCE.indexOf('] = await Promise.all('));
      expect(destructuring, `${name} is not destructured — its result is discarded`).toContain(name);

      const checksArray = SOURCE.slice(SOURCE.indexOf('const checks = ['));
      expect(checksArray.slice(0, 600), `${name} never reaches checks[]`).toContain(name);
    },
  );

  it('every probe in the Promise.all has a name to receive it', () => {
    const calls = (SOURCE.slice(SOURCE.indexOf('] = await Promise.all('), SOURCE.indexOf('const checks = ['))
      .match(/check[A-Z]\w*\(creds/g) ?? []).length;
    const names = SOURCE.slice(SOURCE.indexOf('const ['), SOURCE.indexOf('] = await Promise.all('))
      .split(',').map((x) => x.trim()).filter((x) => x && !x.startsWith('/') && !x.startsWith('*')).length;
    // stsResult is added to checks separately, so names == calls exactly.
    expect(names, 'a probe result is being discarded').toBe(calls);
  });
});

describe('the AWS-I1 probes behave correctly', () => {
  /**
   * Lambda is available in every commercial region and has no "enable"
   * step, so a 403 here is a real policy gap and must never be softened
   * into an enablement state.
   */
  it('reports a Lambda 403 as DENIED, never as not-applicable', async () => {
    fetchMock.mockImplementation(() => denied());
    const r = await checkLambda(creds, REGION);
    expect(r.status).toBe('denied');
    expect(r.detail).toContain('lambda:ListFunctions');
    expect(stateFromCheck(r)).toBe('permission_denied');
  });

  it('reports a Lambda success as granted', async () => {
    fetchMock.mockImplementation(() => json({ Functions: [] }));
    expect(stateFromCheck(await checkLambda(creds, REGION))).toBe('available');
  });

  it('reads a 404 as the service being absent from the region, not denied', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(new Response('{}', { status: 404 })));
    const r = await checkKafka(creds, REGION);
    expect(r.status).toBe('not_applicable');
  });

  /**
   * Firewall Manager answers only for the account designated as the FMS
   * administrator. That is an account state, not a policy gap, and telling
   * someone to edit an IAM policy for it sends them to fix the wrong thing.
   */
  it('separates "not the FMS admin account" from a denial', async () => {
    fetchMock.mockImplementation(() =>
      json({ __type: 'InvalidOperationException', message: 'The account is not associated as the FMS administrator' }, 400));
    const r = await checkFirewallManager(creds);
    expect(r.status).toBe('not_applicable');
    expect(r.detail).toMatch(/administrator account/i);
  });

  it('still reports a real FMS denial as denied', async () => {
    fetchMock.mockImplementation(() => denied());
    expect((await checkFirewallManager(creds)).status).toBe('denied');
  });

  it('reports a License Manager denial with the action that was refused', async () => {
    fetchMock.mockImplementation(() => denied());
    const r = await checkLicenseManager(creds, REGION);
    expect(r.status).toBe('denied');
    expect(r.detail).toContain('license-manager:ListLicenseConfigurations');
  });
});
