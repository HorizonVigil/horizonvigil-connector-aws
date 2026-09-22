import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

import {
  CAPABILITIES,
  REQUIRED_CAPABILITIES,
  stateFromCheck,
  verdictFor,
  setupFor,
  isUsable,
  type CapabilityState,
} from './capabilityMatrix';

const check = (service: string, status: string, detail = '') =>
  ({ service, status: status as never, detail });

/**
 * The exact checks both production AWS connections recorded on 2026-09-22,
 * on a run the product labelled `succeeded`.
 */
const PRODUCTION_CHECKS = [
  check('sts', 'granted', 'Identity confirmed'),
  check('iam', 'granted', 'Read access to IAM confirmed'),
  check('tagging', 'granted', 'Read access confirmed'),
  check('cloudwatch', 'granted', 'Read access confirmed'),
  check('cloudtrail', 'granted', 'Read access confirmed'),
  check('eks', 'granted', 'Read access confirmed'),
  check('cost_explorer', 'granted', 'Read access confirmed'),
  check('config', 'not_applicable', 'Permission confirmed, but no configuration recorder exists in this region — Config has no data to read.'),
  check('organizations', 'not_applicable', 'This account is not part of an AWS Organization'),
  check('trusted_advisor', 'not_applicable', 'Trusted Advisor checks require a Business or Enterprise support plan on this account.'),
  check('securityhub', 'error', 'AWS returned HTTP 401 for Security Hub.'),
  check('compute_optimizer', 'error', 'RESOURCE_NOT_FOUND'),
];

describe('stateFromCheck', () => {
  it('maps a granted check to available', () => {
    expect(stateFromCheck(check('iam', 'granted', 'ok'))).toBe('available');
  });

  it('maps an IAM refusal to permission_denied, which is a policy fix', () => {
    expect(stateFromCheck(check('iam', 'denied', 'AccessDenied'))).toBe('permission_denied');
  });

  /**
   * The distinction the whole module turns on. `permission_denied` sends
   * someone to edit an IAM policy; `not_enabled` sends them to switch a
   * service on. Getting it wrong wastes an afternoon editing a policy that
   * was already correct.
   */
  it('separates "switched off" from "not permitted"', () => {
    expect(stateFromCheck(check('config', 'not_applicable', 'no configuration recorder exists'))).toBe('not_enabled');
    expect(stateFromCheck(check('cost_explorer', 'not_applicable', 'Cost Explorer is not enabled for this AWS account.'))).toBe('not_enabled');
    expect(stateFromCheck(check('organizations', 'not_applicable', 'This account is not part of an AWS Organization'))).toBe('not_enabled');
  });

  it('separates "cannot be enabled here" from both', () => {
    // No amount of policy editing buys a Business support plan.
    expect(stateFromCheck(check('trusted_advisor', 'not_applicable', 'requires a Business or Enterprise support plan'))).toBe('unsupported');
    expect(stateFromCheck(check('compute_optimizer', 'not_applicable', 'not available for this account.'))).toBe('unsupported');
  });

  /** Both live production misclassifications. */
  it('reads Security Hub 401 as not_enabled, not as a fault', () => {
    expect(stateFromCheck(check('securityhub', 'not_applicable', 'Security Hub is not enabled in this region.'))).toBe('not_enabled');
  });

  it('reads Compute Optimizer RESOURCE_NOT_FOUND as not_enabled even when it arrives as an error', () => {
    expect(stateFromCheck(check('compute_optimizer', 'error', 'RESOURCE_NOT_FOUND'))).toBe('not_enabled');
  });

  it('calls a genuine AWS failure service_unavailable, not the customer fault', () => {
    expect(stateFromCheck(check('cloudwatch', 'error', 'HTTP 503'))).toBe('service_unavailable');
    expect(stateFromCheck(check('iam', 'error', 'Request failed'))).toBe('service_unavailable');
  });

  /**
   * A reason nobody has classified must surface as unknown so that it gets
   * classified -- quietly folding it into not_enabled is how an unexamined
   * state becomes a confident answer.
   */
  it('does not quietly downgrade an unrecognised not_applicable reason', () => {
    expect(stateFromCheck(check('eks', 'not_applicable', 'something nobody has seen before'))).toBe('unknown');
  });

  it('never returns available for anything but a granted check', () => {
    for (const status of ['denied', 'error', 'not_applicable']) {
      expect(stateFromCheck(check('x', status, 'whatever'))).not.toBe('available');
    }
  });
});

describe('verdictFor — the production defect', () => {
  /**
   * The run that produced these checks was stored as `succeeded`. It carried
   * two `error` checks. That is the defect.
   */
  it('does not call the real production run succeeded-with-errors a failure either', () => {
    const v = verdictFor(PRODUCTION_CHECKS);

    // Every REQUIRED capability really was available on that run, so the run
    // genuinely did succeed -- the old code reached the right answer here by
    // luck, from the wrong evidence.
    expect(v.status).toBe('succeeded');
    expect(v.failedRequired).toEqual([]);

    // ...and the optional sources that were off are now NAMED rather than
    // silently folded into "succeeded".
    expect(v.unavailableOptional).toContain('Security Hub');
    expect(v.unavailableOptional).toContain('Compute Optimizer');
    expect(v.unavailableOptional).toContain('Trusted Advisor');
    expect(v.summary).toMatch(/optional/i);
  });

  it('FAILS when a required capability is denied, however healthy STS is', () => {
    // The exact case the old `stsCheck === 'granted'` rule got wrong.
    const v = verdictFor([
      ...PRODUCTION_CHECKS.filter((c) => c.service !== 'iam'),
      check('iam', 'denied', 'AccessDenied'),
    ]);

    expect(v.status).toBe('failed');
    expect(v.failedRequired).toContain('IAM inventory');
    expect(v.summary).toMatch(/required/i);
  });

  it('FAILS when a required capability errors', () => {
    const v = verdictFor([
      ...PRODUCTION_CHECKS.filter((c) => c.service !== 'cloudtrail'),
      check('cloudtrail', 'error', 'HTTP 500'),
    ]);
    expect(v.status).toBe('failed');
    expect(v.failedRequired).toContain('CloudTrail change history');
  });

  /**
   * The opposite failure, and why this is a matrix rather than a stricter
   * boolean: an account with no Config recorder and no support plan is a
   * completely normal AWS account.
   */
  it('does NOT fail a run because optional sources are switched off', () => {
    const v = verdictFor(PRODUCTION_CHECKS);
    expect(v.status).toBe('succeeded');
    expect(v.unavailableOptional.length).toBeGreaterThan(0);
  });

  /**
   * Silence is not success. A required capability nobody probed has not been
   * shown to work.
   */
  it('fails when a required capability was never probed at all', () => {
    const v = verdictFor([check('sts', 'granted', 'ok')]);
    expect(v.status).toBe('failed');
    expect(v.failedRequired).toContain('IAM inventory');
  });

  it('fails on an empty check list rather than defaulting to success', () => {
    expect(verdictFor([]).status).toBe('failed');
  });

  it('never reports a required failure as an optional one', () => {
    const v = verdictFor([]);
    for (const label of v.failedRequired) {
      expect(v.unavailableOptional).not.toContain(label);
    }
  });

  it('summarises what a reader must act on', () => {
    const v = verdictFor([check('sts', 'granted', 'ok')]);
    expect(v.summary.length).toBeGreaterThan(30);
    expect(v.summary).toMatch(/IAM inventory/);
  });
});

describe('the capability registry itself', () => {
  it('covers every capability the AWS V1 brief requires', () => {
    const labels = CAPABILITIES.map((c) => c.label.toLowerCase()).join(' | ');
    for (const required of [
      'sts', 'iam', 'organizations', 'tagging', 'cloudwatch', 'cloudtrail',
      'cost explorer', 'cost & usage report', 'eks', 'ecs', 'config',
      'security hub', 'guardduty', 'inspector', 'access analyzer',
      'compute optimizer', 'trusted advisor', 'health',
    ]) {
      expect(labels, `missing capability: ${required}`).toContain(required);
    }
  });

  it('gives every capability an actionable setup instruction', () => {
    for (const c of CAPABILITIES) {
      expect(c.setup.length, c.key).toBeGreaterThan(40);
      expect(setupFor(c.key)).toBe(c.setup);
    }
  });

  it('keeps capability keys unique', () => {
    expect(new Set(CAPABILITIES.map((c) => c.key)).size).toBe(CAPABILITIES.length);
  });

  /**
   * Required means "HorizonVigil cannot deliver its product without it". If an
   * optional source crept into this list, a normal AWS account would start
   * reporting its connection as broken.
   */
  it('keeps the required set to what the product genuinely cannot work without', () => {
    const required = REQUIRED_CAPABILITIES.map((c) => c.key).sort();
    expect(required).toEqual([
      'activity_cloudtrail', 'governance_tags', 'identity', 'identity_sts', 'inventory', 'metrics',
    ]);
  });

  it('does not mark any optional security or billing source required', () => {
    for (const key of ['posture_securityhub', 'posture_guardduty', 'posture_inspector', 'billing_cost_explorer', 'billing_cur', 'recommendations', 'advisory_trusted_advisor', 'advisory_health', 'organizations']) {
      expect(CAPABILITIES.find((c) => c.key === key)?.required, key).toBe(false);
    }
  });

  it('names the setup instruction in terms of what the customer changes', () => {
    // Security Hub's instruction must not tell someone to edit a policy.
    expect(setupFor('posture_securityhub')).toMatch(/enable/i);
    expect(setupFor('advisory_trusted_advisor')).toMatch(/support plan/i);
    expect(setupFor('recommendations')).toMatch(/opt in/i);
  });
});

describe('isUsable', () => {
  it('treats only available and partial as delivering data', () => {
    const usable: CapabilityState[] = ['available', 'partial'];
    const notUsable: CapabilityState[] = ['permission_denied', 'not_enabled', 'unsupported', 'service_unavailable', 'stale', 'unknown'];

    for (const s of usable) expect(isUsable(s), s).toBe(true);
    for (const s of notUsable) expect(isUsable(s), s).toBe(false);
  });

  it('does not treat stale as usable', () => {
    // Stale data is real data that is too old to act on, which is a different
    // answer from current data -- and must not feed a "healthy" rollup.
    expect(isUsable('stale')).toBe(false);
  });
});

/**
 * The wiring, not just the rule.
 *
 * A correct verdict function that nothing calls fixes nothing. This suite was
 * initially written without these assertions, and a tamper test that restored
 * the old STS-only line passed all 25 of them -- the pure function was right
 * and the route still used the broken rule.
 */
describe('the validation route actually uses the verdict', () => {
  const SOURCE = readFileSync('src/routes/permissions.ts', 'utf8');

  it('derives the run status from the capability verdict', () => {
    expect(SOURCE).toContain('verdictFor(checks)');
    expect(SOURCE).toMatch(/const overallStatus = verdict\.status/);
  });

  it('no longer decides the whole run from the STS check alone', () => {
    // The exact line that made both production connections report `succeeded`
    // while carrying two errored checks.
    expect(SOURCE).not.toMatch(/stsCheck\?\.status === 'granted' \? 'succeeded' : 'failed'/);
  });

  it('records WHICH required capabilities failed, not the first check in the array', () => {
    expect(SOURCE).toContain('verdict.summary');
    expect(SOURCE).not.toMatch(/error_message: overallStatus === 'failed' \? checks\[0\]\?\.detail/);
  });
});

/**
 * A capability declared in the matrix but never probed sits at `unknown`
 * forever, which the frontend cannot distinguish from "we looked and it is
 * fine". That was the state of six capabilities before this phase, and it is
 * the same class of miss as a correct verdict function nothing calls.
 */
describe('every declared capability is actually probed', () => {
  const SOURCE = readFileSync('src/lib/permissionChecks.ts', 'utf8');

  it('runFullValidation produces a check for every capability that names a probe', () => {
    const probed = new Set(
      [...SOURCE.matchAll(/service: '([a-z_0-9]+)', label:/g)].map((m) => m[1]),
    );
    const EXTRA = readFileSync('src/lib/permissionProbesExtra.ts', 'utf8');
    for (const m of EXTRA.matchAll(/service: '([a-z_0-9]+)', label:/g)) probed.add(m[1]);

    const declared = CAPABILITIES.filter((c) => c.probeService).map((c) => c.probeService!);
    const missing = [...new Set(declared)].filter((svc) => !probed.has(svc));

    expect(missing, `capabilities declared with no probe: ${missing.join(', ')}`).toEqual([]);
  });

  it('every probe is wired into the validation run, not merely defined', () => {
    // A probe function nobody calls is the same defect as no probe at all.
    for (const fn of ['checkGuardDuty', 'checkInspector', 'checkAccessAnalyzer', 'checkEcs', 'checkAwsHealth', 'checkCur']) {
      expect(SOURCE, `${fn} is defined but never called`).toContain(`${fn}(creds`);
    }
  });

  it('covers all 18 capabilities the brief enumerates', () => {
    const probeServices = new Set(CAPABILITIES.map((c) => c.probeService).filter(Boolean));
    expect(probeServices.size).toBeGreaterThanOrEqual(17);
  });
});
