import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

import { classifyFailure, RegionCoverageLedger } from './regionalAvailability';
import type { AwsCallFailure } from './awsApi';

const fail = (service: string, action: string, region: string, code: string, attempts = 4): AwsCallFailure =>
  ({ service, action, region, normalizedCode: code as never, attempts });

/**
 * Real `[degraded]` lines pulled from the connector's production logs on
 * 2026-09-22. `apprunner:ListServices` fails in twelve regions, and the SAME
 * region answers RESOURCE_NOT_FOUND on one run and NETWORK_ERROR on another —
 * the signature of an endpoint that does not exist, not an intermittent fault.
 */
const APPRUNNER_PRODUCTION = [
  fail('apprunner', 'ListServices', 'ap-northeast-1', 'RESOURCE_NOT_FOUND'),
  fail('apprunner', 'ListServices', 'ap-northeast-2', 'NETWORK_ERROR'),
  fail('apprunner', 'ListServices', 'ap-northeast-3', 'NETWORK_ERROR'),
  fail('apprunner', 'ListServices', 'ap-south-1', 'RESOURCE_NOT_FOUND'),
  fail('apprunner', 'ListServices', 'eu-west-1', 'RESOURCE_NOT_FOUND'),
  fail('apprunner', 'ListServices', 'eu-north-1', 'NETWORK_ERROR'),
];

describe('classifyFailure', () => {
  /**
   * The core judgement. A list operation over an empty account returns an
   * EMPTY LIST, not a not-found — so not-found means the API is not there, and
   * a region with no endpoint has nothing to read rather than something we
   * failed to read.
   */
  it('does not degrade a type because the service has no endpoint in the region', () => {
    const c = classifyFailure(fail('apprunner', 'ListServices', 'eu-west-3', 'RESOURCE_NOT_FOUND'));

    expect(c.meaning).toBe('service_absent_in_region');
    expect(c.degrades).toBe(false);
    expect(c.reason).toMatch(/not available in eu-west-3/);
  });

  it('degrades on a permission denial — resources may exist and were not read', () => {
    const c = classifyFailure(fail('fms', 'ListPolicies', 'us-east-1', 'PERMISSION_DENIED'));
    expect(c.meaning).toBe('permission_denied');
    expect(c.degrades).toBe(true);
    expect(c.reason).toMatch(/may exist and were not read/);
  });

  it('degrades on a throttle, because the region was not fully read', () => {
    const c = classifyFailure(fail('ec2', 'DescribeInstances', 'us-east-1', 'THROTTLED'));
    expect(c.meaning).toBe('throttled');
    expect(c.degrades).toBe(true);
  });

  it('degrades on a truncated page — the count is a lower bound', () => {
    const c = classifyFailure(fail('s3', 'ListBuckets', 'us-east-1', 'PAGINATION_TRUNCATED'));
    expect(c.meaning).toBe('incomplete_read');
    expect(c.degrades).toBe(true);
    expect(c.reason).toMatch(/under-counted/);
  });

  /**
   * The safe default. When a failure cannot be explained, assume resources
   * were missed — the cost of being wrong the other way is deleting inventory
   * that still exists.
   */
  it('degrades on an UNCORROBORATED network error rather than assuming absence', () => {
    const c = classifyFailure(fail('ec2', 'DescribeInstances', 'us-east-1', 'NETWORK_ERROR'));
    expect(c.meaning).toBe('collection_failed');
    expect(c.degrades).toBe(true);
  });

  it('reads a network error as absence ONLY when the service is absent elsewhere', () => {
    const c = classifyFailure(fail('apprunner', 'ListServices', 'eu-north-1', 'NETWORK_ERROR'), true);
    expect(c.meaning).toBe('service_absent_in_region');
    expect(c.degrades).toBe(false);
  });

  it('degrades on an unrecognised code', () => {
    expect(classifyFailure(fail('x', 'Y', 'us-east-1', 'SOMETHING_NEW')).degrades).toBe(true);
  });

  it('never returns a reason a customer cannot act on', () => {
    for (const code of ['RESOURCE_NOT_FOUND', 'PERMISSION_DENIED', 'THROTTLED', 'NETWORK_ERROR', 'PAGINATION_TRUNCATED']) {
      const c = classifyFailure(fail('svc', 'Action', 'eu-west-1', code));
      expect(c.reason.length, code).toBeGreaterThan(30);
      expect(c.reason, code).toContain('eu-west-1');
    }
  });
});

describe('RegionCoverageLedger — the production run', () => {
  const TYPES = ['app_runner_service', 'app_runner_connection'];

  const ledgerFor = (failures: AwsCallFailure[], types = TYPES) => {
    const l = new RegionCoverageLedger();
    for (const f of failures) l.record(f, types);
    return l;
  };

  it('degrades NOTHING for a service simply absent across regions', () => {
    // This is the whole defect: these twelve regions produced two degraded
    // resource types on every run, forever.
    const l = ledgerFor(APPRUNNER_PRODUCTION);

    expect([...l.degradedTypes().keys()]).toEqual([]);
    expect(l.absentRegions().length).toBe(APPRUNNER_PRODUCTION.length);
  });

  it('uses one region to explain an ambiguous failure in another', () => {
    // ap-northeast-2 only answered NETWORK_ERROR. On its own that degrades;
    // corroborated by RESOURCE_NOT_FOUND elsewhere for the same service, it is
    // absence.
    const l = ledgerFor(APPRUNNER_PRODUCTION);
    const absent = l.absentRegions().map((a) => a.region);
    expect(absent).toContain('ap-northeast-2');
  });

  it('does NOT use one service to explain another service network error', () => {
    // Corroboration is per service. An unrelated absent service must not
    // launder a real EC2 outage into "absence".
    const l = new RegionCoverageLedger();
    l.record(fail('apprunner', 'ListServices', 'eu-west-1', 'RESOURCE_NOT_FOUND'), ['app_runner_service']);
    l.record(fail('ec2', 'DescribeInstances', 'eu-west-1', 'NETWORK_ERROR'), ['ec2_instance']);

    expect([...l.degradedTypes().keys()]).toEqual(['ec2_instance']);
  });

  it('still degrades a genuine denial, alongside absent regions', () => {
    const l = new RegionCoverageLedger();
    for (const f of APPRUNNER_PRODUCTION) l.record(f, TYPES);
    l.record(fail('fms', 'ListPolicies', 'us-east-1', 'PERMISSION_DENIED'), ['firewall_manager_policy']);

    const degraded = l.degradedTypes();
    expect([...degraded.keys()]).toEqual(['firewall_manager_policy']);
    expect(degraded.get('firewall_manager_policy')).toMatch(/denied/i);
  });

  it('records WHY each type is degraded, not just that it is', () => {
    // The production runs stored 41 bare type names with no reason anywhere,
    // so nobody could tell a denial from an absent service.
    const l = new RegionCoverageLedger();
    l.record(fail('license-manager', 'ListLicenseConfigurations', 'us-east-1', 'PERMISSION_DENIED'), ['license_manager_configuration']);

    const reason = l.degradedTypes().get('license_manager_configuration');
    expect(reason).toBeTruthy();
    expect(reason).toContain('license-manager:ListLicenseConfigurations');
  });

  it('keeps the first reason when a type degrades twice', () => {
    const l = new RegionCoverageLedger();
    l.record(fail('fms', 'ListPolicies', 'us-east-1', 'PERMISSION_DENIED'), ['firewall_manager_policy']);
    l.record(fail('fms', 'ListPolicies', 'eu-west-1', 'THROTTLED'), ['firewall_manager_policy']);

    expect(l.degradedTypes().get('firewall_manager_policy')).toMatch(/denied/i);
  });

  it('summarises the run by cause', () => {
    const l = new RegionCoverageLedger();
    for (const f of APPRUNNER_PRODUCTION) l.record(f, TYPES);
    l.record(fail('fms', 'ListPolicies', 'us-east-1', 'PERMISSION_DENIED'), ['firewall_manager_policy']);

    const byMeaning = Object.fromEntries(l.summary().map((s) => [s.meaning, s.count]));
    expect(byMeaning.service_absent_in_region).toBe(6);
    expect(byMeaning.permission_denied).toBe(1);
  });

  it('reports nothing for a clean run', () => {
    const l = new RegionCoverageLedger();
    expect([...l.degradedTypes().keys()]).toEqual([]);
    expect(l.absentRegions()).toEqual([]);
    expect(l.summary()).toEqual([]);
  });
});

/**
 * The wiring, on the same lesson that caught the capability verdict: a correct
 * classifier that discovery does not call changes nothing.
 */
describe('discovery uses the ledger', () => {
  const SOURCE = readFileSync('src/routes/discovery.ts', 'utf8');

  it('records failures into the ledger rather than degrading on sight', () => {
    expect(SOURCE).toContain('new RegionCoverageLedger()');
    expect(SOURCE).toContain('coverage.record(f, ownedTypes)');
  });

  it('no longer marks every owned type degraded on any failure', () => {
    // The exact line that produced 41 degraded types on every run.
    expect(SOURCE).not.toMatch(/for \(const t of ownedTypes\) degraded\.add\(t\)/);
  });

  it('takes the degraded set from the classifier', () => {
    expect(SOURCE).toContain('coverage.degradedTypes()');
  });
});
