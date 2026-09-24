import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { AWS_CAPABILITIES, allRequiredPermissions, v1Capabilities } from './capabilityRegistry';

/**
 * A capability registry is only worth having if it cannot drift from the
 * implementation. A declaration nobody checks is how a product ends up
 * claiming capabilities it does not have — which is the exact class of defect
 * the 2026-09-08 audits found across HorizonVigil's public content.
 *
 * These assert the declaration against the real source, so adding or removing
 * a probe without updating the registry fails the build.
 */
const permissionChecksSrc = readFileSync(join(__dirname, 'permissionChecks.ts'), 'utf8');
const capabilitiesSrc = readFileSync(join(__dirname, 'capabilities.ts'), 'utf8');

describe('capability registry integrity', () => {
  it('has a unique key per capability', () => {
    const keys = AWS_CAPABILITIES.map((c) => c.key);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('every capability declares at least one AWS API and one permission', () => {
    for (const c of AWS_CAPABILITIES) {
      expect(c.awsApis.length, c.key).toBeGreaterThan(0);
      expect(c.requiredPermissions.length, c.key).toBeGreaterThan(0);
    }
  });

  it('every capability marked `probed` has a real check function in permissionChecks.ts', () => {
    // The point of the flag: a capability that is scanned but not probed can
    // fail silently every night while the connection still reports healthy.
    // Claiming `probed: true` without a probe would hide exactly that.
    const probeFor: Record<string, string> = {
      sts: 'checkCallerIdentity',
      iam: 'checkIam',
      organizations: 'checkOrganizations',
      cloudwatch: 'checkCloudWatch',
      cloudtrail: 'checkCloudTrail',
      tagging: 'checkTaggingApi',
      cost_explorer: 'checkCostExplorer',
      eks: 'checkEks',
      config: 'checkConfig',
      securityhub: 'checkSecurityHub',
      compute_optimizer: 'checkComputeOptimizer',
      trusted_advisor: 'checkTrustedAdvisor',
    };

    for (const c of AWS_CAPABILITIES.filter((x) => x.probed)) {
      const fn = probeFor[c.key];
      expect(fn, `no probe mapping declared for probed capability "${c.key}"`).toBeTruthy();
      expect(permissionChecksSrc, `${c.key} claims probed but ${fn} is missing`).toContain(`export async function ${fn}(`);
      expect(permissionChecksSrc, `${fn} exists but is never run by runPermissionChecks`).toMatch(new RegExp(`${fn}\\(creds`));
    }
  });

  it('declares no capability as action-capable while provider mutation is gated off', () => {
    // V1 policy from the 2026-09-08 audits: "No direct provider mutation
    // ships in V1." If that gate is ever removed this test should be revisited
    // deliberately, not silently.
    expect(capabilitiesSrc).toContain('isProviderRemediationEnabled');
    for (const c of AWS_CAPABILITIES) {
      expect(c.actionSupported, `${c.key} claims an action while remediation is disabled`).toBe(false);
    }
  });

  it('keeps V2 capabilities out of the V1 surface', () => {
    // GuardDuty/Inspector are collected but must not be presented in V1 —
    // the audits scoped V1 Cloud Security to posture, not vulnerabilities.
    for (const c of AWS_CAPABILITIES.filter((x) => x.lifecycle === 'v2')) {
      expect(c.uiConsumer, c.key).toMatch(/not surfaced in v1|disabled in v1/i);
    }
    expect(v1Capabilities().every((c) => c.lifecycle === 'v1')).toBe(true);
  });

  it('never claims a capability is implemented without saying where its data goes or who reads it', () => {
    for (const c of AWS_CAPABILITIES.filter((x) => x.implemented)) {
      expect(c.uiConsumer.length, c.key).toBeGreaterThan(0);
    }
  });

  it('produces a de-duplicated, sorted least-privilege permission set', () => {
    const perms = allRequiredPermissions();
    expect(new Set(perms).size).toBe(perms.length);
    expect([...perms].sort()).toEqual(perms);
    expect(perms).toContain('sts:GetCallerIdentity');
    expect(perms).toContain('ce:GetCostAndUsage');
  });

  it('grants no write permission outside the disabled remediation capability', () => {
    // A read-only connector that quietly asks for ec2:StopInstances in its
    // least-privilege policy would be asking customers for power it says it
    // does not use.
    const writeish = /:(Create|Delete|Modify|Put|Update|Stop|Start|Terminate|Attach|Detach)/;
    for (const c of AWS_CAPABILITIES.filter((x) => x.key !== 'remediation')) {
      const offenders = c.requiredPermissions.filter((p) => writeish.test(p));
      expect(offenders, `${c.key} requests write permissions`).toEqual([]);
    }
  });
});
