import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import {
  buildManifest, validateManifest, supportFor, isCapabilityAvailable,
  CONTRACT_VERSION, ADAPTER_VERSION, type AdapterManifest,
} from './adapterContract';
import { AWS_CAPABILITIES } from './capabilityRegistry';

describe('adapter contract versions', () => {
  it('exposes machine-readable semver for contract and adapter', () => {
    expect(CONTRACT_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    expect(ADAPTER_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  /**
   * Two versions, not one. CONTRACT_VERSION is the shape Azure, GCP and OCI
   * must satisfy; ADAPTER_VERSION is this AWS implementation. Collapsing
   * them would make an AWS-only change force a contract bump every other
   * provider had to react to.
   */
  it('keeps contract and adapter versions independently addressable', () => {
    const m = buildManifest();
    expect(m.contract_version).toBe(CONTRACT_VERSION);
    expect(m.adapter_version).toBe(ADAPTER_VERSION);
  });
});

describe('capability manifest', () => {
  it('is built from the registry, not declared separately', () => {
    const m = buildManifest();
    expect(m.capabilities).toHaveLength(AWS_CAPABILITIES.length);
    expect(m.capabilities.map((c) => c.key).sort())
      .toEqual(AWS_CAPABILITIES.map((c) => c.key).sort());
  });

  it('summary counts reconcile with the capability list', () => {
    const s = buildManifest().summary;
    expect(s.supported_verified + s.supported_unverified + s.gated_v2 + s.unsupported).toBe(s.total);
  });

  /**
   * The distinction a boolean cannot carry. An implemented-but-unprobed
   * capability can fail every night while the connection still reports
   * healthy — the exact gap the registry exists to expose, so the manifest
   * must not flatten it back to supported: true.
   */
  it('distinguishes verified from unverified support', () => {
    expect(supportFor({ ...AWS_CAPABILITIES[0], implemented: true, probed: true, lifecycle: 'v1' }))
      .toBe('SUPPORTED_VERIFIED');
    expect(supportFor({ ...AWS_CAPABILITIES[0], implemented: true, probed: false, lifecycle: 'v1' }))
      .toBe('SUPPORTED_UNVERIFIED');
  });

  it('never presents a V2 capability as supported', () => {
    const m = buildManifest();
    for (const c of m.capabilities.filter((x) => x.lifecycle === 'v2')) {
      expect(c.support).toBe('GATED_V2');
    }
  });

  it('reports an unimplemented capability as UNSUPPORTED regardless of probing', () => {
    expect(supportFor({ ...AWS_CAPABILITIES[0], implemented: false, probed: true, lifecycle: 'v1' }))
      .toBe('UNSUPPORTED');
  });
});

describe('manifest validation', () => {
  it('the real manifest is valid', () => {
    expect(validateManifest(buildManifest())).toEqual([]);
  });

  const withCaps = (caps: AdapterManifest['capabilities']): AdapterManifest => ({
    ...buildManifest(),
    capabilities: caps,
    summary: { total: caps.length, supported_verified: caps.length, supported_unverified: 0, gated_v2: 0, unsupported: 0 },
  });
  const cap = (over: Partial<AdapterManifest['capabilities'][number]> = {}) => ({
    key: 'x', label: 'X', support: 'SUPPORTED_VERIFIED' as const, lifecycle: 'v1' as const,
    awsApis: ['svc:Do'], requiredPermissions: ['svc:Do'], dataStored: [], actionSupported: false, ...over,
  });

  it('rejects a supported capability that names no AWS API', () => {
    const issues = validateManifest(withCaps([cap({ awsApis: [] })]));
    expect(issues.some((i) => i.problem.includes('names no AWS API'))).toBe(true);
  });

  it('rejects a supported capability that requires no IAM permission', () => {
    const issues = validateManifest(withCaps([cap({ requiredPermissions: [] })]));
    expect(issues.some((i) => i.problem.includes('requires no IAM permission'))).toBe(true);
  });

  /**
   * V1 is read-only and the public copy says so. That copy has drifted back
   * three times, so the manifest refuses to carry a mutation claim at all.
   */
  it('rejects any capability claiming provider mutation', () => {
    const issues = validateManifest(withCaps([cap({ actionSupported: true })]));
    expect(issues.some((i) => i.problem.includes('read-only'))).toBe(true);
  });

  it('rejects a v2 capability declared supported', () => {
    const issues = validateManifest(withCaps([cap({ lifecycle: 'v2' })]));
    expect(issues.some((i) => i.problem.includes('403'))).toBe(true);
  });

  it('rejects duplicate capability keys', () => {
    const issues = validateManifest(withCaps([cap(), cap()]));
    expect(issues.some((i) => i.problem === 'duplicate capability key')).toBe(true);
  });

  it('rejects a non-semver version', () => {
    const m = { ...buildManifest(), adapter_version: 'v1' };
    expect(validateManifest(m).some((i) => i.problem.includes('not semver'))).toBe(true);
  });

  it('rejects a summary that does not reconcile', () => {
    const m = buildManifest();
    const broken = { ...m, summary: { ...m.summary, total: m.summary.total + 5 } };
    expect(validateManifest(broken).some((i) => i.problem.includes('summary counts'))).toBe(true);
  });
});

describe('isCapabilityAvailable', () => {
  it('answers true for an implemented V1 capability', () => {
    expect(isCapabilityAvailable('sts')).toBe(true);
  });

  it('answers false for a V2-gated capability', () => {
    expect(isCapabilityAvailable('remediation')).toBe(false);
  });

  /**
   * An unknown key must be false. Returning true for something the manifest
   * has never heard of would make a typo look like a capability.
   */
  it('answers false for an unknown capability rather than assuming support', () => {
    expect(isCapabilityAvailable('definitely-not-a-capability')).toBe(false);
  });
});

describe('the manifest is consumed, not dead configuration', () => {
  /**
   * AWS-00 acceptance criterion 6. A manifest nothing reads is documentation
   * wearing a .ts extension. Two real consumers:
   *
   *  1. GET /adapter-manifest serves it, and REFUSES to serve an invalid one
   *     rather than handing other systems a declaration that failed its own
   *     validation.
   *  2. The permission policy generator and capability status both read the
   *     same registry the manifest is derived from, so a capability cannot
   *     appear in the manifest without appearing in the IAM policy.
   */
  it('is served by a route that refuses an invalid manifest', () => {
    const src = readFileSync(join(__dirname, '..', 'routes', 'adapterManifest.ts'), 'utf8');
    expect(src).toContain('buildManifest()');
    expect(src).toContain('validateManifest(');
    expect(src).toMatch(/issues\.length > 0/);
    expect(src).toContain('errJson(500');
  });

  it('shares its source of truth with the IAM policy generator', () => {
    const registry = readFileSync(join(__dirname, 'capabilityRegistry.ts'), 'utf8');
    expect(registry).toContain('allRequiredPermissions');
    // Both read AWS_CAPABILITIES, so a capability cannot exist in the
    // manifest while being absent from the generated least-privilege policy.
    const manifestKeys = buildManifest().capabilities.map((c) => c.key);
    expect(manifestKeys).toContain('sts');
    expect(manifestKeys.length).toBe(AWS_CAPABILITIES.length);
  });
});
