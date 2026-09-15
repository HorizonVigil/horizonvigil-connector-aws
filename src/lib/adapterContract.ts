/**
 * AWS-00 — the versioned provider adapter contract and its machine-readable
 * capability manifest.
 *
 * WHY THIS IS DERIVED, NOT DECLARED
 *
 * `AWS_CAPABILITIES` in capabilityRegistry.ts already records, per
 * capability, whether it is genuinely implemented, whether a permission
 * probe covers it, which IAM actions it needs, which tables it writes and
 * which UI consumes it. A hand-written manifest listing the same
 * capabilities would be a second source of truth that drifts from the first
 * — and a manifest that disagrees with the code is worse than none, because
 * it is the artifact other systems trust.
 *
 * So the manifest is BUILT from the registry. Adding a capability to the
 * registry adds it to the manifest; there is no second place to update and
 * no way for the two to disagree.
 *
 * WHY TWO VERSIONS
 *
 *   CONTRACT_VERSION — the SHAPE other providers must satisfy. Azure, GCP
 *                      and OCI implement this same contract, so it changes
 *                      only when the cross-provider shape changes.
 *   ADAPTER_VERSION  — this AWS implementation. Changes when AWS capability
 *                      coverage changes, independently of the contract.
 *
 * Collapsing them into one number would mean an AWS-only change forced a
 * contract bump that every other provider then had to react to.
 */
import { AWS_CAPABILITIES, type AwsCapability } from './capabilityRegistry';

/**
 * The cross-provider contract shape. Bump only when the manifest structure
 * changes in a way other providers must follow.
 */
export const CONTRACT_VERSION = '1.0.0';

/**
 * This adapter's own version. Tracks the connector package, so a released
 * connector and the manifest it publishes cannot disagree about which build
 * produced them.
 */
export const ADAPTER_VERSION = '1.0.0';

/** Capability support states. Deliberately not a boolean. */
export type CapabilitySupport =
  /** Implemented, and a permission probe actively verifies it. */
  | 'SUPPORTED_VERIFIED'
  /** Implemented, but nothing probes it — it can fail silently. */
  | 'SUPPORTED_UNVERIFIED'
  /** Exists in code and is deliberately switched off for V1. */
  | 'GATED_V2'
  /** Not implemented. */
  | 'UNSUPPORTED';

export interface ManifestCapability {
  key: string;
  label: string;
  support: CapabilitySupport;
  lifecycle: AwsCapability['lifecycle'];
  awsApis: readonly string[];
  requiredPermissions: readonly string[];
  dataStored: readonly string[];
  /** Provider mutation. False everywhere in V1 by policy. */
  actionSupported: boolean;
}

export interface AdapterManifest {
  provider: 'aws';
  contract_version: string;
  adapter_version: string;
  generated_at: string;
  capabilities: ManifestCapability[];
  summary: {
    total: number;
    supported_verified: number;
    supported_unverified: number;
    gated_v2: number;
    unsupported: number;
  };
}

/**
 * A boolean `supported: true` cannot express the distinction that matters
 * most here: a capability that is implemented but NOT probed can fail every
 * night while the connection still reports healthy. That is the exact gap
 * the capability registry was built to expose, so the manifest preserves it
 * rather than flattening it back into a yes/no.
 */
export function supportFor(capability: AwsCapability): CapabilitySupport {
  if (!capability.implemented) return 'UNSUPPORTED';
  if (capability.lifecycle === 'v2') return 'GATED_V2';
  return capability.probed ? 'SUPPORTED_VERIFIED' : 'SUPPORTED_UNVERIFIED';
}

export function buildManifest(now: string = new Date().toISOString()): AdapterManifest {
  const capabilities: ManifestCapability[] = AWS_CAPABILITIES.map((c) => ({
    key: c.key,
    label: c.label,
    support: supportFor(c),
    lifecycle: c.lifecycle,
    awsApis: c.awsApis,
    requiredPermissions: c.requiredPermissions,
    dataStored: c.dataStored,
    actionSupported: c.actionSupported,
  }));

  const count = (s: CapabilitySupport) => capabilities.filter((c) => c.support === s).length;

  return {
    provider: 'aws',
    contract_version: CONTRACT_VERSION,
    adapter_version: ADAPTER_VERSION,
    generated_at: now,
    capabilities,
    summary: {
      total: capabilities.length,
      supported_verified: count('SUPPORTED_VERIFIED'),
      supported_unverified: count('SUPPORTED_UNVERIFIED'),
      gated_v2: count('GATED_V2'),
      unsupported: count('UNSUPPORTED'),
    },
  };
}

export interface ValidationIssue {
  capability: string;
  problem: string;
}

/**
 * Validates the manifest against the invariants a consumer may rely on.
 *
 * This exists so an invalid declaration cannot pass silently. Every rule
 * below corresponds to a way the manifest could lie:
 *
 *  - a duplicate key would make capability lookup non-deterministic
 *  - a supported capability with no AWS API is a claim with no mechanism
 *  - a supported capability with no required permission cannot be granted,
 *    so the generated least-privilege policy would be wrong
 *  - `actionSupported` true anywhere contradicts the V1 read-only policy
 *    the public copy states, and that copy has drifted back three times
 *  - a V2 capability presented as SUPPORTED would advertise something the
 *    server refuses with 403
 */
export function validateManifest(manifest: AdapterManifest): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const seen = new Set<string>();

  if (!/^\d+\.\d+\.\d+$/.test(manifest.contract_version)) {
    issues.push({ capability: '(manifest)', problem: `contract_version "${manifest.contract_version}" is not semver` });
  }
  if (!/^\d+\.\d+\.\d+$/.test(manifest.adapter_version)) {
    issues.push({ capability: '(manifest)', problem: `adapter_version "${manifest.adapter_version}" is not semver` });
  }

  for (const c of manifest.capabilities) {
    if (seen.has(c.key)) issues.push({ capability: c.key, problem: 'duplicate capability key' });
    seen.add(c.key);

    const isSupported = c.support === 'SUPPORTED_VERIFIED' || c.support === 'SUPPORTED_UNVERIFIED';

    if (isSupported && c.awsApis.length === 0) {
      issues.push({ capability: c.key, problem: 'declared supported but names no AWS API' });
    }
    if (isSupported && c.requiredPermissions.length === 0) {
      issues.push({ capability: c.key, problem: 'declared supported but requires no IAM permission' });
    }
    if (c.actionSupported) {
      issues.push({ capability: c.key, problem: 'actionSupported is true; V1 is read-only and must not claim provider mutation' });
    }
    if (c.lifecycle === 'v2' && isSupported) {
      issues.push({ capability: c.key, problem: 'v2 capability declared SUPPORTED; the server refuses it with 403' });
    }
  }

  const declared = manifest.summary.supported_verified + manifest.summary.supported_unverified
    + manifest.summary.gated_v2 + manifest.summary.unsupported;
  if (declared !== manifest.summary.total) {
    issues.push({ capability: '(manifest)', problem: `summary counts sum to ${declared}, total says ${manifest.summary.total}` });
  }

  return issues;
}

/**
 * Whether a capability may be used. The single question the rest of the
 * connector should ask — so "is this available?" has one answer rather than
 * each call site re-deriving it from lifecycle and implemented flags.
 */
export function isCapabilityAvailable(key: string, manifest: AdapterManifest = buildManifest()): boolean {
  const c = manifest.capabilities.find((x) => x.key === key);
  // An unknown key is NOT available. Returning true for something the
  // manifest has never heard of would make a typo look like a capability.
  if (!c) return false;
  return c.support === 'SUPPORTED_VERIFIED' || c.support === 'SUPPORTED_UNVERIFIED';
}
