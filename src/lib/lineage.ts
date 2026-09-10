/**
 * Phase 2 — lineage primitives.
 *
 * Deterministic identity and provenance for AWS-derived records. Everything
 * here is pure and synchronous except the hashes, which use the same
 * `crypto.subtle` primitive the rest of this codebase already uses.
 */
import type { ScannedResource } from './scanners/types';

/**
 * Version of the normalization applied by `runResourceStep`. Bump this when
 * the mapping from ScannedResource to a canonical row changes in a way that
 * alters stored values.
 *
 * It is recorded on every observation so an old row remains interpretable:
 * without it, a fingerprint that changed because our own mapping changed is
 * indistinguishable from one that changed because AWS did.
 */
export const NORMALIZATION_VERSION = '2026-09-10.1';

/** Shape of the provider payload this collector understands. */
export const SOURCE_SCHEMA_VERSION = 'aws.scanned_resource.v1';

/** AWS partitions. Not a guess -- these are the five AWS actually operates. */
export const AWS_PARTITIONS = ['aws', 'aws-cn', 'aws-us-gov', 'aws-iso', 'aws-iso-b'] as const;
export type AwsPartition = (typeof AWS_PARTITIONS)[number];

/**
 * Region NAME format, deliberately not a list of known regions.
 *
 * The connector hardcodes 17 regions (AWS-P1-01). Validating membership
 * against that list would quarantine every resource in a region AWS launched
 * afterwards -- turning a healthy account into a pile of "invalid" records.
 * An over-strict validator manufactures false quarantines, which is its own
 * dishonesty. Format plus partition consistency is what can be checked
 * without knowing AWS's current region roster.
 *
 * Matches us-east-1, ap-southeast-4, eu-west-3, cn-north-1, us-gov-west-1,
 * us-iso-east-1, il-central-1.
 */
const REGION_FORMAT = /^[a-z]{2,3}(?:-[a-z]+){1,3}-\d{1,2}$/;

export function isValidRegionFormat(region: string): boolean {
  return REGION_FORMAT.test(region);
}

export function isValidPartition(value: string): value is AwsPartition {
  return (AWS_PARTITIONS as readonly string[]).includes(value);
}

/** The partition a region belongs to, by AWS's own region-prefix convention. */
export function partitionForRegion(region: string | null): AwsPartition | null {
  if (!region) return null;
  if (region.startsWith('cn-')) return 'aws-cn';
  if (region.startsWith('us-gov-')) return 'aws-us-gov';
  if (region.startsWith('us-isob-')) return 'aws-iso-b';
  if (region.startsWith('us-iso-')) return 'aws-iso';
  return isValidRegionFormat(region) ? 'aws' : null;
}

export interface ParsedArn {
  partition: string;
  service: string;
  region: string;
  /** Empty string for ARNs that legitimately carry no account (e.g. S3 buckets). */
  accountId: string;
  resource: string;
}

/**
 * Parses an ARN. Returns null for anything that is not one -- callers treat
 * "not an ARN" as "no ARN evidence", never as invalid, because most
 * ScannedResource.resourceId values are bare ids rather than ARNs.
 */
export function parseArn(value: string | null | undefined): ParsedArn | null {
  if (!value || !value.startsWith('arn:')) return null;
  // arn:partition:service:region:account-id:resource(/|:)...
  const parts = value.split(':');
  if (parts.length < 6) return null;
  const [, partition, service, region, accountId] = parts;
  if (!partition || !service) return null;
  return { partition, service, region: region ?? '', accountId: accountId ?? '', resource: parts.slice(5).join(':') };
}

/**
 * Finds an ARN for a scanned resource, if one is available.
 *
 * Scanners are inconsistent about where they put it -- some use the id
 * itself, most park it in metadata under one of several casings. Checking
 * all of them is what makes the account-mismatch and partition rules apply
 * to real data rather than to the handful of scanners that happen to agree.
 */
export function extractArn(r: ScannedResource): string | null {
  if (r.resourceId.startsWith('arn:')) return r.resourceId;
  const meta = r.metadata ?? {};
  for (const key of ['arn', 'Arn', 'ARN', 'resourceArn', 'ResourceArn']) {
    const value = (meta as Record<string, unknown>)[key];
    if (typeof value === 'string' && value.startsWith('arn:')) return value;
  }
  return null;
}

/**
 * JSON with object keys sorted at every depth.
 *
 * This is load-bearing, not tidiness. `JSON.stringify` emits keys in
 * insertion order, so two logically identical AWS responses that happened to
 * build their objects in a different order would hash differently -- every
 * scan would then look like "the resource changed", writing a new observation
 * row each time and destroying the dedupe the fingerprint exists to provide.
 */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(',')}}`;
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Identity of one OBSERVATION: everything this collector stores about the
 * resource. Two observations with the same fingerprint are the same
 * observation seen twice and are deduplicated.
 *
 * Fields are separated by U+001F, the same unambiguous delimiter the audit
 * hash chain uses, so no rearrangement of values can produce the same input.
 */
export async function fingerprintObservation(r: ScannedResource): Promise<string> {
  return sha256Hex(
    [
      r.resourceTypeKey,
      r.resourceId,
      r.resourceName ?? '',
      r.region ?? '',
      r.state ?? '',
      String(r.isDefault ?? false),
      stableStringify(r.tags ?? {}),
      stableStringify(r.metadata ?? {}),
      stableStringify(r.relationships ?? {}),
    ].join('\u001f'),
  );
}

/**
 * Identity of the resource's CONFIGURATION only -- state, metadata and
 * relationships, excluding tags and display name.
 *
 * Separate from the observation fingerprint so "someone retagged it" is
 * distinguishable from "its configuration changed". Collapsing the two would
 * make every tag edit look like a configuration drift event.
 */
export async function configurationHash(r: ScannedResource): Promise<string> {
  return sha256Hex(
    [r.resourceTypeKey, r.resourceId, r.state ?? '', stableStringify(r.metadata ?? {}), stableStringify(r.relationships ?? {})].join('\u001f'),
  );
}
