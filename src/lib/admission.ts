/**
 * Phase 2 — the admission pipeline.
 *
 * Every record a scanner returns ends as exactly one of ACCEPTED or
 * QUARANTINED. There is no third path, and in particular no path where a
 * record is dropped because a check failed -- that is hard NO-GO #1
 * ("invalid records can silently disappear") and it is what the code did
 * before this existed.
 *
 * Ordering matters and follows §6: cheap identity checks first, so a record
 * missing an id is refused with MISSING_REQUIRED_IDENTITY rather than
 * reaching the catalog lookup and being refused for the wrong reason. The
 * reason code a customer sees should name the first thing actually wrong.
 */
import type { ScannedResource } from './scanners/types';
import {
  NORMALIZATION_VERSION,
  SOURCE_SCHEMA_VERSION,
  configurationHash,
  extractArn,
  fingerprintObservation,
  isValidPartition,
  isValidRegionFormat,
  parseArn,
  partitionForRegion,
} from './lineage';

export type QuarantineReason =
  | 'INVALID_SCHEMA'
  | 'MISSING_REQUIRED_IDENTITY'
  | 'INVALID_PROVIDER_ID'
  | 'INVALID_REGION'
  | 'INVALID_PARTITION'
  | 'UNKNOWN_RESOURCE_TYPE'
  | 'ACCOUNT_MISMATCH'
  | 'DUPLICATE_CONFLICT'
  | 'NORMALIZATION_FAILURE'
  | 'TENANT_CONTEXT_MISSING';

export interface AdmissionContext {
  /** Fails closed when absent -- see admitObservations. */
  orgId: string | null;
  connectionId: string;
  /** The AWS account this connection is bound to. */
  accountNativeId: string | null;
  /** Catalogued resource type keys. The catalog is authoritative here. */
  knownResourceTypes: ReadonlySet<string>;
  providerService?: string;
  providerOperation?: string;
}

export interface AcceptedRecord {
  kind: 'accepted';
  resource: ScannedResource;
  partition: string | null;
  arn: string | null;
  recordFingerprint: string;
  configurationHash: string;
  normalizationVersion: string;
  sourceSchemaVersion: string;
}

export interface QuarantinedRecord {
  kind: 'quarantined';
  resource: ScannedResource;
  reasonCode: QuarantineReason;
  reasonDetail: string;
  validationRule: string;
  retryable: boolean;
  partition: string | null;
  recordFingerprint: string | null;
}

export type AdmissionOutcome = AcceptedRecord | QuarantinedRecord;

/** Largest payload retained on a quarantine row, in characters of JSON. */
export const MAX_QUARANTINE_PAYLOAD_CHARS = 16_000;

/**
 * Keys whose values are never persisted to quarantine evidence, whatever a
 * scanner happens to have put in metadata.
 *
 * Scanners are not supposed to place credential material in metadata and none
 * currently does. This exists because quarantine is the one place a raw
 * provider payload IS retained, so the cost of being wrong is a secret
 * written to a table a customer can read -- and the check costs nothing.
 */
const REDACT_KEYS = /^(.*(secret|password|passwd|token|credential|privatekey|private_key|sessiontoken|accesskey|access_key|authorization|apikey|api_key).*)$/i;

/** Recursively redacts secret-looking values and caps the payload's size. */
export function redactPayload(value: unknown): { payload: unknown; truncated: boolean } {
  const redacted = redact(value, 0);
  const text = JSON.stringify(redacted) ?? 'null';
  if (text.length <= MAX_QUARANTINE_PAYLOAD_CHARS) return { payload: redacted, truncated: false };
  return {
    payload: { __truncated: true, __original_chars: text.length, preview: text.slice(0, MAX_QUARANTINE_PAYLOAD_CHARS) },
    truncated: true,
  };
}

function redact(value: unknown, depth: number): unknown {
  if (depth > 12 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = REDACT_KEYS.test(k) ? '[redacted]' : redact(v, depth + 1);
  }
  return out;
}

function quarantine(
  resource: ScannedResource,
  reasonCode: QuarantineReason,
  validationRule: string,
  reasonDetail: string,
  retryable: boolean,
  partition: string | null = null,
  recordFingerprint: string | null = null,
): QuarantinedRecord {
  return { kind: 'quarantined', resource, reasonCode, reasonDetail, validationRule, retryable, partition, recordFingerprint };
}

/**
 * Classifies ONE record. Pure apart from hashing, so every rule below is
 * unit-testable without a database.
 */
export async function classifyRecord(r: ScannedResource, ctx: AdmissionContext): Promise<AdmissionOutcome> {
  // --- 1. schema shape -----------------------------------------------------
  // Guards against a scanner returning something that is not a record at all.
  // Typed as ScannedResource, but the values come from parsed provider JSON,
  // so the type is a claim about intent rather than a runtime guarantee.
  if (r === null || typeof r !== 'object') {
    return quarantine(r, 'INVALID_SCHEMA', 'schema.is_object', 'Record is not an object.', false);
  }
  for (const [field, value] of [
    ['tags', r.tags],
    ['metadata', r.metadata],
    ['relationships', r.relationships],
  ] as const) {
    if (value !== undefined && (value === null || typeof value !== 'object' || Array.isArray(value))) {
      return quarantine(r, 'INVALID_SCHEMA', `schema.${field}_is_object`, `\`${field}\` must be an object when present.`, false);
    }
  }

  // --- 2. identity ---------------------------------------------------------
  if (typeof r.resourceTypeKey !== 'string' || r.resourceTypeKey.trim() === '') {
    return quarantine(r, 'MISSING_REQUIRED_IDENTITY', 'identity.resource_type_present', 'Record has no resourceTypeKey.', false);
  }
  if (typeof r.resourceId !== 'string' || r.resourceId.trim() === '') {
    // Before this rule, an empty id upserted against a conflict key
    // containing an empty string -- one row per type quietly standing in for
    // every unidentifiable resource.
    return quarantine(r, 'MISSING_REQUIRED_IDENTITY', 'identity.resource_id_present', 'Record has no resourceId.', false);
  }

  // --- 3. provider id well-formedness -------------------------------------
  if (r.resourceId.length > 1024) {
    return quarantine(r, 'INVALID_PROVIDER_ID', 'provider_id.length', `resourceId is ${r.resourceId.length} characters; the maximum is 1024.`, false);
  }
  // Control characters only (U+0000-U+001F, U+007F), written as an explicit
  // escaped range. The shorthand form of this class is a literal
  // space-to-hyphen RANGE, which would quarantine every id containing a
  // hyphen -- that is to say, almost every AWS resource id there is.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(r.resourceId)) {
    return quarantine(r, 'INVALID_PROVIDER_ID', 'provider_id.control_characters', 'resourceId contains control characters.', false);
  }

  const arn = extractArn(r);
  const parsedArn = parseArn(arn);

  // --- 4. partition --------------------------------------------------------
  // Partition comes from the ARN when there is one, otherwise it is inferred
  // from the region. A record with neither is accepted with a null partition
  // rather than refused: most bare-id resources in commercial AWS carry no
  // partition evidence at all, and quarantining them would reject nearly the
  // whole estate.
  const regionPartition = partitionForRegion(r.region ?? null);
  let partition: string | null = parsedArn?.partition ?? regionPartition;

  if (parsedArn && !isValidPartition(parsedArn.partition)) {
    return quarantine(r, 'INVALID_PARTITION', 'partition.known', `ARN declares partition "${parsedArn.partition}", which is not an AWS partition.`, false, null);
  }
  if (parsedArn && regionPartition && parsedArn.partition !== regionPartition) {
    return quarantine(
      r,
      'INVALID_PARTITION',
      'partition.region_consistency',
      `ARN partition "${parsedArn.partition}" does not match the partition implied by region "${r.region}" ("${regionPartition}").`,
      false,
      partition,
    );
  }

  // --- 5. region -----------------------------------------------------------
  // A null region is LEGITIMATE: ScannedResource documents it as null for
  // global services (IAM, Route 53, S3 bucket-level). Only a present but
  // malformed region is a problem.
  if (r.region !== null && r.region !== undefined) {
    if (typeof r.region !== 'string' || !isValidRegionFormat(r.region)) {
      return quarantine(r, 'INVALID_REGION', 'region.format', `"${String(r.region)}" is not a valid AWS region name.`, false, partition);
    }
  }

  // --- 6. account ----------------------------------------------------------
  // Only assertable when the ARN carries an account id. Plenty legitimately
  // do not -- `arn:aws:s3:::bucket` has an empty account field -- and
  // treating "no evidence" as "mismatch" would quarantine every S3 bucket.
  if (parsedArn && parsedArn.accountId && ctx.accountNativeId && parsedArn.accountId !== ctx.accountNativeId) {
    return quarantine(
      r,
      'ACCOUNT_MISMATCH',
      'account.matches_connection',
      `Resource belongs to AWS account ${parsedArn.accountId}, but this connection is bound to ${ctx.accountNativeId}.`,
      false,
      partition,
    );
  }

  // --- 7. resource type ----------------------------------------------------
  // Retryable: the catalog gaining the entry is exactly what makes this
  // record valid later, so reprocessing is meaningful here in a way it is not
  // for a malformed payload.
  if (!ctx.knownResourceTypes.has(r.resourceTypeKey)) {
    return quarantine(
      r,
      'UNKNOWN_RESOURCE_TYPE',
      'resource_type.catalogued',
      `"${r.resourceTypeKey}" is not in resource_type_catalog, so the record cannot be classified.`,
      true,
      partition,
    );
  }

  // --- 8. normalization + fingerprint --------------------------------------
  let recordFingerprint: string;
  let configHash: string;
  try {
    [recordFingerprint, configHash] = await Promise.all([fingerprintObservation(r), configurationHash(r)]);
  } catch (err) {
    return quarantine(
      r,
      'NORMALIZATION_FAILURE',
      'normalization.fingerprint',
      err instanceof Error ? err.message : 'Fingerprinting failed.',
      true,
      partition,
    );
  }

  return {
    kind: 'accepted',
    resource: r,
    partition,
    arn,
    recordFingerprint,
    configurationHash: configHash,
    normalizationVersion: NORMALIZATION_VERSION,
    sourceSchemaVersion: SOURCE_SCHEMA_VERSION,
  };
}

export interface AdmissionResult {
  accepted: AcceptedRecord[];
  quarantined: QuarantinedRecord[];
  counts: { observed: number; accepted: number; quarantined: number; rejected: number };
}

/**
 * Runs the pipeline over a scanner's whole output.
 *
 * Two things this does beyond looping `classifyRecord`:
 *
 * 1. **Fails closed on missing tenant context.** Without an org there is no
 *    tenant to attribute evidence to, and writing it anyway is how records
 *    end up in the wrong customer's account. Every record is quarantined
 *    with TENANT_CONTEXT_MISSING rather than the batch being dropped,
 *    because dropping is the silent-disappearance failure.
 *
 * 2. **Detects intra-batch identity conflicts.** Two records claiming the
 *    same canonical identity with incompatible provider identity (different
 *    ARNs) are ambiguous. Both are quarantined rather than one silently
 *    winning the upsert, because canonical state must not be overwritten
 *    with data we cannot disambiguate (§8).
 */
export async function admitObservations(records: ScannedResource[], ctx: AdmissionContext): Promise<AdmissionResult> {
  const observed = records.length;

  if (!ctx.orgId) {
    const quarantined = records.map((r) =>
      quarantine(r, 'TENANT_CONTEXT_MISSING', 'tenant.context_present', 'No organization context was resolved for this ingestion; nothing may be admitted.', true),
    );
    return { accepted: [], quarantined, counts: { observed, accepted: 0, quarantined: observed, rejected: 0 } };
  }

  const outcomes = await Promise.all(records.map((r) => classifyRecord(r, ctx)));

  // Group accepted records by canonical identity to find conflicts.
  const byIdentity = new Map<string, AcceptedRecord[]>();
  for (const o of outcomes) {
    if (o.kind !== 'accepted') continue;
    const key = `${o.resource.resourceTypeKey}\u001f${o.resource.resourceId}`;
    const list = byIdentity.get(key);
    if (list) list.push(o);
    else byIdentity.set(key, [o]);
  }

  const conflicted = new Set<AcceptedRecord>();
  for (const [, group] of byIdentity) {
    if (group.length < 2) continue;
    // Same identity twice with the SAME provider identity is a duplicate
    // listing, not a conflict -- dedupe it and move on. Different ARNs mean
    // we genuinely cannot tell which resource this is.
    const arns = new Set(group.map((g) => g.arn ?? ''));
    if (arns.size > 1) for (const g of group) conflicted.add(g);
  }

  const accepted: AcceptedRecord[] = [];
  const quarantined: QuarantinedRecord[] = [];
  const seenIdentity = new Set<string>();

  for (const o of outcomes) {
    if (o.kind === 'quarantined') {
      quarantined.push(o);
      continue;
    }
    if (conflicted.has(o)) {
      quarantined.push(
        quarantine(
          o.resource,
          'DUPLICATE_CONFLICT',
          'identity.conflict',
          `Two records in this batch claim resource "${o.resource.resourceId}" of type "${o.resource.resourceTypeKey}" with different ARNs.`,
          false,
          o.partition,
          o.recordFingerprint,
        ),
      );
      continue;
    }
    // Identical duplicate listings collapse to one accepted record.
    const key = `${o.resource.resourceTypeKey}\u001f${o.resource.resourceId}`;
    if (seenIdentity.has(key)) continue;
    seenIdentity.add(key);
    accepted.push(o);
  }

  return {
    accepted,
    quarantined,
    counts: {
      observed,
      // Deduplicated duplicates are counted as accepted so the batch's
      // accounting constraint (observed = accepted + quarantined + rejected)
      // holds. They were observed and they were admitted -- collapsing to one
      // canonical row is what admission MEANS for a repeated listing.
      accepted: observed - quarantined.length,
      quarantined: quarantined.length,
      rejected: 0,
    },
  };
}
