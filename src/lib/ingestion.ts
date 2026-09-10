/**
 * Phase 2 — persisting an ingestion batch and its evidence.
 *
 * The admission decisions themselves live in admission.ts and are pure. This
 * module is only the write side: open a batch, persist what was admitted and
 * what was refused, close the batch with truthful counters.
 *
 * Every write here goes through the service role. `ingestion_batches`,
 * `provider_requests`, `resource_observations` and `quarantine_records` are
 * member-READ only: they are source evidence, and evidence the customer can
 * edit is not evidence.
 */
import type { Db } from '@horizonvigil/shared-lib';
import type { AcceptedRecord, QuarantinedRecord } from './admission';
import { redactPayload } from './admission';
import { NORMALIZATION_VERSION, SOURCE_SCHEMA_VERSION } from './lineage';
import type { AwsCallRecord } from './awsApi';

/** Identifies this collector in lineage. Bumped when collection behaviour changes. */
export const COLLECTOR = 'horizonvigil-connector-aws';
export const COLLECTOR_VERSION = '2026-09-10.1';

export interface BatchIdentity {
  id: string;
  orgId: string;
  connectionId: string;
  accountNativeId: string | null;
  collectionRunId: string | null;
  collectionStepId: string;
}

export interface OpenBatchInput {
  orgId: string;
  connectionId: string;
  accountNativeId: string | null;
  collectionRunId: string | null;
  collectionStepId: string;
  collector?: string;
  correlationId?: string | null;
}

/**
 * Opens a batch in RUNNING. It is opened BEFORE the scanner runs, so a crash
 * mid-step leaves a visible RUNNING batch rather than no evidence that
 * ingestion was ever attempted. An absent batch and a failed batch must not
 * look the same.
 */
export async function openBatch(db: Db, input: OpenBatchInput): Promise<BatchIdentity> {
  const [row] = await db.insert<{ id: string }[]>('ingestion_batches', {
    org_id: input.orgId,
    connection_id: input.connectionId,
    account_native_id: input.accountNativeId,
    provider: 'aws',
    collection_run_id: input.collectionRunId,
    collection_step_id: input.collectionStepId,
    collector: input.collector ?? COLLECTOR,
    collector_version: COLLECTOR_VERSION,
    source_type: 'aws_api',
    status: 'RUNNING',
    correlation_id: input.correlationId ?? null,
  });
  return {
    id: row.id,
    orgId: input.orgId,
    connectionId: input.connectionId,
    accountNativeId: input.accountNativeId,
    collectionRunId: input.collectionRunId,
    collectionStepId: input.collectionStepId,
  };
}

/**
 * Records the AWS calls this batch made.
 *
 * `provider_request_id` is AWS's own id and is NULL when the response did not
 * carry one; `request_id_available` says which case it is, so a null is a
 * stated fact rather than something to guess at. Fabricating an id would be
 * fabricating evidence (hard NO-GO #9).
 */
export async function recordProviderRequests(db: Db, batch: BatchIdentity, calls: AwsCallRecord[]): Promise<void> {
  if (calls.length === 0) return;
  await db.insert(
    'provider_requests',
    calls.map((c) => ({
      org_id: batch.orgId,
      connection_id: batch.connectionId,
      ingestion_batch_id: batch.id,
      provider: 'aws',
      service: c.service,
      operation: c.action,
      region: c.region === 'global' ? null : c.region,
      provider_request_id: c.requestId ?? null,
      request_id_available: Boolean(c.requestId),
      attempt: c.attempts,
      retry_count: Math.max(0, c.attempts - 1),
      started_at: new Date(c.startedAt).toISOString(),
      completed_at: new Date(c.completedAt).toISOString(),
      duration_ms: Math.max(0, c.completedAt - c.startedAt),
      http_status: c.status || null,
      outcome: c.outcome,
      throttled: c.outcome === 'throttled',
      // The normalized vocabulary only. Raw AWS error text has been observed
      // to carry account identifiers and does not belong in stored evidence.
      error_code: c.normalizedCode ?? null,
    })),
    'return=minimal',
  );
}

export interface PersistInput {
  batch: BatchIdentity;
  accepted: AcceptedRecord[];
  /** Canonical row id per `${resourceTypeKey}${resourceId}`, from the caller's own upsert. */
  canonicalIdByIdentity: Map<string, string>;
  providerService: string | null;
  providerOperation: string | null;
  collectorObservedAt: string;
}

/**
 * Writes one observation per accepted record.
 *
 * Deduplicated by (connection, type, provider id, fingerprint) in the
 * DATABASE. A repeated identical observation therefore collapses onto the
 * existing row -- bumping `last_observed_at` and `observation_count` -- while
 * a changed fingerprint becomes a genuinely new observation with its own
 * lineage. Doing this in application code would race between concurrent
 * steps; the unique index does not.
 *
 * `observation_count` is incremented by the merge only in the sense that we
 * resend it; PostgREST has no atomic increment. It is therefore a
 * lower-bound count of sightings, and is documented as such rather than
 * presented as exact.
 */
export async function recordObservations(db: Db, input: PersistInput): Promise<void> {
  if (input.accepted.length === 0) return;

  const rows = input.accepted.map((a) => {
    const key = `${a.resource.resourceTypeKey}${a.resource.resourceId}`;
    return {
      org_id: input.batch.orgId,
      connection_id: input.batch.connectionId,
      account_native_id: input.batch.accountNativeId,
      ingestion_batch_id: input.batch.id,
      provider: 'aws',
      provider_service: input.providerService,
      provider_operation: input.providerOperation,
      provider_resource_id: a.resource.resourceId,
      provider_resource_arn: a.arn,
      resource_type_key: a.resource.resourceTypeKey,
      partition: a.partition,
      region: a.resource.region,
      canonical_resource_id: input.canonicalIdByIdentity.get(key) ?? null,
      // NULL on purpose: AWS list operations do not report when the provider
      // last observed the resource. Filling this with collector time would
      // manufacture provider evidence.
      provider_observed_at: null,
      collector_observed_at: input.collectorObservedAt,
      normalized_at: input.collectorObservedAt,
      source_schema_version: a.sourceSchemaVersion,
      normalization_version: a.normalizationVersion,
      record_fingerprint: a.recordFingerprint,
      configuration_hash: a.configurationHash,
      source_freshness: 'fresh',
      validation_status: 'accepted',
      normalization_status: 'normalized',
      last_observed_at: input.collectorObservedAt,
    };
  });

  await db.insert(
    'resource_observations?on_conflict=connection_id,resource_type_key,provider_resource_id,record_fingerprint',
    rows,
    'resolution=merge-duplicates,return=minimal',
  );
}

export interface QuarantineInput {
  batch: BatchIdentity;
  quarantined: QuarantinedRecord[];
  providerService: string | null;
  providerOperation: string | null;
  collectorObservedAt: string;
}

/**
 * Writes the refused records, with the offending payload attached.
 *
 * Unlike accepted records, the payload IS retained: it is the evidence, and
 * without it "what arrived?" cannot be answered. It is redacted and
 * size-capped by `redactPayload` first.
 */
export async function recordQuarantine(db: Db, input: QuarantineInput): Promise<void> {
  if (input.quarantined.length === 0) return;

  const rows = input.quarantined.map((q) => {
    const { payload, truncated } = redactPayload(q.resource);
    return {
      org_id: input.batch.orgId,
      connection_id: input.batch.connectionId,
      account_native_id: input.batch.accountNativeId,
      ingestion_batch_id: input.batch.id,
      collection_run_id: input.batch.collectionRunId,
      collection_step_id: input.batch.collectionStepId,
      provider: 'aws',
      provider_service: input.providerService,
      provider_operation: input.providerOperation,
      // Nullable: a record refused for having no id genuinely has none.
      provider_resource_id: typeof q.resource?.resourceId === 'string' && q.resource.resourceId !== '' ? q.resource.resourceId : null,
      resource_type_key: typeof q.resource?.resourceTypeKey === 'string' && q.resource.resourceTypeKey !== '' ? q.resource.resourceTypeKey : null,
      partition: q.partition,
      region: typeof q.resource?.region === 'string' ? q.resource.region : null,
      provider_observed_at: null,
      collector_observed_at: input.collectorObservedAt,
      reason_code: q.reasonCode,
      reason_detail: q.reasonDetail,
      validation_rule: q.validationRule,
      payload,
      payload_truncated: truncated,
      record_fingerprint: q.recordFingerprint,
      source_schema_version: SOURCE_SCHEMA_VERSION,
      status: 'QUARANTINED',
      retryable: q.retryable,
    };
  });

  await db.insert('quarantine_records', rows, 'return=minimal');
}

export interface CloseBatchInput {
  observed: number;
  accepted: number;
  quarantined: number;
  rejected: number;
  errorCount: number;
  errorSummary?: string | null;
  /** Null when AWS did not tell us how many results to expect -- the usual case. */
  expectedCount?: number | null;
  failed?: boolean;
}

/**
 * Closes the batch.
 *
 * The status is DERIVED from what happened, never passed in as a wish:
 * anything quarantined or any failed call makes the batch
 * PARTIALLY_SUCCEEDED, not SUCCEEDED. "Do not mark a batch successful if
 * required ingestion work failed" is the rule, and a batch that silently
 * discarded records while reporting success is exactly the dishonesty this
 * phase exists to remove.
 */
export async function closeBatch(db: Db, batchId: string, input: CloseBatchInput): Promise<'SUCCEEDED' | 'PARTIALLY_SUCCEEDED' | 'FAILED'> {
  const status = input.failed
    ? 'FAILED'
    : input.quarantined > 0 || input.errorCount > 0
      ? 'PARTIALLY_SUCCEEDED'
      : 'SUCCEEDED';

  await db.update(
    'ingestion_batches',
    { id: `eq.${batchId}` },
    {
      status,
      completed_at: new Date().toISOString(),
      expected_count: input.expectedCount ?? null,
      observed_count: input.observed,
      accepted_count: input.accepted,
      quarantined_count: input.quarantined,
      rejected_count: input.rejected,
      error_count: input.errorCount,
      error_summary: input.errorSummary ?? null,
      updated_at: new Date().toISOString(),
    },
    'return=minimal',
  );
  return status;
}

export { NORMALIZATION_VERSION };
