import {
  Hono,
  getAuthContext,
  requireOrgId,
  createDb,
  requireMenuPermission,
  getOrgConnectionIds,
  getActiveScope,
  requirePermittedConnection,
  inFilter,
  guarded,
  okJson,
  errJson,
  parsePagination,
  paginatedEnvelope,
  writeAuditLog,
  type Db,
  type Env,
} from '@horizonvigil/shared-lib';

/**
 * Phase 2 — lineage, ingestion batches and quarantine, read-only.
 *
 * Every handler resolves the caller's PERMITTED connection set first and
 * filters on it, rather than filtering on org alone. Filtering on org would
 * let a member with no grant on a connection read that connection's
 * ingestion evidence -- and provider request ids, batch ids and quarantine
 * payloads are exactly the kind of thing §20 says must not leak.
 *
 * A record outside the permitted set returns 404, never 403: a 403 confirms
 * the id exists, which is itself a disclosure (§20, "quarantine APIs do not
 * leak existence of another tenant's records").
 */
export const lineageRoutes = new Hono<{ Bindings: Env }>();

/**
 * Resolves the caller's permitted connections under their ACTIVE SCOPE, or
 * null when they have none.
 *
 * Threading the active scope is what makes §9's disjoint-scope requirement
 * real for lineage: a user scoped to one folder must not read ingestion
 * evidence from another, and filtering on org alone would let them.
 */
async function permittedConnections(db: Db, req: Request, orgId: string, userId: string | null): Promise<string[] | null> {
  const ids = await getOrgConnectionIds(db, orgId, userId ?? undefined, getActiveScope(req, orgId));
  return ids.length > 0 ? ids : null;
}

interface BatchRow {
  id: string;
  connection_id: string;
  account_native_id: string | null;
  provider: string;
  collection_run_id: string | null;
  collection_step_id: string | null;
  collector: string;
  collector_version: string | null;
  source_type: string;
  started_at: string;
  completed_at: string | null;
  status: string;
  expected_count: number | null;
  observed_count: number;
  accepted_count: number;
  quarantined_count: number;
  rejected_count: number;
  error_count: number;
  error_summary: string | null;
}

function mapBatch(b: BatchRow) {
  return {
    id: b.id,
    connectionId: b.connection_id,
    accountNativeId: b.account_native_id,
    provider: b.provider,
    collectionRunId: b.collection_run_id,
    collectionStepId: b.collection_step_id,
    collector: b.collector,
    collectorVersion: b.collector_version,
    sourceType: b.source_type,
    status: b.status,
    startedAt: b.started_at,
    completedAt: b.completed_at,
    counts: {
      /**
       * Null, not zero. AWS list operations do not report how many results
       * exist before paging them, so `expected = observed` would be a
       * reconciliation that always passes. Null says "not knowable", which
       * is the truth and is what §19 requires.
       */
      expected: b.expected_count,
      observed: b.observed_count,
      accepted: b.accepted_count,
      quarantined: b.quarantined_count,
      rejected: b.rejected_count,
      errors: b.error_count,
    },
    errorSummary: b.error_summary,
  };
}

/** GET /ingestion-batches — recent batches for the caller's permitted connections. */
lineageRoutes.get('/ingestion-batches', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const permitted = await permittedConnections(db, c.req.raw, orgId, auth.userId);
    const pagination = parsePagination(new URL(c.req.url));
    // No permitted connections means no evidence, not all evidence.
    if (!permitted) return okJson(paginatedEnvelope([], 0, pagination));

    const url = new URL(c.req.url);
    const status = url.searchParams.get('status');
    const connectionId = url.searchParams.get('connectionId');

    const filters: Record<string, string> = { connection_id: inFilter(permitted) };
    if (status) filters.status = `eq.${status}`;
    // A connectionId outside the permitted set intersects to nothing rather
    // than widening the query.
    if (connectionId && permitted.includes(connectionId)) filters.connection_id = `eq.${connectionId}`;
    else if (connectionId) return okJson(paginatedEnvelope([], 0, pagination));

    const [rows, total] = await db.selectWithCount<BatchRow[]>('ingestion_batches', {
      select: '*',
      filters,
      order: 'started_at.desc',
      offset: pagination.offset,
      limit: pagination.limit,
    });
    return okJson(paginatedEnvelope(rows.map(mapBatch), total, pagination));
  }),
);

/** GET /ingestion-batches/:id — one batch, with its provider requests. */
lineageRoutes.get('/ingestion-batches/:id', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const permitted = await permittedConnections(db, c.req.raw, orgId, auth.userId);
    if (!permitted) return errJson(404, 'Ingestion batch not found', { code: 'not_found' });

    const [batch] = await db.select<BatchRow[]>('ingestion_batches', {
      select: '*',
      filters: { id: `eq.${c.req.param('id')}`, connection_id: inFilter(permitted) },
      limit: 1,
    });
    if (!batch) return errJson(404, 'Ingestion batch not found', { code: 'not_found' });

    const requests = await db.select<
      {
        id: string; service: string; operation: string; region: string | null;
        provider_request_id: string | null; request_id_available: boolean;
        attempt: number; retry_count: number; started_at: string; completed_at: string | null;
        duration_ms: number | null; http_status: number | null; outcome: string;
        throttled: boolean; error_code: string | null;
      }[]
    >('provider_requests', {
      select: '*',
      filters: { ingestion_batch_id: `eq.${batch.id}` },
      order: 'started_at.asc',
      limit: 200,
    });

    return okJson({
      ...mapBatch(batch),
      providerRequests: requests.map((r) => ({
        id: r.id,
        service: r.service,
        operation: r.operation,
        region: r.region,
        /**
         * Null when AWS did not return one. `requestIdAvailable` states which
         * case this is rather than leaving the consumer to guess whether the
         * null means "absent" or "not captured" -- and nothing here invents
         * an id to fill the gap.
         */
        providerRequestId: r.provider_request_id,
        requestIdAvailable: r.request_id_available,
        attempt: r.attempt,
        retryCount: r.retry_count,
        startedAt: r.started_at,
        completedAt: r.completed_at,
        durationMs: r.duration_ms,
        httpStatus: r.http_status,
        outcome: r.outcome,
        throttled: r.throttled,
        errorCode: r.error_code,
      })),
    });
  }),
);

/**
 * GET /resources/:resourceId/lineage — where this canonical row came from.
 *
 * Answers the question this phase exists for: "exactly where did this data
 * come from, when was it observed, which AWS request produced it, which
 * ingestion run processed it, how was it transformed, and why was it
 * trusted?"
 */
lineageRoutes.get('/resources/:resourceId/lineage', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const permitted = await permittedConnections(db, c.req.raw, orgId, auth.userId);
    if (!permitted) return errJson(404, 'Resource not found', { code: 'not_found' });

    const [resource] = await db.select<
      {
        id: string; connection_id: string; account_id: string; resource_type_key: string;
        resource_id: string; region: string | null; partition: string | null;
        provider_resource_arn: string | null; source_type: string | null;
        ingestion_batch_id: string | null; provider_observed_at: string | null;
        collector_observed_at: string | null; ingested_at: string | null; normalized_at: string | null;
        source_schema_version: string | null; normalization_version: string | null;
        record_fingerprint: string | null; configuration_hash: string | null;
        lineage_state: string; last_seen_at: string;
      }[]
    >('cloud_resources', {
      select:
        'id,connection_id,account_id,resource_type_key,resource_id,region,partition,provider_resource_arn,source_type,' +
        'ingestion_batch_id,provider_observed_at,collector_observed_at,ingested_at,normalized_at,' +
        'source_schema_version,normalization_version,record_fingerprint,configuration_hash,lineage_state,last_seen_at',
      filters: { id: `eq.${c.req.param('resourceId')}`, connection_id: inFilter(permitted) },
      limit: 1,
    });
    if (!resource) return errJson(404, 'Resource not found', { code: 'not_found' });

    /**
     * A row that predates Phase 2 says so, plainly, instead of returning a
     * lineage object full of nulls that reads like a broken lookup. Its
     * provenance is genuinely unknown and was not invented (§12).
     */
    if (resource.lineage_state !== 'traced') {
      return okJson({
        resourceId: resource.id,
        lineageState: 'legacy_unknown',
        explanation:
          'This resource was recorded before ingestion lineage existed, so its source, ingestion batch and provider request are genuinely unknown. It will gain full lineage the next time a scan observes it.',
        observations: [],
        batch: null,
      });
    }

    const observations = await db.select<
      {
        id: string; ingestion_batch_id: string | null; provider_request_id: string | null;
        provider_service: string | null; provider_operation: string | null;
        provider_resource_id: string; provider_resource_arn: string | null;
        partition: string | null; region: string | null;
        provider_observed_at: string | null; collector_observed_at: string; ingested_at: string;
        normalized_at: string | null; source_schema_version: string | null; normalization_version: string | null;
        record_fingerprint: string; configuration_hash: string | null; source_freshness: string | null;
        validation_status: string; normalization_status: string;
        observation_count: number; first_observed_at: string; last_observed_at: string;
      }[]
    >('resource_observations', {
      select: '*',
      filters: { canonical_resource_id: `eq.${resource.id}` },
      order: 'last_observed_at.desc',
      limit: 20,
    });

    let batch: BatchRow | undefined;
    let batchRequests: { service: string; operation: string; region: string | null; provider_request_id: string | null; request_id_available: boolean; outcome: string }[] = [];
    if (resource.ingestion_batch_id) {
      [batch] = await db.select<BatchRow[]>('ingestion_batches', {
        select: '*',
        filters: { id: `eq.${resource.ingestion_batch_id}` },
        limit: 1,
      });
      if (batch) {
        batchRequests = await db.select<typeof batchRequests>('provider_requests', {
          select: 'service,operation,region,provider_request_id,request_id_available,outcome',
          filters: { ingestion_batch_id: `eq.${batch.id}` },
          order: 'started_at.asc',
          limit: 200,
        });
      }
    }

    return okJson({
      resourceId: resource.id,
      lineageState: resource.lineage_state,
      who: {
        connectionId: resource.connection_id,
        accountNativeId: resource.account_id,
        collector: batch?.collector ?? null,
        collectorVersion: batch?.collector_version ?? null,
      },
      what: {
        provider: 'aws',
        providerResourceId: resource.resource_id,
        providerResourceArn: resource.provider_resource_arn,
        resourceType: resource.resource_type_key,
      },
      where: { partition: resource.partition, region: resource.region },
      when: {
        /**
         * Three distinct facts, deliberately not collapsed.
         * `providerObservedAt` is null for most AWS list calls, which do not
         * report when the provider last observed the resource; filling it
         * with collector time would manufacture provider evidence.
         */
        providerObservedAt: resource.provider_observed_at,
        collectorObservedAt: resource.collector_observed_at,
        ingestedAt: resource.ingested_at,
        normalizedAt: resource.normalized_at,
        canonicalUpdatedAt: resource.last_seen_at,
      },
      how: {
        sourceType: resource.source_type,
        collectionRunId: batch?.collection_run_id ?? null,
        collectionStepId: batch?.collection_step_id ?? null,
        ingestionBatchId: resource.ingestion_batch_id,
      },
      transformation: {
        sourceSchemaVersion: resource.source_schema_version,
        normalizationVersion: resource.normalization_version,
        recordFingerprint: resource.record_fingerprint,
        configurationHash: resource.configuration_hash,
      },
      batch: batch ? mapBatch(batch) : null,
      /**
       * Every AWS request the batch that produced this row made.
       *
       * GRANULARITY, stated rather than implied: provider requests are
       * recorded per BATCH, not per record. A single scanner makes many calls
       * -- the EC2 scanner alone makes DescribeInstances, DescribeVolumes,
       * DescribeSnapshots and more -- and none of the 111 scanners reports
       * which call yielded which record. Attributing this specific resource
       * to one of them would be a guess presented as provenance, so the
       * honest answer is the full set, labelled as such.
       */
      providerRequests: {
        granularity: 'batch',
        note: 'These are all AWS requests made by the ingestion batch that produced this resource. The collector does not record which individual request yielded which record, so no per-record attribution is claimed.',
        requests: batchRequests.map((r) => ({
          service: r.service,
          operation: r.operation,
          region: r.region,
          providerRequestId: r.provider_request_id,
          requestIdAvailable: r.request_id_available,
          outcome: r.outcome,
        })),
      },
      observations: observations.map((o) => ({
        id: o.id,
        ingestionBatchId: o.ingestion_batch_id,
        providerService: o.provider_service,
        providerOperation: o.provider_operation,
        providerResourceArn: o.provider_resource_arn,
        region: o.region,
        partition: o.partition,
        providerObservedAt: o.provider_observed_at,
        collectorObservedAt: o.collector_observed_at,
        ingestedAt: o.ingested_at,
        normalizedAt: o.normalized_at,
        recordFingerprint: o.record_fingerprint,
        configurationHash: o.configuration_hash,
        sourceSchemaVersion: o.source_schema_version,
        normalizationVersion: o.normalization_version,
        sourceFreshness: o.source_freshness,
        validationStatus: o.validation_status,
        normalizationStatus: o.normalization_status,
        /** A lower bound: PostgREST has no atomic increment, so repeated identical sightings are counted on merge, not incremented server-side. */
        observationCountAtLeast: o.observation_count,
        firstObservedAt: o.first_observed_at,
        lastObservedAt: o.last_observed_at,
      })),
    });
  }),
);

interface QuarantineRow {
  id: string;
  connection_id: string;
  account_native_id: string | null;
  ingestion_batch_id: string | null;
  collection_run_id: string | null;
  collection_step_id: string | null;
  provider: string;
  provider_service: string | null;
  provider_operation: string | null;
  provider_resource_id: string | null;
  resource_type_key: string | null;
  partition: string | null;
  region: string | null;
  collector_observed_at: string | null;
  quarantined_at: string;
  reason_code: string;
  reason_detail: string | null;
  validation_rule: string;
  payload: unknown;
  payload_truncated: boolean;
  record_fingerprint: string | null;
  status: string;
  retryable: boolean;
  resolved_at: string | null;
  resolution: string | null;
}

/** Summary form — no payload. A list view has no business shipping every rejected record's contents. */
function mapQuarantineSummary(q: QuarantineRow) {
  return {
    id: q.id,
    connectionId: q.connection_id,
    ingestionBatchId: q.ingestion_batch_id,
    provider: q.provider,
    providerResourceId: q.provider_resource_id,
    resourceType: q.resource_type_key,
    region: q.region,
    partition: q.partition,
    quarantinedAt: q.quarantined_at,
    reasonCode: q.reason_code,
    reasonDetail: q.reason_detail,
    validationRule: q.validation_rule,
    status: q.status,
    retryable: q.retryable,
    resolvedAt: q.resolved_at,
    resolution: q.resolution,
  };
}

/** GET /quarantine — records refused admission, newest first. */
lineageRoutes.get('/quarantine', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const permitted = await permittedConnections(db, c.req.raw, orgId, auth.userId);
    const pagination = parsePagination(new URL(c.req.url));
    if (!permitted) return okJson(paginatedEnvelope([], 0, pagination));

    const url = new URL(c.req.url);
    const filters: Record<string, string> = { connection_id: inFilter(permitted) };
    const status = url.searchParams.get('status');
    const reason = url.searchParams.get('reasonCode');
    const batchId = url.searchParams.get('ingestionBatchId');
    if (status) filters.status = `eq.${status}`;
    if (reason) filters.reason_code = `eq.${reason}`;
    if (batchId) filters.ingestion_batch_id = `eq.${batchId}`;

    const [rows, total] = await db.selectWithCount<QuarantineRow[]>('quarantine_records', {
      select: '*',
      filters,
      order: 'quarantined_at.desc',
      offset: pagination.offset,
      limit: pagination.limit,
    });

    return okJson(paginatedEnvelope(rows.map(mapQuarantineSummary), total, pagination));
  }),
);

/** GET /quarantine/:id — one record, including the redacted payload that arrived. */
lineageRoutes.get('/quarantine/:id', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'read');

    const permitted = await permittedConnections(db, c.req.raw, orgId, auth.userId);
    if (!permitted) return errJson(404, 'Quarantine record not found', { code: 'not_found' });

    const [row] = await db.select<QuarantineRow[]>('quarantine_records', {
      select: '*',
      filters: { id: `eq.${c.req.param('id')}`, connection_id: inFilter(permitted) },
      limit: 1,
    });
    if (!row) return errJson(404, 'Quarantine record not found', { code: 'not_found' });

    return okJson({
      ...mapQuarantineSummary(row),
      collectionRunId: row.collection_run_id,
      collectionStepId: row.collection_step_id,
      providerService: row.provider_service,
      providerOperation: row.provider_operation,
      collectorObservedAt: row.collector_observed_at,
      recordFingerprint: row.record_fingerprint,
      /**
       * The payload that arrived, redacted and size-capped at write time.
       * This is the one place a raw provider record is retained, because
       * "what arrived?" is unanswerable without it -- and it is only ever
       * returned for a connection the caller is permitted on.
       */
      payload: row.payload,
      payloadTruncated: row.payload_truncated,
    });
  }),
);

/**
 * POST /quarantine/:id/reprocess — request revalidation of a refused record.
 *
 * Deliberately does NOT revalidate inline, and deliberately does not admit
 * anything to canonical state by itself. It moves the record to
 * REPROCESS_REQUESTED; the next scan that observes the resource runs the same
 * admission pipeline it would have run anyway.
 *
 * That ordering is the point (§15): reprocessing must not bypass validation,
 * and a record that was refused for an unknown resource type becomes valid
 * because the CATALOG changed, not because someone pressed a button.
 *
 * The original reason, rule, fingerprint, batch and detection time are never
 * overwritten -- §14 requires them to remain auditable, so a reprocess
 * request adds state rather than rewriting history.
 */
lineageRoutes.post('/quarantine/:id/reprocess', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'cloud', 'write');

    const permitted = await permittedConnections(db, c.req.raw, orgId, auth.userId);
    if (!permitted) return errJson(404, 'Quarantine record not found', { code: 'not_found' });

    const id = c.req.param('id');
    const [row] = await db.select<QuarantineRow[]>('quarantine_records', {
      select: '*',
      filters: { id: `eq.${id}`, connection_id: inFilter(permitted) },
      limit: 1,
    });
    if (!row) return errJson(404, 'Quarantine record not found', { code: 'not_found' });

    // Confirms the caller is permitted on the connection itself, not merely
    // that the row is in their permitted set.
    await requirePermittedConnection(db, orgId, auth.userId, row.connection_id, getActiveScope(c.req.raw, orgId));

    if (!row.retryable) {
      return errJson(
        409,
        'This record cannot be reprocessed. It was refused for a reason that revalidating the same payload cannot resolve.',
      );
    }
    if (row.status !== 'QUARANTINED') {
      return errJson(409, `This record is already ${row.status}.`);
    }

    await db.update(
      'quarantine_records',
      { id: `eq.${id}` },
      { status: 'REPROCESS_REQUESTED', updated_at: new Date().toISOString() },
      'return=minimal',
    );

    await writeAuditLog(db, {
      orgId,
      actorId: auth.userId,
      action: 'quarantine.reprocess_requested',
      targetType: 'quarantine_record',
      targetId: id,
      metadata: { reasonCode: row.reason_code, validationRule: row.validation_rule },
    });

    return okJson({
      id,
      status: 'REPROCESS_REQUESTED',
      explanation:
        'This record will be revalidated by the next collection run that observes the resource. Nothing is admitted to inventory until it passes the same validation it failed.',
    });
  }),
);
