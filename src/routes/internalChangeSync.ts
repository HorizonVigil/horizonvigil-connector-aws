import { createHash } from 'node:crypto';
import { Hono, createDb, guarded, okJson, errJson, type Db } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { callJsonApi } from '../lib/awsApi';
import { classifyChangeImpact } from '../lib/changeImpact';
import { mapCloudTrailEvent, type RawCloudTrailEvent } from './cloudtrailEvents';
import { resolveCredentials, type ResolvableConnection } from './permissions';

export const internalChangeSyncRoutes = new Hono<{ Bindings: Env }>();

const MAX_CONNECTIONS = 3;
const MAX_PAGES_PER_REGION = 5;
const PAGE_SIZE = 50;
const OVERLAP_MS = 5 * 60 * 1000;
const INITIAL_LOOKBACK_MS = 24 * 60 * 60 * 1000;

interface ChangeConnection extends ResolvableConnection {
  org_id: string;
  scan_regions: string[] | null;
}

interface SyncState { last_event_time: string | null }

function checksum(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function regionsFor(connection: ChangeConnection): string[] {
  return [...new Set(connection.scan_regions?.length ? connection.scan_regions : [connection.default_region])];
}

function startTime(state: SyncState | undefined, nowMs: number): number {
  const cursor = state?.last_event_time ? Date.parse(state.last_event_time) : Number.NaN;
  return Number.isFinite(cursor) ? Math.max(0, cursor - OVERLAP_MS) : nowMs - INITIAL_LOOKBACK_MS;
}

async function updateState(db: Db, connection: ChangeConnection, patch: Record<string, unknown>) {
  await db.insert(
    'aws_change_sync_state?on_conflict=connection_id',
    { connection_id: connection.id, org_id: connection.org_id, updated_at: new Date().toISOString(), ...patch },
    'resolution=merge-duplicates,return=minimal',
  );
}

export async function syncConnectionChanges(db: Db, env: Env, connection: ChangeConnection, now = new Date()) {
  const states = await db.select<SyncState[]>('aws_change_sync_state', {
    select: 'last_event_time', filters: { connection_id: `eq.${connection.id}` }, limit: 1,
  });
  const fromMs = startTime(states[0], now.getTime());
  await updateState(db, connection, { status: 'running', last_attempt_at: now.toISOString(), error_code: null, error_message: null });

  const resolved = await resolveCredentials(env, connection);
  if ('error' in resolved) {
    await updateState(db, connection, { status: 'failed', error_code: 'CREDENTIALS_UNAVAILABLE', error_message: resolved.error });
    return { connectionId: connection.id, status: 'failed' as const, eventsSeen: 0, eventsWritten: 0, error: resolved.error };
  }

  let eventsSeen = 0;
  let eventsWritten = 0;
  let newestEventTime: string | null = states[0]?.last_event_time ?? null;
  let partial = false;

  for (const region of regionsFor(connection)) {
    let nextToken: string | undefined;
    for (let page = 0; page < MAX_PAGES_PER_REGION; page += 1) {
      const body: Record<string, unknown> = {
        MaxResults: PAGE_SIZE,
        StartTime: Math.floor(fromMs / 1000),
        EndTime: Math.floor(now.getTime() / 1000),
        LookupAttributes: [{ AttributeKey: 'ReadOnly', AttributeValue: 'false' }],
      };
      if (nextToken) body.NextToken = nextToken;
      const result = await callJsonApi(resolved.creds, {
        service: 'cloudtrail', region, host: `cloudtrail.${region}.amazonaws.com`,
        target: 'CloudTrail_20131101.LookupEvents', body,
      }, { pagination: 'follow' });

      if (!result.ok) {
        const denied = result.status === 403 || result.errorCode === 'AccessDeniedException';
        await updateState(db, connection, {
          status: denied ? 'permission_denied' : 'failed',
          error_code: result.errorCode ?? 'CLOUDTRAIL_LOOKUP_FAILED',
          error_message: result.errorMessage ?? `CloudTrail lookup failed in ${region}`,
          events_seen: eventsSeen, events_written: eventsWritten,
        });
        return { connectionId: connection.id, status: denied ? 'permission_denied' as const : 'failed' as const, eventsSeen, eventsWritten, error: result.errorMessage ?? result.errorCode };
      }

      const response = result.body as { Events?: RawCloudTrailEvent[]; NextToken?: string };
      const mapped = (response.Events ?? []).map(mapCloudTrailEvent);
      eventsSeen += mapped.length;
      if (mapped.length) {
        const rows = mapped.map(event => ({
          org_id: connection.org_id,
          connection_id: connection.id,
          event_id: event.eventId,
          event_name: event.eventName,
          event_source: event.eventSource,
          event_time: event.eventTime,
          aws_region: event.awsRegion ?? region,
          read_only: event.readOnly,
          actor_principal: event.username,
          actor_identity_type: event.userIdentityType,
          actor_arn: event.userIdentityArn,
          actor_class: event.provenance.actorClass,
          actor_kind: event.provenance.actorKind,
          actor_label: event.provenance.actorLabel,
          attribution_basis: event.provenance.basis,
          attribution_ambiguity: event.provenance.ambiguityReason,
          invoked_by: event.invokedBy,
          source_ip_address: event.sourceIpAddress,
          user_agent: event.userAgent,
          resource_names: event.resources.map(item => item.resourceName).filter((value): value is string => Boolean(value)),
          resources: event.resources,
          request_parameters: event.requestParameters,
          response_elements: event.responseElements,
          error_code: event.errorCode,
          error_message: event.errorMessage,
          impact: classifyChangeImpact(event.eventName, event.errorCode),
          raw_evidence_checksum: checksum(event),
          collected_at: now.toISOString(),
        }));
        const inserted = await db.insert<Array<{ id: string }>>(
          'aws_change_events?on_conflict=connection_id,event_id', rows,
          'resolution=ignore-duplicates,return=representation',
        );
        eventsWritten += inserted.length;
        for (const event of mapped) {
          if (!newestEventTime || Date.parse(event.eventTime) > Date.parse(newestEventTime)) newestEventTime = event.eventTime;
        }
      }

      nextToken = response.NextToken;
      if (!nextToken) break;
      if (page === MAX_PAGES_PER_REGION - 1) partial = true;
    }
  }

  await updateState(db, connection, {
    status: partial ? 'partial' : 'succeeded', last_success_at: now.toISOString(),
    last_event_time: newestEventTime, events_seen: eventsSeen, events_written: eventsWritten,
    error_code: partial ? 'PAGE_BUDGET_REACHED' : null,
    error_message: partial ? 'More CloudTrail changes remain and will be collected on the next scheduled run.' : null,
  });
  return { connectionId: connection.id, status: partial ? 'partial' as const : 'succeeded' as const, eventsSeen, eventsWritten, regions: regionsFor(connection) };
}

/** Scheduled, bounded ingestion of normalized AWS change evidence. */
internalChangeSyncRoutes.post('/internal/sync-change-events', c => guarded(async () => {
  if (!c.env.INTERNAL_SCAN_SECRET) return errJson(503, 'INTERNAL_SCAN_SECRET is not configured.');
  if (c.req.header('x-internal-scan-secret') !== c.env.INTERNAL_SCAN_SECRET) return errJson(403, 'Invalid or missing X-Internal-Scan-Secret.');
  if (!c.env.SUPABASE_SERVICE_ROLE_KEY) return errJson(503, 'SUPABASE_SERVICE_ROLE_KEY is not configured.');

  const db = createDb(c.env, c.env.SUPABASE_SERVICE_ROLE_KEY);
  const connections = await db.select<ChangeConnection[]>('cloud_connections', {
    select: 'id,org_id,connection_method,credentials_encrypted,role_arn,external_id,default_region,scan_regions',
    filters: { provider: 'eq.aws', status: 'neq.disconnected' }, order: 'last_sync_at.asc.nullsfirst', limit: MAX_CONNECTIONS,
  });
  const results = [];
  for (const connection of connections) results.push(await syncConnectionChanges(db, c.env, connection));
  return okJson({ connectionsProcessed: results.length, results });
}));
