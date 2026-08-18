import { Hono, getAuthContext, requireOrgId, createDb, requireMenuPermission, writeAuditLog, guarded, okJson, errJson, enforceRateLimit, type Db } from '@cloudops360/shared-lib';
import type { Env } from '../env';
import { resolveCredentials, type ResolvableConnection } from './permissions';
import {
  describeCurrentState, runAction, interpretDryRun, createSafetySnapshot, startInstance, stopInstance, modifyInstanceType,
  type RemediationActionType,
} from '../lib/remediationActions';
import type { AwsCreds } from '../lib/awsApi';
import { notify } from '../lib/notify';
import { checkCachedEligibility, type CachedResourceRow } from '../lib/remediationEligibility';

export const remediationRoutes = new Hono<{ Bindings: Env }>();

/**
 * Safe Automated Remediation: request -> approve -> dry-run -> execute,
 * with an optional rollback for the one reversible action type. Every step
 * uses the target connection's own stored AWS credentials (never a
 * platform-level credential) via aws4fetch, the same as scanning/cost
 * sync — so whether an action actually succeeds is entirely governed by
 * that connection's own IAM permissions. Lives here rather than in
 * automation-api because only this Worker holds ENCRYPTION_KEY to decrypt
 * those credentials; automation_executions still gets a row per
 * execution so the existing Automation > Remediation/History tabs work.
 */
const ACTION_RESOURCE_TYPE: Record<RemediationActionType, string> = {
  stop_instance: 'ec2_instance', start_instance: 'ec2_instance', release_eip: 'elastic_ip', delete_volume: 'ebs_volume',
  delete_snapshot: 'ebs_snapshot', deregister_ami: 'ec2_ami', resize_instance: 'ec2_instance',
};

const SELECT = 'id,org_id,connection_id,resource_id,recommendation_id,action_type,target_resource_id,region,status,requested_by,approved_by,dry_run_result,execution_result,rollback_of,target_config,provider,created_at,approved_at,executed_at';

interface RemediationRequestRow {
  id: string; org_id: string; connection_id: string; resource_id: string | null; recommendation_id: string | null;
  action_type: RemediationActionType; target_resource_id: string; region: string | null; status: string;
  requested_by: string | null; approved_by: string | null; dry_run_result: unknown; execution_result: unknown;
  rollback_of: string | null; target_config: { targetInstanceType?: string } | null;
  created_at: string; approved_at: string | null; executed_at: string | null;
}

async function loadRequest(db: Db, orgId: string, id: string): Promise<RemediationRequestRow | null> {
  const rows = await db.select<RemediationRequestRow[]>('remediation_requests', { select: SELECT, filters: { id: `eq.${id}`, org_id: `eq.${orgId}` } });
  return rows[0] ?? null;
}

async function loadConnectionForCreds(db: Db, orgId: string, connectionId: string): Promise<ResolvableConnection | null> {
  // Every call site already derives connectionId from a remediation_requests
  // row that was itself loaded with an org_id filter (loadRequest), and
  // Postgres RLS on cloud_connections independently enforces org membership
  // regardless — but filtering by org_id here too means this function is
  // safe to call with an untrusted connectionId in the future without
  // depending on a caller having already checked it.
  const rows = await db.select<ResolvableConnection[]>('cloud_connections', {
    select: 'id,connection_method,credentials_encrypted,role_arn,external_id,default_region',
    filters: { id: `eq.${connectionId}`, org_id: `eq.${orgId}`, provider: 'eq.aws' },
  });
  return rows[0] ?? null;
}

/** Best-effort — a completed/failed execution should still report to the caller even if this bookkeeping fails. */
async function logExecution(db: Db, orgId: string, req: RemediationRequestRow, status: 'succeeded' | 'failed', userId: string, output: Record<string, unknown>): Promise<void> {
  await db.insert('automation_executions', {
    org_id: orgId, automation_type: 'remediation', automation_id: req.id, status,
    started_at: req.approved_at ?? req.created_at, finished_at: new Date().toISOString(), triggered_by: userId,
    output, error_message: status === 'failed' ? (typeof output.reason === 'string' ? output.reason : JSON.stringify(output)) : null,
  }, 'return=minimal').catch(() => {});
}

/** Reflects a successful action on the cached inventory immediately, rather than waiting for the next discovery scan. Best-effort. */
async function updateCachedResourceState(db: Db, req: RemediationRequestRow): Promise<void> {
  if (!req.resource_id) return;
  if (req.action_type === 'stop_instance') await db.update('cloud_resources', { id: `eq.${req.resource_id}` }, { state: 'stopped', status: 'stopped' }, 'return=minimal');
  else if (req.action_type === 'start_instance') await db.update('cloud_resources', { id: `eq.${req.resource_id}` }, { state: 'running', status: 'active' }, 'return=minimal');
  else if (req.action_type === 'resize_instance') {
    // Full cycle ends with the instance running again on the new type —
    // metadata is a jsonb column PostgREST replaces wholesale on update, so
    // this reads the current row first rather than blindly overwriting
    // whatever else discovery had already stored there.
    if (req.target_config?.targetInstanceType) {
      const [current] = await db.select<{ metadata: Record<string, unknown> | null }[]>('cloud_resources', { select: 'metadata', filters: { id: `eq.${req.resource_id}` } });
      await db.update('cloud_resources', { id: `eq.${req.resource_id}` }, { state: 'running', status: 'active', metadata: { ...(current?.metadata ?? {}), instanceType: req.target_config.targetInstanceType } }, 'return=minimal');
    }
  } else await db.update('cloud_resources', { id: `eq.${req.resource_id}` }, { deleted_at: new Date().toISOString(), status: 'deleted' }, 'return=minimal');
}

interface FinishResizeResult {
  [key: string]: unknown;
  ok: boolean;
  errorCode?: string;
  errorMessage?: string;
  step?: 'modify' | 'start';
}

/** The second half of a resize: ModifyInstanceAttribute (real, only valid once the instance is confirmed stopped) then StartInstances. Shared by /execute (when the instance was already stopped, so both halves happen in one call) and /finish-resize (when execute had to stop it first). */
async function finishResizeSequence(creds: AwsCreds, region: string, instanceId: string, targetInstanceType: string): Promise<FinishResizeResult> {
  const modifyResult = await modifyInstanceType(creds, region, instanceId, targetInstanceType, false);
  if (!modifyResult.ok) return { ok: false, errorCode: modifyResult.errorCode, errorMessage: modifyResult.errorMessage, step: 'modify' };
  const startResult = await startInstance(creds, region, instanceId, false);
  if (!startResult.ok) return { ok: false, errorCode: startResult.errorCode, errorMessage: startResult.errorMessage, step: 'start' };
  return { ok: true };
}

interface RequestBody {
  connectionId?: string;
  resourceId?: string;
  actionType?: RemediationActionType;
  recommendationId?: string;
  targetConfig?: { targetInstanceType?: string };
}

/** Real EC2 instance type shape (<family><generation>.<size>) — same loose validation as ec2Sizing.ts's parser on the cost-optimization-api side, just confirming the string is well-formed, not that AWS actually offers it (AWS's own DryRun at dry-run time is the real check for that). */
const INSTANCE_TYPE_PATTERN = /^[a-z0-9]+\.[a-z0-9]+$/;

/** POST /api/aws-accounts/remediation/request — editor+. Creates a pending_approval row after a cached-data eligibility pre-check (the authoritative check happens live, against real AWS state, at dry-run time). */
remediationRoutes.post('/remediation/request', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'automation', 'write');

    const body = (await c.req.json().catch(() => ({}))) as RequestBody;
    if (!body.connectionId || !body.resourceId || !body.actionType) return errJson(400, 'connectionId, resourceId, and actionType are required');
    if (!(body.actionType in ACTION_RESOURCE_TYPE)) return errJson(400, `Unknown actionType "${body.actionType}"`);
    if (body.actionType === 'resize_instance') {
      if (!body.targetConfig?.targetInstanceType || !INSTANCE_TYPE_PATTERN.test(body.targetConfig.targetInstanceType)) {
        return errJson(400, 'targetConfig.targetInstanceType is required for resize_instance and must look like a real instance type (e.g. "m5.large")');
      }
    }

    const [connectionRows, resourceRows] = await Promise.all([
      db.select<{ id: string }[]>('cloud_connections', { select: 'id', filters: { id: `eq.${body.connectionId}`, org_id: `eq.${orgId}`, provider: 'eq.aws' } }),
      db.select<CachedResourceRow[]>('cloud_resources', {
        select: 'id,connection_id,resource_type_key,resource_id,region,state,relationships',
        filters: { id: `eq.${body.resourceId}`, connection_id: `eq.${body.connectionId}` },
      }),
    ]);
    if (!connectionRows[0]) return errJson(404, 'Account not found');
    const resource = resourceRows[0];
    if (!resource) return errJson(404, 'Resource not found on this account');
    if (resource.resource_type_key !== ACTION_RESOURCE_TYPE[body.actionType]) {
      return errJson(400, `${body.actionType} requires a ${ACTION_RESOURCE_TYPE[body.actionType]} resource, not ${resource.resource_type_key}`);
    }
    const eligibility = checkCachedEligibility(body.actionType, resource);
    if (!eligibility.eligible) return errJson(400, eligibility.reason ?? 'Resource is not eligible for this action.');

    const [created] = await db.insert<RemediationRequestRow[]>('remediation_requests', [{
      org_id: orgId, connection_id: body.connectionId, resource_id: resource.id, recommendation_id: body.recommendationId ?? null,
      action_type: body.actionType, target_resource_id: resource.resource_id, region: resource.region, requested_by: auth.userId,
      target_config: body.actionType === 'resize_instance' ? body.targetConfig : null,
    }]);

    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'remediation.requested', targetType: 'remediation_request', targetId: created.id, metadata: { actionType: body.actionType, targetResourceId: resource.resource_id } });
    return okJson(created);
  }),
);

/** POST /api/aws-accounts/remediation/:id/approve — admin+ (higher bar than requesting), pending_approval -> approved. */
remediationRoutes.post('/remediation/:id/approve', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'automation', 'admin');
    await enforceRateLimit(db, `remediation:approve:${orgId}`, 20, 60);

    const existing = await loadRequest(db, orgId, c.req.param('id'));
    if (!existing) return errJson(404, 'Remediation request not found');
    if (existing.status !== 'pending_approval') return errJson(409, `Cannot approve a request with status '${existing.status}'`);

    // Conditional on status still being pending_approval — closes the race
    // where two concurrent approve/reject calls both pass the check above
    // before either writes; only the request that actually flips the row
    // proceeds, the loser gets a 409 instead of silently double-processing.
    const [updated] = await db.update<RemediationRequestRow[]>(
      'remediation_requests',
      { id: `eq.${existing.id}`, status: 'eq.pending_approval' },
      { status: 'approved', approved_by: auth.userId, approved_at: new Date().toISOString() },
    );
    if (!updated) return errJson(409, 'Another request already changed this remediation request — reload and try again.');
    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'remediation.approved', targetType: 'remediation_request', targetId: existing.id });
    return okJson(updated);
  }),
);

/** POST /api/aws-accounts/remediation/:id/reject — admin+, pending_approval -> rejected. */
remediationRoutes.post('/remediation/:id/reject', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'automation', 'admin');

    const existing = await loadRequest(db, orgId, c.req.param('id'));
    if (!existing) return errJson(404, 'Remediation request not found');
    if (existing.status !== 'pending_approval') return errJson(409, `Cannot reject a request with status '${existing.status}'`);

    // See /approve — conditional on status to close the same race.
    const [updated] = await db.update<RemediationRequestRow[]>(
      'remediation_requests',
      { id: `eq.${existing.id}`, status: 'eq.pending_approval' },
      { status: 'rejected' },
    );
    if (!updated) return errJson(409, 'Another request already changed this remediation request — reload and try again.');
    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'remediation.rejected', targetType: 'remediation_request', targetId: existing.id });
    return okJson(updated);
  }),
);

/** POST /api/aws-accounts/remediation/:id/dry-run — editor+, approved -> dry_run_passed|dry_run_failed. Uses AWS's own DryRun parameter — a real permission/state check, not a simulation. */
remediationRoutes.post('/remediation/:id/dry-run', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'automation', 'write');

    const existing = await loadRequest(db, orgId, c.req.param('id'));
    if (!existing) return errJson(404, 'Remediation request not found');
    if (existing.status !== 'approved') return errJson(409, `Cannot dry-run a request with status '${existing.status}' — it must be approved first.`);
    if (!existing.region) return errJson(400, 'Resource has no recorded region');

    const connection = await loadConnectionForCreds(db, orgId, existing.connection_id);
    if (!connection) return errJson(404, 'Account not found');
    const resolved = await resolveCredentials(c.env, connection);
    if ('error' in resolved) {
      const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'dry_run_failed', dry_run_result: { reason: resolved.error } });
      return okJson(updated);
    }

    const state = await describeCurrentState(resolved.creds, existing.region, existing.action_type, existing.target_resource_id);
    if (!state.eligible) {
      const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'dry_run_failed', dry_run_result: { eligible: false, reason: state.reason } });
      await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'remediation.dry_run_failed', targetType: 'remediation_request', targetId: existing.id, metadata: { reason: state.reason } });
      return okJson(updated);
    }

    const dryRunResult = await runAction(resolved.creds, existing.region, existing.action_type, existing.target_resource_id, true, existing.target_config?.targetInstanceType);
    const outcome = interpretDryRun(dryRunResult);
    const nextStatus = outcome.wouldSucceed ? 'dry_run_passed' : 'dry_run_failed';
    const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: nextStatus, dry_run_result: { eligible: true, ...outcome } });

    await writeAuditLog(db, { orgId, actorId: auth.userId, action: `remediation.${nextStatus}`, targetType: 'remediation_request', targetId: existing.id, metadata: outcome as Record<string, unknown> });
    return okJson(updated);
  }),
);

/** POST /api/aws-accounts/remediation/:id/execute — admin+, dry_run_passed -> completed|failed. Re-validates live AWS state once more before mutating (the approval-to-execute gap can be arbitrarily long). delete_volume takes a mandatory safety snapshot first. */
remediationRoutes.post('/remediation/:id/execute', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'automation', 'admin');
    // The one check on this file that matters most — this is the endpoint
    // that actually mutates real customer infrastructure (stop/start/
    // delete/resize). 10/60s per org is generous for legitimate bulk
    // remediation while still capping a runaway script or compromised
    // session from firing an unbounded number of real AWS mutations.
    await enforceRateLimit(db, `remediation:execute:${orgId}`, 10, 60);

    const existing = await loadRequest(db, orgId, c.req.param('id'));
    if (!existing) return errJson(404, 'Remediation request not found');
    if (existing.status !== 'dry_run_passed') return errJson(409, `Cannot execute a request with status '${existing.status}' — it must pass a dry run first.`);
    if (!existing.region) return errJson(400, 'Resource has no recorded region');

    // Atomic claim, conditional on status still being dry_run_passed — this
    // must happen before any AWS calls, not after. Two concurrent execute
    // calls (double-click, two admins) would otherwise both read
    // dry_run_passed, both pass every check below, and both fire the real
    // AWS mutation; only the request that actually flips this row to
    // 'executing' is allowed to proceed, the other gets a 409 immediately.
    const [claimed] = await db.update<RemediationRequestRow[]>(
      'remediation_requests',
      { id: `eq.${existing.id}`, status: 'eq.dry_run_passed' },
      { status: 'executing' },
    );
    if (!claimed) return errJson(409, 'Another request already started executing this remediation — reload and try again.');

    const connection = await loadConnectionForCreds(db, orgId, existing.connection_id);
    if (!connection) return errJson(404, 'Account not found');
    const resolved = await resolveCredentials(c.env, connection);
    if ('error' in resolved) {
      const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'failed', execution_result: { reason: resolved.error } });
      return okJson(updated);
    }

    const state = await describeCurrentState(resolved.creds, existing.region, existing.action_type, existing.target_resource_id);
    if (!state.eligible) {
      const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'failed', execution_result: { reason: `Resource state changed since dry-run: ${state.reason}` } });
      await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'remediation.execute_blocked_stale_state', targetType: 'remediation_request', targetId: existing.id, metadata: { reason: state.reason } });
      return okJson(updated);
    }

    // resize_instance is the one action that can't be a single AWS call —
    // see modifyInstanceType's doc comment. If the instance is already
    // stopped, finish the whole thing now (modify + start, straight to
    // completed). If it's running, only the first step (stop) is safe to do
    // here; finish-resize (below) does the rest once the caller confirms
    // it's actually stopped — AWS's StopInstances is itself async, this
    // Worker invocation can't safely block waiting for it to finish.
    if (existing.action_type === 'resize_instance') {
      const targetInstanceType = existing.target_config?.targetInstanceType;
      if (!targetInstanceType) {
        const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'failed', execution_result: { reason: 'No target instance type recorded on this request' } });
        return okJson(updated);
      }

      if (state.state === 'running') {
        const stopResult = await stopInstance(resolved.creds, existing.region, existing.target_resource_id, false);
        if (!stopResult.ok) {
          const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'failed', execution_result: { ok: false, errorCode: stopResult.errorCode, errorMessage: stopResult.errorMessage, step: 'stop' } });
          await logExecution(db, orgId, existing, 'failed', auth.userId, { step: 'stop', errorMessage: stopResult.errorMessage });
          await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'remediation.execute_failed', targetType: 'remediation_request', targetId: existing.id, metadata: { step: 'stop' } });
          return okJson(updated);
        }
        const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'awaiting_stop', execution_result: { step: 'stopped', targetInstanceType } });
        await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'remediation.resize_awaiting_stop', targetType: 'remediation_request', targetId: existing.id });
        return okJson(updated);
      }

      // Already stopped — finish the whole sequence now.
      const finishResult = await finishResizeSequence(resolved.creds, existing.region, existing.target_resource_id, targetInstanceType);
      if (!finishResult.ok) {
        const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'failed', execution_result: finishResult });
        await logExecution(db, orgId, existing, 'failed', auth.userId, finishResult);
        await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'remediation.execute_failed', targetType: 'remediation_request', targetId: existing.id, metadata: finishResult });
        return okJson(updated);
      }
      const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'completed', execution_result: finishResult, executed_at: new Date().toISOString() });
      await updateCachedResourceState(db, existing).catch(() => {});
      await logExecution(db, orgId, existing, 'succeeded', auth.userId, finishResult);
      await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'remediation.executed', targetType: 'remediation_request', targetId: existing.id, metadata: finishResult });
      await notify(c.env, auth.accessToken, orgId, 'remediation.completed', `Resize of ${existing.target_resource_id} to ${targetInstanceType} completed successfully.`);
      return okJson(updated);
    }

    let snapshotId: string | undefined;
    if (existing.action_type === 'delete_volume') {
      const snap = await createSafetySnapshot(resolved.creds, existing.region, existing.target_resource_id, `Auto-snapshot before HorizonVigil remediation ${existing.id}`);
      if ('error' in snap) {
        const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'failed', execution_result: { reason: `Safety snapshot failed, delete aborted: ${snap.error}` } });
        await logExecution(db, orgId, existing, 'failed', auth.userId, { reason: snap.error });
        return okJson(updated);
      }
      snapshotId = snap.snapshotId;
    }

    const result = await runAction(resolved.creds, existing.region, existing.action_type, existing.target_resource_id, false);
    const executionResult: Record<string, unknown> = { ok: result.ok, errorCode: result.errorCode, errorMessage: result.errorMessage, snapshotId };

    if (!result.ok) {
      const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'failed', execution_result: executionResult });
      await logExecution(db, orgId, existing, 'failed', auth.userId, executionResult);
      await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'remediation.execute_failed', targetType: 'remediation_request', targetId: existing.id, metadata: executionResult });
      await notify(c.env, auth.accessToken, orgId, 'remediation.failed', `${existing.action_type.replace(/_/g, ' ')} on ${existing.target_resource_id} failed to execute.`, result.errorMessage);
      return okJson(updated);
    }

    const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'completed', execution_result: executionResult, executed_at: new Date().toISOString() });
    await updateCachedResourceState(db, existing).catch(() => {});
    await logExecution(db, orgId, existing, 'succeeded', auth.userId, executionResult);
    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'remediation.executed', targetType: 'remediation_request', targetId: existing.id, metadata: executionResult });
    await notify(c.env, auth.accessToken, orgId, 'remediation.completed', `${existing.action_type.replace(/_/g, ' ')} on ${existing.target_resource_id} completed successfully.`);

    return okJson(updated);
  }),
);

/**
 * POST /api/aws-accounts/remediation/:id/finish-resize — admin+,
 * awaiting_stop -> completed|failed (or back to awaiting_stop if the
 * instance genuinely isn't stopped yet). Meant to be polled by the frontend
 * every few seconds after /execute returns 'awaiting_stop' — StopInstances
 * is itself asynchronous on AWS's side (can take anywhere from seconds to a
 * couple minutes), and this Worker invocation has no safe way to block and
 * wait for that inline, so the "wait" step is a real state re-check per
 * call instead, same "small step, caller drives the loop" shape as every
 * other multi-step operation in this codebase (e.g. discovery.ts).
 */
remediationRoutes.post('/remediation/:id/finish-resize', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'automation', 'admin');

    const existing = await loadRequest(db, orgId, c.req.param('id'));
    if (!existing) return errJson(404, 'Remediation request not found');
    if (existing.action_type !== 'resize_instance') return errJson(400, 'finish-resize only applies to resize_instance requests');
    if (existing.status !== 'awaiting_stop') return errJson(409, `Cannot finish a resize with status '${existing.status}' — it must be awaiting_stop.`);
    if (!existing.region) return errJson(400, 'Resource has no recorded region');
    const targetInstanceType = existing.target_config?.targetInstanceType;
    if (!targetInstanceType) return errJson(400, 'No target instance type recorded on this request');

    // Atomic claim, same reasoning as /execute — prevents two concurrent
    // polls both passing the state check and both firing the real
    // modify+start sequence.
    const [claimed] = await db.update<RemediationRequestRow[]>(
      'remediation_requests',
      { id: `eq.${existing.id}`, status: 'eq.awaiting_stop' },
      { status: 'executing' },
    );
    if (!claimed) return errJson(409, 'Another request already progressed this resize — reload and try again.');

    const connection = await loadConnectionForCreds(db, orgId, existing.connection_id);
    if (!connection) return errJson(404, 'Account not found');
    const resolved = await resolveCredentials(c.env, connection);
    if ('error' in resolved) {
      const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'failed', execution_result: { reason: resolved.error } });
      return okJson(updated);
    }

    // 'stop_instance' here is just a way to borrow describeCurrentState's
    // instance-state lookup (it always populates `state` regardless of
    // which branch's `eligible` semantics fire) — this call only ever reads
    // `state.state`, not `state.eligible`, so which action type is passed
    // doesn't change the correctness of what's checked below.
    const state = await describeCurrentState(resolved.creds, existing.region, 'stop_instance', existing.target_resource_id);
    if (state.state !== 'stopped') {
      // Not ready yet — this is not a failure, revert to awaiting_stop so
      // the frontend's poll loop can just call this again shortly.
      const [reverted] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'awaiting_stop', execution_result: { step: 'still_stopping', observedState: state.state } });
      return okJson(reverted);
    }

    const finishResult = await finishResizeSequence(resolved.creds, existing.region, existing.target_resource_id, targetInstanceType);
    if (!finishResult.ok) {
      const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'failed', execution_result: finishResult });
      await logExecution(db, orgId, existing, 'failed', auth.userId, finishResult);
      await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'remediation.execute_failed', targetType: 'remediation_request', targetId: existing.id, metadata: finishResult });
      return okJson(updated);
    }

    const [updated] = await db.update<RemediationRequestRow[]>('remediation_requests', { id: `eq.${existing.id}` }, { status: 'completed', execution_result: finishResult, executed_at: new Date().toISOString() });
    await updateCachedResourceState(db, existing).catch(() => {});
    await logExecution(db, orgId, existing, 'succeeded', auth.userId, finishResult);
    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'remediation.executed', targetType: 'remediation_request', targetId: existing.id, metadata: finishResult });
    await notify(c.env, auth.accessToken, orgId, 'remediation.completed', `Resize of ${existing.target_resource_id} to ${targetInstanceType} completed successfully.`);
    return okJson(updated);
  }),
);

/** POST /api/aws-accounts/remediation/:id/rollback — admin+. Only stop_instance is reversible (-> start_instance); release_eip and delete_volume are not, by design. */
remediationRoutes.post('/remediation/:id/rollback', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'automation', 'admin');
    await enforceRateLimit(db, `remediation:execute:${orgId}`, 10, 60);

    const existing = await loadRequest(db, orgId, c.req.param('id'));
    if (!existing) return errJson(404, 'Remediation request not found');
    if (existing.action_type !== 'stop_instance') return errJson(400, 'Only stop_instance actions can be rolled back automatically — the others are not reversible.');
    if (existing.status !== 'completed') return errJson(409, `Cannot roll back a request with status '${existing.status}'`);
    if (!existing.region) return errJson(400, 'Resource has no recorded region');

    // Atomic claim, conditional on status still being completed — see /execute.
    const [claimed] = await db.update<RemediationRequestRow[]>(
      'remediation_requests',
      { id: `eq.${existing.id}`, status: 'eq.completed' },
      { status: 'rolled_back' },
    );
    if (!claimed) return errJson(409, 'Another request already rolled this back — reload and try again.');

    const connection = await loadConnectionForCreds(db, orgId, existing.connection_id);
    if (!connection) return errJson(404, 'Account not found');
    const resolved = await resolveCredentials(c.env, connection);
    if ('error' in resolved) {
      // Roll the status claim back — we didn't actually call AWS yet.
      await db.update('remediation_requests', { id: `eq.${existing.id}` }, { status: 'completed' }, 'return=minimal');
      return errJson(400, resolved.error);
    }

    const result = await startInstance(resolved.creds, existing.region, existing.target_resource_id, false);
    if (!result.ok) {
      await db.update('remediation_requests', { id: `eq.${existing.id}` }, { status: 'completed' }, 'return=minimal');
      return errJson(400, result.errorMessage ?? result.errorCode ?? 'Rollback (start instance) failed');
    }

    const updated = claimed;
    if (existing.resource_id) await db.update('cloud_resources', { id: `eq.${existing.resource_id}` }, { state: 'running', status: 'active' }, 'return=minimal').catch(() => {});
    await logExecution(db, orgId, existing, 'succeeded', auth.userId, { rolledBack: true });
    await writeAuditLog(db, { orgId, actorId: auth.userId, action: 'remediation.rolled_back', targetType: 'remediation_request', targetId: existing.id });

    return okJson(updated);
  }),
);

/** GET /api/aws-accounts/remediation — org-wide list, filterable by status/connectionId. */
remediationRoutes.get('/remediation', (c) =>
  guarded(async () => {
    const auth = getAuthContext(c.req.raw);
    const orgId = requireOrgId(c.req.raw);
    const db = createDb(c.env, auth.accessToken);
    await requireMenuPermission(db, auth.userId, orgId, 'automation', 'read');

    const url = new URL(c.req.url);
    const filters: Record<string, string> = { org_id: `eq.${orgId}` };
    const status = url.searchParams.get('status');
    if (status) filters.status = `eq.${status}`;
    const connectionId = url.searchParams.get('connectionId');
    if (connectionId) filters.connection_id = `eq.${connectionId}`;

    const rows = await db.select<RemediationRequestRow[]>('remediation_requests', { select: SELECT, filters, order: 'created_at.desc', limit: 200 });
    return okJson({ items: rows });
  }),
);
