import { Hono, createDb, guarded, okJson, errJson } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { loadConnection } from './discovery';
import { resolveCredentials } from './permissions';
import { checkCostExplorer } from '../lib/permissionChecks';

export const costReadinessRoutes = new Hono<{ Bindings: Env }>();

/**
 * Machine-verifiable readiness states for AWS-13.
 *
 * The point of this endpoint is that "Cost Explorer, account-owner action"
 * is not an actionable statement. These four states each imply a DIFFERENT
 * remedy, and conflating them sends someone to fix the wrong thing:
 *
 *   READY                nothing to do
 *   NOT_ENABLED          switch it on in Billing preferences — an ACCOUNT
 *                        setting, not an IAM policy
 *   PERMISSION_DENIED    the IAM role lacks ce:* — a POLICY fix
 *   AWAITING_DATA        enabled, but AWS has not populated it yet (~24h)
 *
 * Reporting NOT_ENABLED as PERMISSION_DENIED sends an engineer to widen a
 * policy that is already correct. That is the specific confusion this
 * endpoint exists to remove.
 */
export type CostReadinessState = 'READY' | 'NOT_ENABLED' | 'PERMISSION_DENIED' | 'AWAITING_DATA' | 'UNKNOWN';

export interface CostReadiness {
  connectionId: string;
  connectionName: string;
  awsAccountId: string | null;
  state: CostReadinessState;
  /** What a human must actually do. Empty when READY. */
  requiredAction: string | null;
  /** Which AWS principal must perform it. */
  actionOwner: string | null;
  detail: string;
}

/** Maps the permission probe's verdict onto an actionable readiness state. */
export function readinessFromProbe(status: string, detail: string): Pick<CostReadiness, 'state' | 'requiredAction' | 'actionOwner'> {
  if (status === 'granted') {
    return { state: 'READY', requiredAction: null, actionOwner: null };
  }
  if (/not enabled for cost explorer/i.test(detail) || /Cost Explorer is not enabled/i.test(detail)) {
    return {
      state: 'NOT_ENABLED',
      requiredAction:
        'Enable Cost Explorer in the AWS Billing console: Billing and Cost Management > Cost Explorer > Launch Cost Explorer. '
        + 'This is an ACCOUNT setting, not an IAM permission — widening the role will not fix it. '
        + 'AWS populates data within roughly 24 hours of enabling.',
      actionOwner:
        'The account root user, or an IAM principal with aws-portal:ModifyBilling / billing full access, '
        + 'in the account being monitored. In an AWS Organization this may be the management account.',
    };
  }
  if (/has not accumulated data/i.test(detail) || /DataUnavailable/i.test(detail)) {
    return {
      state: 'AWAITING_DATA',
      requiredAction: 'No action. Cost Explorer is enabled but AWS has not populated data yet; this resolves on its own, typically within 24 hours of first enabling.',
      actionOwner: null,
    };
  }
  if (status === 'denied') {
    return {
      state: 'PERMISSION_DENIED',
      requiredAction:
        'Grant the collection role ce:GetCostAndUsage, ce:GetDimensionValues and ce:GetCostForecast. '
        + 'This is an IAM POLICY fix, distinct from the account-level enablement above.',
      actionOwner: 'Whoever administers the IAM role this connection assumes.',
    };
  }
  return { state: 'UNKNOWN', requiredAction: null, actionOwner: null };
}

/**
 * GET /internal/cost-readiness — AWS-13 readiness check.
 *
 * Probes Cost Explorer live for every connected AWS account and returns a
 * structured, machine-verifiable verdict. This is the "precise readiness
 * check" the phase requires: a caller can assert on `state` rather than
 * parsing a human sentence, and CI can fail on a regression from READY.
 */
costReadinessRoutes.post('/internal/cost-readiness', (c) =>
  guarded(async () => {
    const secret = c.req.header('x-internal-scan-secret');
    if (!c.env.INTERNAL_SCAN_SECRET) return errJson(503, 'INTERNAL_SCAN_SECRET is not configured — cost readiness check is not active in this environment.');
    if (!c.env.SUPABASE_SERVICE_ROLE_KEY) return errJson(503, 'SUPABASE_SERVICE_ROLE_KEY is not configured.');
    if (secret !== c.env.INTERNAL_SCAN_SECRET) return errJson(403, 'Invalid or missing X-Internal-Scan-Secret.');

    const db = createDb(c.env, c.env.SUPABASE_SERVICE_ROLE_KEY);
    const rows = await db.select<{ id: string; org_id: string; connection_name: string; aws_account_id: string | null }[]>('cloud_connections', {
      select: 'id,org_id,connection_name,aws_account_id',
      filters: { provider: 'eq.aws', status: 'eq.connected' },
      limit: 50,
    });

    const results: CostReadiness[] = [];
    for (const row of rows) {
      const connection = await loadConnection(db, row.org_id, null, row.id);
      if (!connection) continue;

      const resolved = await resolveCredentials(c.env, connection as never);
      if ('error' in resolved) {
        results.push({
          connectionId: row.id, connectionName: row.connection_name, awsAccountId: row.aws_account_id,
          state: 'UNKNOWN', requiredAction: null, actionOwner: null,
          detail: 'Credentials could not be resolved; Cost Explorer readiness cannot be determined.',
        });
        continue;
      }

      const probe = await checkCostExplorer(resolved.creds);
      results.push({
        connectionId: row.id,
        connectionName: row.connection_name,
        awsAccountId: row.aws_account_id,
        detail: probe.detail ?? probe.status,
        ...readinessFromProbe(probe.status, probe.detail ?? ''),
      });
    }

    return okJson({
      checked: results.length,
      ready: results.filter((r) => r.state === 'READY').length,
      blocked: results.filter((r) => r.state !== 'READY').length,
      results,
    });
  }),
);
