import { callJsonApi } from '../awsApi';
import { walkPages } from './restJson';
import { reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const FMS_RESOURCE_TYPES = ['firewall_manager_policy'] as const;

interface PolicySummary {
  PolicyArn?: string; PolicyId?: string; PolicyName?: string; ResourceType?: string; SecurityServiceType?: string;
  RemediationEnabled?: boolean; DeleteUnusedFMManagedResources?: boolean; PolicyStatus?: string;
}

/**
 * Error codes meaning "this account is not the Firewall Manager admin" --
 * the expected answer for almost every account, not a failure.
 */
const NOT_ADMIN = /AccessDenied|InvalidOperation|ResourceNotFound|not.*admin/i;

/**
 * AWS Firewall Manager policies (JSON-RPC, AWSFMS_20180101). Only the FMS
 * administrator account can list them.
 *
 * What changed, and why:
 *  - Paginates (NextToken); previously one page of 100.
 *  - `PolicyId!` (a non-null assertion on provider data) is gone; a policy
 *    with neither ARN nor id is recorded with an empty id, which admission
 *    quarantines with a typed reason.
 *  - "Not the admin account" stays a quiet, settled answer; any OTHER
 *    failure is now reported, so a transient error in the real admin account
 *    no longer deletes every policy row.
 *  - Evidence: auto-remediation, cleanup of unused managed resources, and
 *    whether the policy is actually in the admin's scope.
 */
export async function scanFms(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `fms.${ctx.region}.amazonaws.com`;
  const walk = await walkPages<PolicySummary>(
    async (token) => {
      const r = await callJsonApi(ctx.creds, {
        service: 'fms', region: ctx.region, host, target: 'AWSFMS_20180101.ListPolicies',
        body: { MaxResults: 100, ...(token ? { NextToken: token } : {}) },
      });
      // Code AND message: either may carry the "not the admin" signal.
      return r.ok
        ? { ok: true, status: r.status, body: (r.body ?? {}) as Record<string, unknown> }
        : { ok: false, status: r.status, body: null, error: `${r.errorCode ?? ''} ${r.errorMessage ?? ''}`.trim() || `status ${r.status}` };
    },
    (b) => b.PolicyList,
    (b) => b.NextToken,
  );

  if (!walk.complete) {
    if (walk.firstPageFailed && NOT_ADMIN.test(walk.error ?? '')) {
      return [];
    }
    console.error(`FMS ListPolicies ${walk.firstPageFailed ? 'failed' : 'was incomplete'} in ${ctx.region}: ${walk.error ?? ''}`);
    reportListingFailure(ctx, walk.firstPageFailed
      ? { service: 'fms', action: 'ListPolicies', region: ctx.region, httpStatus: walk.status }
      : { service: 'fms', action: 'ListPolicies', region: ctx.region, truncated: true });
  }

  return walk.items.filter(Boolean).map((p) => ({
    resourceTypeKey: 'firewall_manager_policy', resourceId: p.PolicyArn ?? p.PolicyId ?? '', region: ctx.region, resourceName: p.PolicyName,
    state: p.PolicyStatus,
    metadata: {
      resourceType: p.ResourceType, securityServiceType: p.SecurityServiceType, remediationEnabled: p.RemediationEnabled,
      deleteUnusedManagedResources: p.DeleteUnusedFMManagedResources ?? null,
      policyStatus: p.PolicyStatus ?? null,
    },
  }));
}
