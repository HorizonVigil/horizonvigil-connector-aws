import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const FMS_RESOURCE_TYPES = ['firewall_manager_policy'] as const;

interface PolicySummary { PolicyArn?: string; PolicyId?: string; PolicyName?: string; ResourceType?: string; SecurityServiceType?: string; RemediationEnabled?: boolean }
interface ListPoliciesResponse { PolicyList?: PolicySummary[] }

/**
 * Firewall Manager — ListPolicies only succeeds for the account designated
 * as the FMS admin account; every other account gets an access-denied-style
 * error, which is the expected common case (not a real failure) since FMS
 * is an org-wide, single-admin-account service.
 */
export async function scanFms(ctx: ScannerContext): Promise<ScannedResource[]> {
  const result = await callJsonApi(ctx.creds, {
    service: 'fms', region: ctx.region, host: `fms.${ctx.region}.amazonaws.com`,
    target: 'AWSFMS_20180101.ListPolicies', body: { MaxResults: 100 },
  });
  if (!result.ok) {
    console.error(`FMS ListPolicies failed in ${ctx.region} (continuing without it — likely not the FMS admin account): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const policies = (result.body as ListPoliciesResponse).PolicyList ?? [];
  return policies.map((p) => ({
    resourceTypeKey: 'firewall_manager_policy', resourceId: p.PolicyArn ?? p.PolicyId!, region: ctx.region, resourceName: p.PolicyName,
    metadata: { resourceType: p.ResourceType, securityServiceType: p.SecurityServiceType, remediationEnabled: p.RemediationEnabled },
  }));
}
