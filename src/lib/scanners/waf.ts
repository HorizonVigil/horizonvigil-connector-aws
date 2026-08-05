import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AWSWAF_20190729';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const WAF_RESOURCE_TYPES = ['wafv2_web_acl'] as const;

interface WebAclSummary {
  Name: string; Id: string; ARN?: string; Description?: string; LockToken?: string;
}

/**
 * WAFv2 ListWebACLs — one JSON-RPC call, Scope=REGIONAL only. CloudFront-
 * scoped Web ACLs (Scope=CLOUDFRONT) are queryable only from us-east-1
 * regardless of caller region and would double-count across every scan
 * region if included here — skipped in this pass rather than adding a
 * separate global scanner for just that scope.
 */
export async function scanWaf(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `wafv2.${ctx.region}.amazonaws.com`;
  const result = await callJsonApi(ctx.creds, { service: 'wafv2', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListWebACLs`, body: { Scope: 'REGIONAL' } });
  if (!result.ok) {
    console.error(`WAF ListWebACLs failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const acls = (result.body as { WebACLs?: WebAclSummary[] }).WebACLs ?? [];
  return acls.map((acl) => ({
    resourceTypeKey: 'wafv2_web_acl', resourceId: acl.ARN ?? acl.Id, region: ctx.region, resourceName: acl.Name,
    metadata: { description: acl.Description },
  }));
}
