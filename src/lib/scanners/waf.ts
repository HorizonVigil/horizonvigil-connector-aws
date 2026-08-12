import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AWSWAF_20190729';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const WAF_RESOURCE_TYPES = ['wafv2_web_acl', 'wafv2_ip_set', 'wafv2_rule_group'] as const;

interface WebAclSummary {
  Name: string; Id: string; ARN?: string; Description?: string; LockToken?: string;
}
interface IpSetSummary {
  Name: string; Id: string; ARN?: string; Description?: string;
}
interface RuleGroupSummary {
  Name: string; Id: string; ARN?: string; Description?: string;
}

/**
 * WAFv2 ListWebACLs/ListIPSets/ListRuleGroups — three JSON-RPC calls, all
 * Scope=REGIONAL only. CloudFront-scoped resources (Scope=CLOUDFRONT) are
 * queryable only from us-east-1 regardless of caller region and would
 * double-count across every scan region if included here — skipped in this
 * pass rather than adding a separate global scanner for just that scope
 * (same reasoning as the original Web ACL-only version of this scanner).
 * List calls only return summaries (Name/Id/ARN/Description) — the full
 * rule/IP-address contents need a per-resource Get call this pass doesn't
 * make, matching the inventory-not-full-config depth of most scanners here.
 */
export async function scanWaf(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `wafv2.${ctx.region}.amazonaws.com`;
  const call = async <T>(action: string, key: string): Promise<T[]> => {
    const result = await callJsonApi(ctx.creds, { service: 'wafv2', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.${action}`, body: { Scope: 'REGIONAL' } });
    if (!result.ok) {
      console.error(`WAF ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return [];
    }
    return ((result.body as Record<string, T[]>)[key]) ?? [];
  };

  const [acls, ipSets, ruleGroups] = await Promise.all([
    call<WebAclSummary>('ListWebACLs', 'WebACLs'),
    call<IpSetSummary>('ListIPSets', 'IPSets'),
    call<RuleGroupSummary>('ListRuleGroups', 'RuleGroups'),
  ]);

  const out: ScannedResource[] = acls.map((acl) => ({
    resourceTypeKey: 'wafv2_web_acl', resourceId: acl.ARN ?? acl.Id, region: ctx.region, resourceName: acl.Name,
    metadata: { description: acl.Description },
  }));
  for (const ip of ipSets) {
    out.push({ resourceTypeKey: 'wafv2_ip_set', resourceId: ip.ARN ?? ip.Id, region: ctx.region, resourceName: ip.Name, metadata: { description: ip.Description } });
  }
  for (const rg of ruleGroups) {
    out.push({ resourceTypeKey: 'wafv2_rule_group', resourceId: rg.ARN ?? rg.Id, region: ctx.region, resourceName: rg.Name, metadata: { description: rg.Description } });
  }
  return out;
}
