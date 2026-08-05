import { createAwsClient } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SECURITYHUB_RESOURCE_TYPES = ['securityhub_hub'] as const;

interface HubDetail {
  HubArn?: string; SubscribedAt?: string; AutoEnableControls?: boolean;
}

/**
 * Security Hub's DescribeHub (GET /hub) is a yes/no membership check, not a
 * list — REST-JSON like guardduty.ts. A region where Security Hub was
 * never enabled returns an error here (AWS's own "not subscribed"
 * response), which — same as every other scanner in this codebase — is
 * caught and logged rather than thrown, so it correctly shows up as zero
 * resources for that region rather than a scan failure.
 */
export async function scanSecurityHub(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'securityhub', ctx.region);
  const res = await client.fetch(`https://securityhub.${ctx.region}.amazonaws.com/hub`, { method: 'GET' });
  const text = await res.text();
  if (!res.ok) {
    console.error(`Security Hub DescribeHub failed in ${ctx.region} (continuing without it — likely just not enabled there): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const hub = text ? (JSON.parse(text) as HubDetail) : {};
  if (!hub.HubArn) return [];
  return [{
    resourceTypeKey: 'securityhub_hub', resourceId: hub.HubArn, region: ctx.region, resourceName: `Security Hub (${ctx.region})`,
    metadata: { subscribedAt: hub.SubscribedAt, autoEnableControls: hub.AutoEnableControls },
  }];
}
