import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DRS_RESOURCE_TYPES = ['elastic_disaster_recovery_source_server'] as const;

interface SourceServer { sourceServerID: string; arn?: string; recoveryInstanceId?: string; dataReplicationInfo?: { dataReplicationState?: string } }
interface DescribeSourceServersResponse { items?: SourceServer[] }

/** AWS Elastic Disaster Recovery — REST-JSON, POST /DescribeSourceServers (DRS actions are named like RPC calls but routed as REST-JSON POSTs to their own action-named paths, not the X-Amz-Target header style). UNVERIFIED against a real account. */
export async function scanDrs(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'drs', ctx.region);
  const res = await safeFetch(client, `https://drs.${ctx.region}.amazonaws.com/DescribeSourceServers`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
  });
  const text = await res.text();
  if (!res.ok) {
    console.error(`DRS DescribeSourceServers failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const servers = ((text ? JSON.parse(text) : {}) as DescribeSourceServersResponse).items ?? [];
  return servers.map((s) => ({
    resourceTypeKey: 'elastic_disaster_recovery_source_server', resourceId: s.arn ?? s.sourceServerID, region: ctx.region,
    state: s.dataReplicationInfo?.dataReplicationState, relationships: { recoveryInstanceId: s.recoveryInstanceId },
  }));
}
