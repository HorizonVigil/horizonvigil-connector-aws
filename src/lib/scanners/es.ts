import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ES_RESOURCE_TYPES = ['opensearch_domain'] as const;

interface DomainNameInfo { DomainName: string; EngineType?: string }
interface ListDomainNamesResponse { DomainNames?: DomainNameInfo[] }
interface VpcOptions { VPCId?: string }
interface DomainConfig { VPCOptions?: { Options?: VpcOptions }; EngineVersion?: { Options?: string } }
interface DomainStatus {
  DomainName: string; DomainId?: string; ARN?: string; Created?: boolean; Deleted?: boolean;
  Endpoint?: string; ClusterConfig?: { InstanceType?: string; InstanceCount?: number };
  EngineVersion?: string;
}
interface DescribeDomainResponse { DomainStatus?: DomainStatus }

/**
 * Amazon OpenSearch Service (formerly Elasticsearch Service) — REST API,
 * confirmed via AWS docs: GET /2021-01-01/domain lists every domain name in
 * the region, one DescribeDomain call per name fills in the detail (no
 * batch describe for the fields this needs). Same REST-JSON pattern
 * inspectorFindings.ts/s3control.ts already use in this connector.
 *
 * UNVERIFIED against a real account's actual OpenSearch response shape
 * until this runs against a live connection and gets checked -- same
 * disclosed-uncertainty convention as every other new scanner this pass.
 */
export async function scanOpenSearch(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'es', ctx.region);
  const base = `https://es.${ctx.region}.amazonaws.com`;
  const out: ScannedResource[] = [];

  const listRes = await safeFetch(client, `${base}/2021-01-01/domain`, { method: 'GET' });
  const listText = await listRes.text();
  if (!listRes.ok) {
    console.error(`OpenSearch ListDomainNames failed in ${ctx.region} (continuing without it): HTTP ${listRes.status} ${listText.slice(0, 200)}`);
    return out;
  }
  const domains = (listText ? (JSON.parse(listText) as ListDomainNamesResponse) : {}).DomainNames ?? [];

  for (const d of domains) {
    const descRes = await safeFetch(client, `${base}/2021-01-01/es/domain/${encodeURIComponent(d.DomainName)}`, { method: 'GET' });
    const descText = await descRes.text();
    if (!descRes.ok) {
      console.error(`OpenSearch DescribeDomain(${d.DomainName}) failed in ${ctx.region} (skipping detail, keeping the bare name): HTTP ${descRes.status} ${descText.slice(0, 200)}`);
      out.push({ resourceTypeKey: 'opensearch_domain', resourceId: d.DomainName, region: ctx.region, resourceName: d.DomainName, metadata: { engineType: d.EngineType } });
      continue;
    }
    const status = (descText ? (JSON.parse(descText) as DescribeDomainResponse) : {}).DomainStatus;
    out.push({
      resourceTypeKey: 'opensearch_domain', resourceId: status?.ARN ?? d.DomainName, region: ctx.region, resourceName: d.DomainName,
      metadata: {
        engineType: d.EngineType, engineVersion: status?.EngineVersion, endpoint: status?.Endpoint,
        instanceType: status?.ClusterConfig?.InstanceType, instanceCount: status?.ClusterConfig?.InstanceCount,
      },
    });
  }

  return out;
}
