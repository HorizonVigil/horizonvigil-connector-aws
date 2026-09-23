import { createAwsClient } from '../awsApi';
import { accountIdFromArn, summarizePolicy } from './policyEvidence';
import { fetchJson, postJson } from './restJson';
import { mapWithConcurrency, reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ES_RESOURCE_TYPES = ['opensearch_domain'] as const;

/** DescribeDomains accepts at most 5 domain names per call. */
const DESCRIBE_BATCH = 5;

interface DomainNameInfo { DomainName: string; EngineType?: string }
export interface DomainStatus {
  DomainName: string; DomainId?: string; ARN?: string; Created?: boolean; Deleted?: boolean; Processing?: boolean;
  Endpoint?: string; Endpoints?: Record<string, string>;
  EngineVersion?: string;
  ClusterConfig?: { InstanceType?: string; InstanceCount?: number; DedicatedMasterEnabled?: boolean; ZoneAwarenessEnabled?: boolean };
  VPCOptions?: { VPCId?: string; SubnetIds?: string[]; SecurityGroupIds?: string[] };
  EncryptionAtRestOptions?: { Enabled?: boolean; KmsKeyId?: string };
  NodeToNodeEncryptionOptions?: { Enabled?: boolean };
  DomainEndpointOptions?: { EnforceHTTPS?: boolean; TLSSecurityPolicy?: string };
  AdvancedSecurityOptions?: { Enabled?: boolean; InternalUserDatabaseEnabled?: boolean };
  AccessPolicies?: string;
  LogPublishingOptions?: Record<string, { Enabled?: boolean }>;
  CognitoOptions?: { Enabled?: boolean };
  SoftwareUpdateOptions?: { AutoSoftwareUpdateEnabled?: boolean };
  ServiceSoftwareOptions?: { UpdateAvailable?: boolean };
}

/** Security evidence for one domain (FSBP Opensearch.1–.11). */
export function domainEvidence(d: DomainStatus | undefined, engineType: string | undefined) {
  if (!d) return { detailsCollected: false, engineType };
  const logs = d.LogPublishingOptions ?? {};
  const vpc = !!d.VPCOptions?.VPCId;
  const policy = summarizePolicy(d.AccessPolicies, accountIdFromArn(d.ARN));
  return {
    detailsCollected: true,
    engineType, engineVersion: d.EngineVersion, endpoint: d.Endpoint ?? d.Endpoints?.vpc ?? null,
    instanceType: d.ClusterConfig?.InstanceType, instanceCount: d.ClusterConfig?.InstanceCount,
    arn: d.ARN ?? null,
    // A domain outside a VPC has a public endpoint; with an open access policy it is reachable by anyone.
    inVpc: vpc,
    publiclyAccessible: !vpc && policy.allowsAnonymous,
    accessPolicy: policy,
    encryptionAtRestEnabled: d.EncryptionAtRestOptions?.Enabled ?? false,
    nodeToNodeEncryptionEnabled: d.NodeToNodeEncryptionOptions?.Enabled ?? false,
    enforceHttps: d.DomainEndpointOptions?.EnforceHTTPS ?? false,
    tlsSecurityPolicy: d.DomainEndpointOptions?.TLSSecurityPolicy ?? null,
    fineGrainedAccessControl: d.AdvancedSecurityOptions?.Enabled ?? false,
    auditLogsEnabled: logs.AUDIT_LOGS?.Enabled ?? false,
    errorLogsEnabled: logs.ES_APPLICATION_LOGS?.Enabled ?? false,
    dedicatedMasterEnabled: d.ClusterConfig?.DedicatedMasterEnabled ?? false,
    zoneAwarenessEnabled: d.ClusterConfig?.ZoneAwarenessEnabled ?? false,
    softwareUpdateAvailable: d.ServiceSoftwareOptions?.UpdateAvailable ?? null,
  };
}

const chunk = <T>(xs: T[], n: number): T[][] => Array.from({ length: Math.ceil(xs.length / n) }, (_, i) => xs.slice(i * n, i * n + n));

/**
 * Amazon OpenSearch Service domains (REST-JSON, API 2021-01-01).
 *
 * What changed, and why:
 *  - The per-domain detail call used `/2021-01-01/es/domain/{name}`, a path
 *    that mixes the 2021 API version with the legacy `es` resource and does
 *    not exist -- so every domain fell back to a name-only row with NO
 *    security evidence. Details now come from the batch DescribeDomains call
 *    (POST /2021-01-01/opensearch/domain-info, 5 names per call).
 *  - resourceId is the domain NAME (unique per account and region) in every
 *    case, so a row's identity no longer depends on whether its describe
 *    succeeded; the ARN is in metadata.
 *  - A failed list is reported rather than returned as []; bodies are
 *    parsed defensively.
 *  - Evidence: VPC vs public endpoint and access policy, encryption at rest
 *    and node-to-node, HTTPS enforcement and TLS policy, fine-grained access
 *    control, audit/error logs, dedicated masters and zone awareness.
 */
export async function scanOpenSearch(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'es', ctx.region);
  const base = `https://es.${ctx.region}.amazonaws.com/2021-01-01`;

  const list = await fetchJson(client, `${base}/domain`);
  if (!list.ok) {
    console.error(`OpenSearch ListDomainNames failed in ${ctx.region} (continuing without it): ${list.error ?? list.status}`);
    reportListingFailure(ctx, { service: 'es', action: 'ListDomainNames', region: ctx.region, httpStatus: list.status });
    return [];
  }
  const domains = ((list.body?.DomainNames as DomainNameInfo[] | undefined) ?? []).filter((d) => !!d?.DomainName);

  const statuses = new Map<string, DomainStatus>();
  await mapWithConcurrency(chunk(domains.map((d) => d.DomainName), DESCRIBE_BATCH), 3, async (names) => {
    const res = await postJson(client, `${base}/opensearch/domain-info`, { DomainNames: names });
    if (!res.ok) {
      console.error(`OpenSearch DescribeDomains failed for ${names.join(', ')} in ${ctx.region}: ${res.error ?? res.status}`);
      return;
    }
    for (const s of (res.body?.DomainStatusList as DomainStatus[] | undefined) ?? []) {
      if (s?.DomainName) statuses.set(s.DomainName, s);
    }
  });

  return domains.map((d) => {
    const s = statuses.get(d.DomainName);
    return {
      resourceTypeKey: 'opensearch_domain', resourceId: d.DomainName, region: ctx.region, resourceName: d.DomainName,
      state: s ? (s.Deleted ? 'deleting' : s.Processing ? 'processing' : 'active') : undefined,
      metadata: domainEvidence(s, d.EngineType),
      relationships: {
        vpcId: s?.VPCOptions?.VPCId ?? null,
        subnetIds: s?.VPCOptions?.SubnetIds ?? [],
        securityGroupIds: s?.VPCOptions?.SecurityGroupIds ?? [],
        kmsKeyId: s?.EncryptionAtRestOptions?.KmsKeyId ?? null,
      },
    };
  });
}
