import { callJsonApi } from '../awsApi';
import { reportWalk, toIso, walkJsonRpc } from './restJson';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const APPRUNNER_RESOURCE_TYPES = ['app_runner_service', 'app_runner_connection'] as const;

const TARGET_PREFIX = 'AppRunner_20200515';
/** DescribeService follow-ups per region (network/encryption evidence). */
const MAX_SERVICE_DETAILS = 25;
const DETAIL_CONCURRENCY = 4;

interface ServiceSummary { ServiceArn: string; ServiceId?: string; ServiceName?: string; ServiceUrl?: string; Status?: string; CreatedAt?: number | string; UpdatedAt?: number | string }
interface Connection { ConnectionArn: string; ConnectionName?: string; ProviderType?: string; Status?: string; CreatedAt?: number | string }
interface ServiceDetail {
  NetworkConfiguration?: {
    EgressConfiguration?: { EgressType?: string; VpcConnectorArn?: string };
    IngressConfiguration?: { IsPubliclyAccessible?: boolean };
    IpAddressType?: string;
  };
  EncryptionConfiguration?: { KmsKey?: string };
  InstanceConfiguration?: { InstanceRoleArn?: string; Cpu?: string; Memory?: string };
  ObservabilityConfiguration?: { ObservabilityEnabled?: boolean };
  SourceConfiguration?: { AutoDeploymentsEnabled?: boolean; ImageRepository?: { ImageRepositoryType?: string }; CodeRepository?: { RepositoryUrl?: string } };
}

/** Security evidence from DescribeService; `collected: false` means NOT_ASSESSED. */
export function serviceEvidence(detail: ServiceDetail | null) {
  if (!detail) {
    return { detailsCollected: false, publiclyAccessible: null, egressType: null, customerManagedKms: null, instanceRoleArn: null, observabilityEnabled: null, autoDeploymentsEnabled: null };
  }
  return {
    detailsCollected: true,
    // An App Runner service is internet-reachable unless ingress is private.
    publiclyAccessible: detail.NetworkConfiguration?.IngressConfiguration?.IsPubliclyAccessible ?? true,
    egressType: detail.NetworkConfiguration?.EgressConfiguration?.EgressType ?? 'DEFAULT',
    vpcConnectorArn: detail.NetworkConfiguration?.EgressConfiguration?.VpcConnectorArn ?? null,
    customerManagedKms: !!detail.EncryptionConfiguration?.KmsKey,
    kmsKey: detail.EncryptionConfiguration?.KmsKey ?? null,
    instanceRoleArn: detail.InstanceConfiguration?.InstanceRoleArn ?? null,
    observabilityEnabled: detail.ObservabilityConfiguration?.ObservabilityEnabled ?? false,
    autoDeploymentsEnabled: detail.SourceConfiguration?.AutoDeploymentsEnabled ?? null,
    sourceType: detail.SourceConfiguration?.ImageRepository ? 'image' : detail.SourceConfiguration?.CodeRepository ? 'code' : null,
  };
}

/**
 * AWS App Runner (JSON-RPC, AppRunner_20200515). Closed to new customers,
 * kept for existing users' visibility.
 *
 * Both lists paginate now (NextToken; default page is 20 services, so the
 * 21st used to vanish). ListConnections failures are reported instead of
 * silently dropping every connection. Each service carries network exposure
 * (public vs private ingress, VPC egress), KMS encryption and instance role
 * from a bounded DescribeService pass.
 */
export async function scanAppRunner(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `apprunner.${ctx.region}.amazonaws.com`;
  const [servicesWalk, connectionsWalk] = await Promise.all([
    walkJsonRpc<ServiceSummary>(ctx, { service: 'apprunner', host, target: `${TARGET_PREFIX}.ListServices`, body: { MaxResults: 20 } }, 'ServiceSummaryList'),
    walkJsonRpc<Connection>(ctx, { service: 'apprunner', host, target: `${TARGET_PREFIX}.ListConnections`, body: { MaxResults: 100 } }, 'ConnectionSummaryList'),
  ]);
  reportWalk(ctx, servicesWalk, 'apprunner', 'ListServices');
  reportWalk(ctx, connectionsWalk, 'apprunner', 'ListConnections');

  const services = servicesWalk.items.filter((s) => !!s?.ServiceArn);
  const details = new Map<string, ServiceDetail | null>();
  await mapWithConcurrency(services.slice(0, MAX_SERVICE_DETAILS), DETAIL_CONCURRENCY, async (s) => {
    const r = await callJsonApi(ctx.creds, { service: 'apprunner', region: ctx.region, host, target: `${TARGET_PREFIX}.DescribeService`, body: { ServiceArn: s.ServiceArn } });
    details.set(s.ServiceArn, r.ok ? ((r.body as { Service?: ServiceDetail })?.Service ?? null) : null);
  });

  const out: ScannedResource[] = [];
  for (const s of services) {
    const evidence = serviceEvidence(details.get(s.ServiceArn) ?? null);
    out.push({
      resourceTypeKey: 'app_runner_service', resourceId: s.ServiceArn, region: ctx.region, resourceName: s.ServiceName, state: s.Status,
      metadata: { serviceUrl: s.ServiceUrl, createdAt: s.CreatedAt, createdAtIso: toIso(s.CreatedAt), ...evidence },
      relationships: { instanceRoleArn: evidence.instanceRoleArn, vpcConnectorArn: 'vpcConnectorArn' in evidence ? evidence.vpcConnectorArn : null },
    });
  }
  for (const c of connectionsWalk.items) {
    if (!c?.ConnectionArn) continue;
    out.push({ resourceTypeKey: 'app_runner_connection', resourceId: c.ConnectionArn, region: ctx.region, resourceName: c.ConnectionName, state: c.Status, metadata: { providerType: c.ProviderType, createdAtIso: toIso(c.CreatedAt) } });
  }
  return out;
}