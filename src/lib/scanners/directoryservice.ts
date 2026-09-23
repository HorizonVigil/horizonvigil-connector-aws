import { reportWalk, toIso, walkJsonRpc } from './restJson';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const DIRECTORYSERVICE_RESOURCE_TYPES = ['directory_service_directory'] as const;

const TARGET_PREFIX = 'DirectoryService_20150416';

export interface DirectoryDescription {
  DirectoryId: string; Name?: string; ShortName?: string; Type?: string; Edition?: string; Stage?: string; LaunchTime?: number; Size?: string;
  DnsIpAddrs?: string[];
  VpcSettings?: { VpcId?: string; SubnetIds?: string[]; SecurityGroupId?: string; AvailabilityZones?: string[] };
  ConnectSettings?: { VpcId?: string; SubnetIds?: string[]; SecurityGroupId?: string };
  RadiusStatus?: string;
  SsoEnabled?: boolean;
  DesiredNumberOfDomainControllers?: number;
  ShareStatus?: string; ShareMethod?: string; OwnerDirectoryDescription?: { AccountId?: string };
}
interface LogSubscription { DirectoryId?: string; LogGroupName?: string }

/** Identity-infrastructure evidence for one directory. */
export function directoryEvidence(d: DirectoryDescription, logGroup: string | null | undefined, logsCollected: boolean) {
  const vpc = d.VpcSettings ?? d.ConnectSettings;
  return {
    type: d.Type, size: d.Size, launchTime: d.LaunchTime, dnsIpAddrs: d.DnsIpAddrs,
    launchTimeIso: toIso(d.LaunchTime),
    edition: d.Edition ?? null,
    shortName: d.ShortName ?? null,
    // RADIUS MFA for directory-authenticated sign-ins.
    radiusMfaStatus: d.RadiusStatus ?? null,
    mfaEnabled: d.RadiusStatus === 'Completed',
    ssoEnabled: d.SsoEnabled ?? false,
    domainControllerCount: d.DesiredNumberOfDomainControllers ?? null,
    // A directory shared from another account.
    sharedFromAccount: d.OwnerDirectoryDescription?.AccountId ?? null,
    shareStatus: d.ShareStatus ?? null,
    // Security-event forwarding to CloudWatch Logs.
    logSubscriptionsCollected: logsCollected,
    logForwardingEnabled: logsCollected ? !!logGroup : null,
    logGroupName: logGroup ?? null,
    securityGroupId: vpc?.SecurityGroupId ?? null,
  };
}

/**
 * AWS Directory Service directories (JSON-RPC, DirectoryService_20150416).
 *
 * DescribeDirectories paginates now (NextToken); a failure is reported
 * rather than returned as []. Each directory carries RADIUS MFA, SSO, domain
 * controller count, sharing, and whether security logs are forwarded (one
 * account-wide ListLogSubscriptions call).
 */
export async function scanDirectoryService(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `ds.${ctx.region}.amazonaws.com`;
  const [dirs, subs] = await Promise.all([
    walkJsonRpc<DirectoryDescription>(ctx, { service: 'ds', host, target: `${TARGET_PREFIX}.DescribeDirectories`, body: {} }, 'DirectoryDescriptions'),
    walkJsonRpc<LogSubscription>(ctx, { service: 'ds', host, target: `${TARGET_PREFIX}.ListLogSubscriptions`, body: {} }, 'LogSubscriptions'),
  ]);
  reportWalk(ctx, dirs, 'ds', 'DescribeDirectories');
  const logByDirectory = new Map(subs.items.filter((s) => s?.DirectoryId).map((s) => [s.DirectoryId as string, s.LogGroupName ?? null]));

  return dirs.items.filter((d) => !!d?.DirectoryId).map((d) => {
    const vpc = d.VpcSettings ?? d.ConnectSettings;
    return {
      resourceTypeKey: 'directory_service_directory', resourceId: d.DirectoryId, region: ctx.region, resourceName: d.Name,
      state: d.Stage,
      metadata: directoryEvidence(d, logByDirectory.get(d.DirectoryId), subs.complete),
      relationships: { vpcId: vpc?.VpcId ?? null, subnetIds: vpc?.SubnetIds ?? [], securityGroupId: vpc?.SecurityGroupId ?? null },
    };
  });
}