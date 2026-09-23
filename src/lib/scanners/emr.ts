import { callJsonApi } from '../awsApi';
import { reportWalk, toIso, walkJsonRpc } from './restJson';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'ElasticMapReduce';
/** DescribeCluster follow-ups per region-step. */
const MAX_CLUSTER_DETAILS = 25;

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const EMR_RESOURCE_TYPES = ['emr_cluster'] as const;

interface ClusterSummary {
  Id: string; Name?: string; NormalizedInstanceHours?: number; ClusterArn?: string;
  Status?: { State?: string; Timeline?: { CreationDateTime?: number } };
}
export interface ClusterDetail {
  SecurityConfiguration?: string;
  KerberosAttributes?: { Realm?: string };
  Ec2InstanceAttributes?: {
    Ec2SubnetId?: string; Ec2KeyName?: string; IamInstanceProfile?: string;
    EmrManagedMasterSecurityGroup?: string; EmrManagedSlaveSecurityGroup?: string; ServiceAccessSecurityGroup?: string;
  };
  MasterPublicDnsName?: string;
  TerminationProtected?: boolean;
  VisibleToAllUsers?: boolean;
  LogUri?: string;
  ReleaseLabel?: string;
  AutoTerminate?: boolean;
  ServiceRole?: string;
  Applications?: { Name?: string; Version?: string }[];
}

/** Security evidence for one cluster (FSBP EMR.1–.4). */
export function clusterEvidence(d: ClusterDetail | null, accountBlockPublicAccess: boolean | null) {
  if (!d) return { detailsCollected: false, accountBlockPublicAccessEnabled: accountBlockPublicAccess };
  const dns = d.MasterPublicDnsName ?? '';
  return {
    detailsCollected: true,
    releaseLabel: d.ReleaseLabel ?? null,
    // EMR.1: a master node with a PUBLIC DNS name is reachable from the internet
    // (private-subnet clusters report an internal "ip-…" name).
    masterHasPublicDns: !!dns && !/^ip-\d+-\d+-\d+-\d+\./.test(dns),
    // Encryption at rest / in transit and Kerberos come from a security configuration.
    securityConfiguration: d.SecurityConfiguration ?? null,
    hasSecurityConfiguration: !!d.SecurityConfiguration,
    kerberosEnabled: !!d.KerberosAttributes?.Realm,
    terminationProtected: d.TerminationProtected ?? false,
    loggingEnabled: !!d.LogUri,
    ec2KeyName: d.Ec2InstanceAttributes?.Ec2KeyName ?? null,
    applications: (d.Applications ?? []).map((a) => a.Name).filter((v): v is string => !!v),
    // EMR.2: account-level block public access (one setting for the whole region).
    accountBlockPublicAccessEnabled: accountBlockPublicAccess,
  };
}

/**
 * Amazon EMR clusters (JSON-RPC, ElasticMapReduce). ListClusters without a
 * state filter returns only active clusters, deliberately: terminated
 * clusters would flood inventory.
 *
 * What changed: ListClusters paginates (Marker); failures are reported.
 * Each cluster carries network exposure and hardening evidence from a
 * bounded DescribeCluster pass, plus the region's EMR block-public-access
 * setting (one GetBlockPublicAccessConfiguration call).
 */
export async function scanEmr(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `elasticmapreduce.${ctx.region}.amazonaws.com`;
  const call = (action: string, body: Record<string, unknown>) =>
    callJsonApi(ctx.creds, { service: 'elasticmapreduce', region: ctx.region, host, target: `${TARGET_PREFIX}.${action}`, body });

  const [walk, bpa] = await Promise.all([
    walkJsonRpc<ClusterSummary>(ctx, { service: 'elasticmapreduce', host, target: `${TARGET_PREFIX}.ListClusters`, body: {} }, 'Clusters', { tokenIn: 'Marker', tokenOut: 'Marker' }),
    call('GetBlockPublicAccessConfiguration', {}),
  ]);
  reportWalk(ctx, walk, 'elasticmapreduce', 'ListClusters');
  const blockPublicAccess = bpa.ok
    ? ((bpa.body as { BlockPublicAccessConfiguration?: { BlockPublicSecurityGroupRules?: boolean } } | null)?.BlockPublicAccessConfiguration?.BlockPublicSecurityGroupRules ?? null)
    : null;

  const clusters = walk.items.filter((c) => !!c?.Id);
  const details = new Map<string, ClusterDetail | null>();
  await mapWithConcurrency(clusters.slice(0, MAX_CLUSTER_DETAILS), 4, async (c) => {
    const r = await call('DescribeCluster', { ClusterId: c.Id });
    details.set(c.Id, r.ok ? ((r.body as { Cluster?: ClusterDetail } | null)?.Cluster ?? null) : null);
  });

  return clusters.map((c) => {
    const d = details.get(c.Id) ?? null;
    return {
      resourceTypeKey: 'emr_cluster', resourceId: c.Id, region: ctx.region, resourceName: c.Name,
      state: c.Status?.State,
      metadata: {
        normalizedInstanceHours: c.NormalizedInstanceHours, createdAt: c.Status?.Timeline?.CreationDateTime,
        createdAtIso: toIso(c.Status?.Timeline?.CreationDateTime),
        arn: c.ClusterArn ?? null,
        ...clusterEvidence(d, blockPublicAccess),
      },
      relationships: {
        subnetId: d?.Ec2InstanceAttributes?.Ec2SubnetId ?? null,
        serviceRole: d?.ServiceRole ?? null,
        instanceProfile: d?.Ec2InstanceAttributes?.IamInstanceProfile ?? null,
        securityGroupIds: [d?.Ec2InstanceAttributes?.EmrManagedMasterSecurityGroup, d?.Ec2InstanceAttributes?.EmrManagedSlaveSecurityGroup, d?.Ec2InstanceAttributes?.ServiceAccessSecurityGroup]
          .filter((v): v is string => !!v),
      },
    };
  });
}
