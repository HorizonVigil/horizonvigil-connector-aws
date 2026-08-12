import { createAwsClient } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const EKS_RESOURCE_TYPES = ['eks_cluster', 'eks_nodegroup', 'eks_addon', 'eks_fargate_profile', 'eks_identity_provider_config', 'eks_access_entry'] as const;

interface EksClusterDetail {
  name: string; arn?: string; status?: string; version?: string; endpoint?: string;
  createdAt?: string; roleArn?: string; platformVersion?: string;
  resourcesVpcConfig?: {
    vpcId?: string; subnetIds?: string[]; securityGroupIds?: string[]; clusterSecurityGroupId?: string;
    endpointPublicAccess?: boolean; endpointPrivateAccess?: boolean; publicAccessCidrs?: string[];
  };
  logging?: { clusterLogging?: { types?: string[]; enabled?: boolean }[] };
  encryptionConfig?: { resources?: string[]; provider?: { keyArn?: string } }[];
  health?: { issues?: { code?: string; message?: string; resourceIds?: string[] }[] };
  accessConfig?: { authenticationMode?: string };
  // IRSA (IAM Roles for Service Accounts) hinges on this issuer being
  // registered as an IAM OIDC identity provider (a separate, account-wide
  // IAM object, already captured by iam.ts's own scanner as
  // iam_oidc_provider) -- not re-fetched here, the frontend cross-references
  // this URL against those existing rows instead of duplicating the IAM call.
  identity?: { oidc?: { issuer?: string } };
}
interface EksAccessEntryDetail {
  principalArn?: string; kubernetesGroups?: string[]; username?: string; type?: string;
  createdAt?: string; modifiedAt?: string;
}
interface EksNodegroupDetail {
  nodegroupName: string; status?: string; instanceTypes?: string[]; amiType?: string; createdAt?: string;
  scalingConfig?: { minSize?: number; maxSize?: number; desiredSize?: number };
  capacityType?: string; subnets?: string[]; diskSize?: number; releaseVersion?: string; version?: string;
  nodeRole?: string; labels?: Record<string, string>; taints?: { key?: string; value?: string; effect?: string }[];
  launchTemplate?: { id?: string; name?: string; version?: string };
  health?: { issues?: { code?: string; message?: string; resourceIds?: string[] }[] };
}

// Hand-maintained, same "update when it changes" precedent as this
// codebase's other drift-prone constants (e.g. discovery.ts's catalogued
// count) — EKS's own standard-support policy keeps the newest ~4 minor
// versions in standard support at any time; anything older is either
// extended support (billed) or fully unsupported. Exact cutoffs shift as
// AWS ships new versions, so this is a "roughly current" signal for the
// UI, not an authoritative deprecation-date source.
export const EKS_LATEST_STANDARD_SUPPORT_VERSION = '1.31';

/**
 * EKS is REST-JSON, like lambda.ts — ListClusters only returns bare names,
 * so a GetCluster (and, per cluster, ListNodegroups + GetNodegroup) follow
 * up. Capped at 10 clusters and, per cluster, 10 nodegroups — EKS clusters
 * per account/region are typically few, so this covers the common case;
 * an account with more needs pagination support, not built yet.
 */
export async function scanEks(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'eks', ctx.region);
  const base = `https://eks.${ctx.region}.amazonaws.com`;
  const getJson = async (path: string): Promise<Record<string, unknown> | null> => {
    const res = await client.fetch(`${base}${path}`, { method: 'GET' });
    const text = await res.text();
    if (!res.ok) {
      console.error(`EKS GET ${path} failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };

  const out: ScannedResource[] = [];
  // Unlike every per-cluster detail call below (best-effort, one bad
  // cluster shouldn't lose the others), a failed ListClusters itself must
  // not be swallowed to []: that's indistinguishable from an honest
  // zero-cluster account, and is exactly the failure mode reported when
  // eksworkloads.ts's own independent ListClusters call (verified working
  // against a real cluster) found real nodes/namespaces the same run this
  // scanner reported zero clusters -- a scan-time permission or transient
  // API issue on this specific call would explain that gap; silently
  // returning [] here made it undiagnosable.
  const listRes = await client.fetch(`${base}/clusters`, { method: 'GET' });
  const listText = await listRes.text();
  if (!listRes.ok) throw new Error(`EKS ListClusters failed in ${ctx.region}: HTTP ${listRes.status} ${listText.slice(0, 300)}`);
  const list = listText ? (JSON.parse(listText) as Record<string, unknown>) : {};
  const names = ((list?.clusters as string[] | undefined) ?? []).slice(0, 10);

  for (const name of names) {
    const detail = await getJson(`/clusters/${encodeURIComponent(name)}`);
    const cluster = detail?.cluster as EksClusterDetail | undefined;
    if (cluster) {
      const vpcConfig = cluster.resourcesVpcConfig;
      // AWS returns clusterLogging as one entry per (types, enabled) group,
      // not one row per log type -- flattened here into the 5 fixed type
      // names so the UI can just look up each one's enabled state directly.
      const enabledLogTypes = new Set<string>();
      for (const entry of cluster.logging?.clusterLogging ?? []) {
        if (entry.enabled) for (const t of entry.types ?? []) enabledLogTypes.add(t);
      }
      out.push({
        resourceTypeKey: 'eks_cluster', resourceId: cluster.arn ?? name, region: ctx.region, resourceName: name,
        state: cluster.status,
        metadata: {
          version: cluster.version, endpoint: cluster.endpoint, createdAt: cluster.createdAt, platformVersion: cluster.platformVersion,
          latestStandardSupportVersion: EKS_LATEST_STANDARD_SUPPORT_VERSION,
          subnetIds: vpcConfig?.subnetIds, securityGroupIds: vpcConfig?.securityGroupIds, clusterSecurityGroupId: vpcConfig?.clusterSecurityGroupId,
          endpointPublicAccess: vpcConfig?.endpointPublicAccess, endpointPrivateAccess: vpcConfig?.endpointPrivateAccess, publicAccessCidrs: vpcConfig?.publicAccessCidrs,
          logTypes: ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'].map(t => ({ type: t, enabled: enabledLogTypes.has(t) })),
          secretsEncryptionKeyArn: cluster.encryptionConfig?.find(e => e.resources?.includes('secrets'))?.provider?.keyArn ?? null,
          healthIssues: cluster.health?.issues ?? [],
          authenticationMode: cluster.accessConfig?.authenticationMode,
          oidcIssuerUrl: cluster.identity?.oidc?.issuer,
        },
        relationships: { roleArn: cluster.roleArn, vpcId: vpcConfig?.vpcId },
      });
    }

    const ngList = await getJson(`/clusters/${encodeURIComponent(name)}/node-groups`);
    const ngNames = ((ngList?.nodegroups as string[] | undefined) ?? []).slice(0, 10);
    for (const ngName of ngNames) {
      const ngDetail = await getJson(`/clusters/${encodeURIComponent(name)}/node-groups/${encodeURIComponent(ngName)}`);
      const ng = ngDetail?.nodegroup as EksNodegroupDetail | undefined;
      out.push({
        resourceTypeKey: 'eks_nodegroup', resourceId: `${name}/${ngName}`, region: ctx.region, resourceName: ngName,
        state: ng?.status,
        metadata: {
          instanceTypes: ng?.instanceTypes, amiType: ng?.amiType, createdAt: ng?.createdAt,
          minSize: ng?.scalingConfig?.minSize, maxSize: ng?.scalingConfig?.maxSize, desiredSize: ng?.scalingConfig?.desiredSize,
          capacityType: ng?.capacityType, subnets: ng?.subnets, diskSizeGiB: ng?.diskSize,
          releaseVersion: ng?.releaseVersion, kubernetesVersion: ng?.version,
          labels: ng?.labels ?? {}, taints: ng?.taints ?? [],
          launchTemplate: ng?.launchTemplate, healthIssues: ng?.health?.issues ?? [],
        },
        relationships: { clusterName: name, nodeRoleArn: ng?.nodeRole },
      });
    }
  }

  // Addons, Fargate profiles, and identity provider configs — three more
  // per-cluster list-name-only calls (AWS doesn't return details in the
  // list response for any of these), capped to the first 3 clusters rather
  // than the 10 above, since these are additive to an already-generous
  // per-cluster fan-out.
  for (const name of names.slice(0, 3)) {
    const addonList = await getJson(`/clusters/${encodeURIComponent(name)}/addons`);
    for (const addonName of (addonList?.addons as string[] | undefined) ?? []) {
      out.push({ resourceTypeKey: 'eks_addon', resourceId: `${name}/${addonName}`, region: ctx.region, resourceName: addonName, relationships: { clusterName: name } });
    }

    const fpList = await getJson(`/clusters/${encodeURIComponent(name)}/fargate-profiles`);
    for (const fpName of (fpList?.fargateProfileNames as string[] | undefined) ?? []) {
      out.push({ resourceTypeKey: 'eks_fargate_profile', resourceId: `${name}/${fpName}`, region: ctx.region, resourceName: fpName, relationships: { clusterName: name } });
    }

    const idpList = await getJson(`/clusters/${encodeURIComponent(name)}/identity-provider-configs`);
    for (const idp of (idpList?.identityProviderConfigs as { name: string; type: string }[] | undefined) ?? []) {
      out.push({ resourceTypeKey: 'eks_identity_provider_config', resourceId: `${name}/${idp.name}`, region: ctx.region, resourceName: idp.name, metadata: { type: idp.type }, relationships: { clusterName: name } });
    }

    // Access entries — the modern (2023+) replacement for the aws-auth
    // ConfigMap, only present on clusters using API/API_AND_CONFIG_MAP
    // authentication mode (accessConfig.authenticationMode, already
    // captured above). A cluster in CONFIG_MAP-only mode legitimately has
    // zero of these; eksworkloads.ts separately parses the ConfigMap itself
    // for that case, since the two mechanisms are mutually exclusive per
    // principal but a cluster can genuinely use both at once.
    const entriesList = await getJson(`/clusters/${encodeURIComponent(name)}/access-entries`);
    const entryArns = ((entriesList?.accessEntries as string[] | undefined) ?? []).slice(0, 20);
    for (const principalArn of entryArns) {
      const encodedArn = encodeURIComponent(principalArn);
      const [entryDetail, policiesResult] = await Promise.all([
        getJson(`/clusters/${encodeURIComponent(name)}/access-entries/${encodedArn}`),
        getJson(`/clusters/${encodeURIComponent(name)}/access-entries/${encodedArn}/access-policies`),
      ]);
      const entry = entryDetail?.accessEntry as EksAccessEntryDetail | undefined;
      const policies = (policiesResult?.associatedAccessPolicies as { policyArn?: string; accessScope?: { type?: string; namespaces?: string[] } }[] | undefined) ?? [];
      out.push({
        resourceTypeKey: 'eks_access_entry', resourceId: `${name}/${principalArn}`, region: ctx.region, resourceName: principalArn.split('/').pop(),
        metadata: {
          principalArn, type: entry?.type, kubernetesGroups: entry?.kubernetesGroups ?? [], username: entry?.username,
          createdAt: entry?.createdAt, modifiedAt: entry?.modifiedAt,
          associatedPolicies: policies.map(p => ({ policyArn: p.policyArn, scopeType: p.accessScope?.type, namespaces: p.accessScope?.namespaces })),
        },
        relationships: { clusterName: name },
      });
    }
  }

  return out;
}
