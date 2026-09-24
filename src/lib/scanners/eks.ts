import { createAwsClient } from '../awsApi';
import { siblingArn } from './dynamodb';
import { fetchJson, reportWalk, walkPages, type PageWalk } from './restJson';
import { mapWithConcurrency, reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const EKS_RESOURCE_TYPES = ['eks_cluster', 'eks_nodegroup', 'eks_addon', 'eks_fargate_profile', 'eks_identity_provider_config', 'eks_access_entry'] as const;

/** Clusters fully enumerated (details + children) per region-step. */
const MAX_CLUSTERS = 25;
/** Access-entry details per cluster (two calls each). */
const MAX_ACCESS_ENTRY_DETAILS = 50;
const CONCURRENCY = 3;

interface Issue { code?: string; message?: string; resourceIds?: string[] }
export interface EksClusterDetail {
  name: string; arn?: string; status?: string; version?: string; endpoint?: string;
  createdAt?: string; roleArn?: string; platformVersion?: string;
  resourcesVpcConfig?: {
    vpcId?: string; subnetIds?: string[]; securityGroupIds?: string[]; clusterSecurityGroupId?: string;
    endpointPublicAccess?: boolean; endpointPrivateAccess?: boolean; publicAccessCidrs?: string[];
  };
  logging?: { clusterLogging?: { types?: string[]; enabled?: boolean }[] };
  encryptionConfig?: { resources?: string[]; provider?: { keyArn?: string } }[];
  health?: { issues?: Issue[] };
  accessConfig?: { authenticationMode?: string; bootstrapClusterCreatorAdminPermissions?: boolean };
  identity?: { oidc?: { issuer?: string } };
  upgradePolicy?: { supportType?: string };
}
interface EksAccessEntryDetail {
  principalArn?: string; kubernetesGroups?: string[]; username?: string; type?: string; createdAt?: string; modifiedAt?: string;
}
export interface EksNodegroupDetail {
  nodegroupName: string; nodegroupArn?: string; status?: string; instanceTypes?: string[]; amiType?: string; createdAt?: string;
  scalingConfig?: { minSize?: number; maxSize?: number; desiredSize?: number };
  capacityType?: string; subnets?: string[]; diskSize?: number; releaseVersion?: string; version?: string;
  nodeRole?: string; labels?: Record<string, string>; taints?: { key?: string; value?: string; effect?: string }[];
  launchTemplate?: { id?: string; name?: string; version?: string };
  remoteAccess?: { ec2SshKey?: string; sourceSecurityGroups?: string[] };
  health?: { issues?: Issue[] };
}
interface ClusterVersionInfo { clusterVersion?: string; status?: string; versionStatus?: string; endOfStandardSupportDate?: string; endOfExtendedSupportDate?: string }

/**
 * Fallback ONLY. Support status now comes from DescribeClusterVersions
 * (GET /cluster-versions), which is authoritative and never goes stale; this
 * constant is used when that call is unavailable, and is kept exported for
 * existing importers. Treat it as a rough signal, not a policy source.
 */
export const EKS_LATEST_STANDARD_SUPPORT_VERSION = '1.31';

const versionKey = (v: string) => v.split('.').map((n) => n.padStart(4, '0')).join('.');

/** Posture evidence for one cluster (FSBP EKS.1/.2/.3/.8). */
export function clusterEvidence(c: EksClusterDetail, versions: Map<string, ClusterVersionInfo>, latestStandard: string) {
  const vpc = c.resourcesVpcConfig;
  const enabledLogTypes = new Set<string>();
  for (const entry of c.logging?.clusterLogging ?? []) if (entry.enabled) for (const t of entry.types ?? []) enabledLogTypes.add(t);
  const v = c.version ? versions.get(c.version) : undefined;
  const cidrs = vpc?.publicAccessCidrs ?? [];
  return {
    version: c.version, endpoint: c.endpoint, createdAt: c.createdAt, platformVersion: c.platformVersion,
    latestStandardSupportVersion: latestStandard,
    // Authoritative per-version support state when available.
    versionSupportStatus: v?.status ?? v?.versionStatus ?? null,
    endOfStandardSupportDate: v?.endOfStandardSupportDate ?? null,
    endOfExtendedSupportDate: v?.endOfExtendedSupportDate ?? null,
    upgradePolicySupportType: c.upgradePolicy?.supportType ?? null,
    subnetIds: vpc?.subnetIds, securityGroupIds: vpc?.securityGroupIds, clusterSecurityGroupId: vpc?.clusterSecurityGroupId,
    endpointPublicAccess: vpc?.endpointPublicAccess, endpointPrivateAccess: vpc?.endpointPrivateAccess, publicAccessCidrs: vpc?.publicAccessCidrs,
    // EKS.1: a public endpoint open to 0.0.0.0/0 exposes the Kubernetes API to the internet.
    publicEndpointOpenToWorld: !!vpc?.endpointPublicAccess && (cidrs.length === 0 || cidrs.includes('0.0.0.0/0')),
    logTypes: ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'].map((t) => ({ type: t, enabled: enabledLogTypes.has(t) })),
    // EKS.3: envelope encryption of Kubernetes secrets.
    secretsEncryptionKeyArn: c.encryptionConfig?.find((e) => e.resources?.includes('secrets'))?.provider?.keyArn ?? null,
    healthIssues: c.health?.issues ?? [],
    authenticationMode: c.accessConfig?.authenticationMode,
    oidcIssuerUrl: c.identity?.oidc?.issuer,
  };
}

/** Node-group evidence, including SSH exposure. */
export function nodegroupEvidence(ng: EksNodegroupDetail | undefined) {
  if (!ng) return { detailsCollected: false };
  const ssh = ng.remoteAccess;
  return {
    detailsCollected: true,
    instanceTypes: ng.instanceTypes, amiType: ng.amiType, createdAt: ng.createdAt,
    minSize: ng.scalingConfig?.minSize, maxSize: ng.scalingConfig?.maxSize, desiredSize: ng.scalingConfig?.desiredSize,
    capacityType: ng.capacityType, subnets: ng.subnets, diskSizeGiB: ng.diskSize,
    releaseVersion: ng.releaseVersion, kubernetesVersion: ng.version,
    labels: ng.labels ?? {}, taints: ng.taints ?? [],
    launchTemplate: ng.launchTemplate, healthIssues: ng.health?.issues ?? [],
    // SSH remote access with NO source security group is open to 0.0.0.0/0 on port 22.
    sshRemoteAccessEnabled: !!ssh?.ec2SshKey,
    sshOpenToInternet: !!ssh?.ec2SshKey && (ssh.sourceSecurityGroups ?? []).length === 0,
  };
}

/**
 * Amazon EKS clusters and their AWS-side children (REST-JSON).
 *
 * What changed, and why:
 *  - Every list paginates (nextToken). Clusters were capped at 10, node
 *    groups at 10 per cluster, and add-ons / Fargate profiles / identity
 *    configs / access entries were read for only the first 3 clusters --
 *    silently, so everything past a cap looked deleted. Remaining bounds are
 *    reported as truncation.
 *  - A cluster whose GetCluster failed keeps a stable ARN identity.
 *  - Version support comes from DescribeClusterVersions (authoritative),
 *    add-on "latest version" lookups are cached per (add-on, k8s version),
 *    and bodies are parsed defensively.
 *  - Evidence: public endpoint open to the world, node-group SSH exposure,
 *    cluster-admin access entries.
 *
 * A failed ListClusters still THROWS (deliberately, unchanged): an empty
 * answer there is indistinguishable from "no clusters".
 */
export async function scanEks(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'eks', ctx.region);
  const base = `https://eks.${ctx.region}.amazonaws.com`;
  const get = (path: string) => fetchJson(client, `${base}${path}`);
  const list = <T>(path: string, key: string): Promise<PageWalk<T>> => walkPages<T>(
    (token) => get(`${path}${path.includes('?') ? '&' : '?'}maxResults=100${token ? `&nextToken=${encodeURIComponent(token)}` : ''}`),
    (b) => b[key],
    (b) => b.nextToken,
  );
  const enc = encodeURIComponent;

  const clustersWalk = await list<string>('/clusters', 'clusters');
  if (clustersWalk.firstPageFailed) {
    throw new Error(`EKS ListClusters failed in ${ctx.region}: ${clustersWalk.error ?? clustersWalk.status}`);
  }
  reportWalk(ctx, clustersWalk, 'eks', 'ListClusters');
  const names = [...new Set(clustersWalk.items.filter((n): n is string => typeof n === 'string'))];
  const enumerated = names.slice(0, MAX_CLUSTERS);
  if (names.length > enumerated.length) {
    console.error(`EKS ${ctx.region}: ${names.length} clusters; children enumerated for the first ${enumerated.length}.`);
    for (const action of ['ListNodegroups', 'ListAddons', 'ListFargateProfiles', 'ListIdentityProviderConfigs', 'ListAccessEntries']) {
      reportListingFailure(ctx, { service: 'eks', action, region: ctx.region, truncated: true });
    }
  }

  // Authoritative version-support data (one call); falls back to the constant.
  const versionsWalk = await list<ClusterVersionInfo>('/cluster-versions', 'clusterVersions');
  const versions = new Map(versionsWalk.items.filter((v) => v?.clusterVersion).map((v) => [v.clusterVersion as string, v]));
  const standard = [...versions.values()].filter((v) => (v.status ?? v.versionStatus) === 'STANDARD_SUPPORT').map((v) => v.clusterVersion as string);
  const latestStandard = standard.sort((a, b) => versionKey(b).localeCompare(versionKey(a)))[0] ?? EKS_LATEST_STANDARD_SUPPORT_VERSION;

  const addonLatest = new Map<string, Promise<string | undefined>>();
  const latestAddonVersion = (addon: string, k8s: string) => {
    const key = `${addon}@${k8s}`;
    if (!addonLatest.has(key)) {
      addonLatest.set(key, get(`/addons/supported-versions?addonName=${enc(addon)}&kubernetesVersion=${enc(k8s)}`).then((r) => {
        const info = (r.body?.addons as { addonVersions?: { addonVersion?: string }[] }[] | undefined) ?? [];
        // AWS lists addonVersions newest-first in practice (not formally guaranteed).
        return info[0]?.addonVersions?.[0]?.addonVersion;
      }));
    }
    return addonLatest.get(key) as Promise<string | undefined>;
  };

  const perCluster = await mapWithConcurrency(enumerated, CONCURRENCY, async (name) => {
    const out: ScannedResource[] = [];
    const cp = `/clusters/${enc(name)}`;
    const detail = await get(cp);
    const cluster = detail.ok ? (detail.body?.cluster as EksClusterDetail | undefined) : undefined;
    const k8sVersion = cluster?.version;

    const [ngs, addons, fps, idps, entries] = await Promise.all([
      list<string>(`${cp}/node-groups`, 'nodegroups'),
      list<string>(`${cp}/addons`, 'addons'),
      list<string>(`${cp}/fargate-profiles`, 'fargateProfileNames'),
      list<{ name: string; type: string }>(`${cp}/identity-provider-configs`, 'identityProviderConfigs'),
      list<string>(`${cp}/access-entries`, 'accessEntries'),
    ]);
    reportWalk(ctx, ngs, 'eks', 'ListNodegroups');
    reportWalk(ctx, addons, 'eks', 'ListAddons');
    reportWalk(ctx, fps, 'eks', 'ListFargateProfiles');
    reportWalk(ctx, idps, 'eks', 'ListIdentityProviderConfigs');
    reportWalk(ctx, entries, 'eks', 'ListAccessEntries');

    for (const ngName of ngs.items) {
      const r = await get(`${cp}/node-groups/${enc(ngName)}`);
      const ng = r.ok ? (r.body?.nodegroup as EksNodegroupDetail | undefined) : undefined;
      out.push({
        resourceTypeKey: 'eks_nodegroup', resourceId: `${name}/${ngName}`, region: ctx.region, resourceName: ngName,
        state: ng?.status,
        metadata: nodegroupEvidence(ng),
        relationships: { clusterName: name, nodeRoleArn: ng?.nodeRole, sshSourceSecurityGroups: ng?.remoteAccess?.sourceSecurityGroups ?? [] },
      });
    }

    for (const addonName of addons.items) {
      const [r, latestVersion] = await Promise.all([
        get(`${cp}/addons/${enc(addonName)}`),
        k8sVersion ? latestAddonVersion(addonName, k8sVersion) : Promise.resolve(undefined),
      ]);
      const addon = r.ok ? (r.body?.addon as {
        addonVersion?: string; status?: string; health?: { issues?: Issue[] };
        serviceAccountRoleArn?: string; createdAt?: string; modifiedAt?: string; publisher?: string; owner?: string;
      } | undefined) : undefined;
      out.push({
        resourceTypeKey: 'eks_addon', resourceId: `${name}/${addonName}`, region: ctx.region, resourceName: addonName,
        state: addon?.status,
        metadata: {
          version: addon?.addonVersion, latestVersion, behindLatest: !!latestVersion && !!addon?.addonVersion && latestVersion !== addon.addonVersion,
          healthIssues: addon?.health?.issues ?? [], serviceAccountRoleArn: addon?.serviceAccountRoleArn,
          createdAt: addon?.createdAt, modifiedAt: addon?.modifiedAt, publisher: addon?.publisher, owner: addon?.owner,
        },
        relationships: { clusterName: name },
      });
    }

    for (const fpName of fps.items) {
      out.push({ resourceTypeKey: 'eks_fargate_profile', resourceId: `${name}/${fpName}`, region: ctx.region, resourceName: fpName, relationships: { clusterName: name } });
    }
    for (const idp of idps.items) {
      if (!idp?.name) continue;
      out.push({ resourceTypeKey: 'eks_identity_provider_config', resourceId: `${name}/${idp.name}`, region: ctx.region, resourceName: idp.name, metadata: { type: idp.type }, relationships: { clusterName: name } });
    }

    // Access entries: the modern (2023+) replacement for aws-auth (see eksWorkloads.ts for the ConfigMap path).
    const entryArns = entries.items.slice(0, MAX_ACCESS_ENTRY_DETAILS);
    if (entries.items.length > entryArns.length) reportListingFailure(ctx, { service: 'eks', action: 'ListAccessEntries', region: ctx.region, truncated: true });
    for (const principalArn of entryArns) {
      const e = enc(principalArn);
      const [entryRes, policiesRes] = await Promise.all([get(`${cp}/access-entries/${e}`), get(`${cp}/access-entries/${e}/access-policies`)]);
      const entry = entryRes.ok ? (entryRes.body?.accessEntry as EksAccessEntryDetail | undefined) : undefined;
      const policies = (policiesRes.ok ? (policiesRes.body?.associatedAccessPolicies as { policyArn?: string; accessScope?: { type?: string; namespaces?: string[] } }[] | undefined) : undefined) ?? [];
      out.push({
        resourceTypeKey: 'eks_access_entry', resourceId: `${name}/${principalArn}`, region: ctx.region, resourceName: principalArn.split('/').pop(),
        metadata: {
          principalArn, type: entry?.type, kubernetesGroups: entry?.kubernetesGroups ?? [], username: entry?.username,
          createdAt: entry?.createdAt, modifiedAt: entry?.modifiedAt,
          associatedPolicies: policies.map((p) => ({ policyArn: p.policyArn, scopeType: p.accessScope?.type, namespaces: p.accessScope?.namespaces })),
          // Cluster-wide admin via access policy or the system:masters group.
          grantsClusterAdmin: policies.some((p) => (p.policyArn ?? '').endsWith('/AmazonEKSClusterAdminPolicy') && p.accessScope?.type === 'cluster')
            || (entry?.kubernetesGroups ?? []).includes('system:masters'),
        },
        relationships: { clusterName: name },
      });
    }

    return { name, cluster, out };
  });

  const out: ScannedResource[] = [];
  const sampleArn = perCluster.find((c) => c.cluster?.arn)?.cluster?.arn;
  for (const { name, cluster } of perCluster) {
    const arn = cluster?.arn ?? siblingArn(sampleArn, ':cluster/', name) ?? name;
    out.push({
      resourceTypeKey: 'eks_cluster', resourceId: arn, region: ctx.region, resourceName: name,
      state: cluster?.status,
      metadata: cluster ? { detailsCollected: true, ...clusterEvidence(cluster, versions, latestStandard) } : { detailsCollected: false },
      relationships: { roleArn: cluster?.roleArn, vpcId: cluster?.resourcesVpcConfig?.vpcId },
    });
  }
  // Clusters past the enumeration cap: recorded (not dropped) with a stable identity.
  for (const name of names.slice(MAX_CLUSTERS)) {
    out.push({
      resourceTypeKey: 'eks_cluster', resourceId: siblingArn(sampleArn, ':cluster/', name) ?? name, region: ctx.region, resourceName: name,
      metadata: { detailsCollected: false },
    });
  }
  for (const c of perCluster) out.push(...c.out);
  return out;
}
