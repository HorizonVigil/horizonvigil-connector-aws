import { createAwsClient } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const EKS_RESOURCE_TYPES = ['eks_cluster', 'eks_nodegroup', 'eks_addon', 'eks_fargate_profile', 'eks_identity_provider_config'] as const;

interface EksClusterDetail {
  name: string; arn?: string; status?: string; version?: string; endpoint?: string;
  createdAt?: string; roleArn?: string; platformVersion?: string;
  resourcesVpcConfig?: { vpcId?: string };
}
interface EksNodegroupDetail {
  nodegroupName: string; status?: string; instanceTypes?: string[]; amiType?: string; createdAt?: string;
  scalingConfig?: { minSize?: number; maxSize?: number; desiredSize?: number };
}

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
      out.push({
        resourceTypeKey: 'eks_cluster', resourceId: cluster.arn ?? name, region: ctx.region, resourceName: name,
        state: cluster.status,
        metadata: { version: cluster.version, endpoint: cluster.endpoint, createdAt: cluster.createdAt, platformVersion: cluster.platformVersion },
        relationships: { roleArn: cluster.roleArn, vpcId: cluster.resourcesVpcConfig?.vpcId },
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
        },
        relationships: { clusterName: name },
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
  }

  return out;
}
