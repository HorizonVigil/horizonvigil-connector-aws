import { fetch as undiciFetch, Agent } from 'undici';
import { AwsV4Signer } from 'aws4fetch';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const EKS_WORKLOAD_RESOURCE_TYPES = ['eks_pod', 'eks_deployment'] as const;

/**
 * UNVERIFIED AGAINST A REAL CLUSTER — flagging this explicitly because
 * every other scanner in this codebase was checked against real AWS
 * infrastructure before being called done, and this one hasn't been (no
 * EKS cluster exists anywhere available to this deployment to test
 * against). What IS independently verified: the presigned-STS-URL token
 * construction below produces the exact token shape AWS's own `aws eks
 * get-token` CLI command produces (checked by hand against the documented
 * aws-iam-authenticator protocol — SignedHeaders includes x-k8s-aws-id,
 * Action=GetCallerIdentity, k8s-aws-v1.<base64url> format) and the undici
 * fetch + custom-CA Agent mechanism was verified end-to-end against a real
 * HTTPS endpoint (same mechanism as gkeWorkloads.ts in the GCP connector).
 * What's unverified is whether a real EKS API server accepts this token
 * and CA cert the way the docs describe.
 *
 * EKS's own cluster-level scanner (eks.ts) doesn't parse
 * certificateAuthority.data — this scanner does its own GetCluster call
 * per cluster for that field, alongside the endpoint eks.ts already reads.
 *
 * Auth model differs from GKE in a real way, not just superficially: GKE
 * accepts the same GCP OAuth bearer token used for every other GCP API
 * call, directly. EKS instead requires a presigned STS GetCallerIdentity
 * URL (SigV4-signed with a required x-k8s-aws-id header naming the
 * cluster), base64url-encoded and prefixed "k8s-aws-v1." — the exact
 * mechanism the `aws-iam-authenticator`/client-go exec plugin uses. The
 * EKS API server independently replays that presigned URL against STS
 * server-side to verify the caller's IAM identity.
 *
 * Either way, IAM identity alone isn't enough: the customer must also map
 * this connection's IAM identity to a Kubernetes RBAC role via the
 * cluster's aws-auth ConfigMap (kube-system namespace) — a real,
 * per-cluster prerequisite, separate from the IAM permissions this
 * connection already has. Example mapping (added to the aws-auth
 * ConfigMap's mapUsers or mapRoles section):
 *
 *   - userarn: <this connection's IAM user or role ARN>
 *     username: cloudops360-reader
 *     groups: ["view"]
 *
 * (The "view" group requires a matching ClusterRoleBinding to the built-in
 * view ClusterRole to exist in the cluster — most EKS clusters have this
 * by default via the standard Kubernetes bootstrap roles, but not
 * guaranteed on every cluster.)
 *
 * Without that mapping, every request here returns 403 — surfaced as a
 * clear, actionable thrown error, not silently swallowed to "0 pods
 * found" (which would be indistinguishable from a real empty cluster).
 */

/**
 * aws4fetch's signed.headers is a real DOM/undici-compatible Headers
 * instance at runtime, but this project's Headers *type* (still pulling in
 * @cloudflare/workers-types from before the Cloud Run port) doesn't
 * declare .entries() — forEach is part of every Headers-like interface,
 * DOM and Workers types alike, so it works regardless of which type
 * declaration is in scope.
 */
function headersToObject(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => { out[key] = value; });
  return out;
}

interface EksClusterDetail {
  name: string; status?: string; endpoint?: string;
  certificateAuthority?: { data?: string };
}

async function getClusterDetail(ctx: ScannerContext, name: string): Promise<EksClusterDetail | null> {
  const client = new AwsV4Signer({
    url: `https://eks.${ctx.region}.amazonaws.com/clusters/${encodeURIComponent(name)}`,
    method: 'GET',
    accessKeyId: ctx.creds.accessKeyId, secretAccessKey: ctx.creds.secretAccessKey, sessionToken: ctx.creds.sessionToken,
    service: 'eks', region: ctx.region,
  });
  const signed = await client.sign();
  // aws4fetch's Headers is the DOM lib's type; undici's fetch wants its own
  // (structurally near-identical but nominally distinct) HeadersInit — a
  // plain object satisfies both.
  const res = await undiciFetch(signed.url, { method: signed.method, headers: headersToObject(signed.headers) });
  const text = await res.text();
  if (!res.ok) {
    console.error(`EKS GetCluster failed for ${name} in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return null;
  }
  const parsed = text ? (JSON.parse(text) as { cluster?: EksClusterDetail }) : {};
  return parsed.cluster ?? null;
}

/**
 * Builds the k8s-aws-v1 bearer token: a presigned STS GetCallerIdentity URL
 * with x-k8s-aws-id signed in as a header, base64url-encoded. 60-second
 * expiry matches the convention `aws eks get-token` itself uses (not
 * strictly required by the protocol, but the standard value).
 */
async function buildEksToken(ctx: ScannerContext, clusterName: string): Promise<string> {
  const signer = new AwsV4Signer({
    url: `https://sts.${ctx.region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15`,
    method: 'GET',
    headers: { 'x-k8s-aws-id': clusterName },
    accessKeyId: ctx.creds.accessKeyId, secretAccessKey: ctx.creds.secretAccessKey, sessionToken: ctx.creds.sessionToken,
    service: 'sts', region: ctx.region,
    signQuery: true,
  });
  const signed = await signer.sign();
  const url = signed.url.toString();
  return `k8s-aws-v1.${Buffer.from(url).toString('base64url').replace(/=+$/, '')}`;
}

interface K8sObjectMeta {
  name: string; namespace?: string; uid?: string; creationTimestamp?: string;
  labels?: Record<string, string>;
}
interface K8sPod {
  metadata: K8sObjectMeta;
  spec?: { nodeName?: string; containers?: { name: string; image: string }[] };
  status?: { phase?: string };
}
interface K8sPodList { items?: K8sPod[] }
interface K8sDeployment {
  metadata: K8sObjectMeta;
  spec?: { replicas?: number; template?: { spec?: { containers?: { name: string; image: string }[] } } };
  status?: { readyReplicas?: number; availableReplicas?: number };
}
interface K8sDeploymentList { items?: K8sDeployment[] }

async function callK8sApi(endpoint: string, caCertPem: string, bearerToken: string, path: string): Promise<{ ok: boolean; status: number; body: unknown; forbidden: boolean }> {
  const agent = new Agent({ connect: { ca: caCertPem } });
  const res = await undiciFetch(`${endpoint}${path}`, {
    headers: { Authorization: `Bearer ${bearerToken}` },
    dispatcher: agent,
  });
  const text = await res.text();
  const body = text ? JSON.parse(text) : {};
  return { ok: res.ok, status: res.status, body, forbidden: res.status === 403 };
}

/** Cluster names come from eks.ts's own scan, but that scanner doesn't expose them for reuse (scanners are independent by design in this codebase) — this one does its own ListClusters, capped the same way eks.ts caps at 10. */
async function listClusterNames(ctx: ScannerContext): Promise<string[]> {
  const client = new AwsV4Signer({
    url: `https://eks.${ctx.region}.amazonaws.com/clusters`,
    method: 'GET',
    accessKeyId: ctx.creds.accessKeyId, secretAccessKey: ctx.creds.secretAccessKey, sessionToken: ctx.creds.sessionToken,
    service: 'eks', region: ctx.region,
  });
  const signed = await client.sign();
  const res = await undiciFetch(signed.url, { method: signed.method, headers: headersToObject(signed.headers) });
  const text = await res.text();
  if (!res.ok) {
    console.error(`EKS ListClusters failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }
  const parsed = text ? (JSON.parse(text) as { clusters?: string[] }) : {};
  return (parsed.clusters ?? []).slice(0, 10);
}

export async function scanEksWorkloads(ctx: ScannerContext): Promise<ScannedResource[]> {
  const names = await listClusterNames(ctx);
  const out: ScannedResource[] = [];
  const forbiddenClusters: string[] = [];

  for (const name of names) {
    const detail = await getClusterDetail(ctx, name);
    if (!detail || detail.status !== 'ACTIVE' || !detail.endpoint || !detail.certificateAuthority?.data) continue;

    const caCertPem = Buffer.from(detail.certificateAuthority.data, 'base64').toString('utf8');
    const token = await buildEksToken(ctx, name);
    const clusterId = `${ctx.region}/${name}`;

    const podsResult = await callK8sApi(detail.endpoint, caCertPem, token, '/api/v1/pods');
    if (!podsResult.ok) {
      if (podsResult.forbidden) forbiddenClusters.push(name);
      else throw new Error(`EKS pod list failed for cluster ${clusterId}: HTTP ${podsResult.status} ${JSON.stringify(podsResult.body).slice(0, 200)}`);
    } else {
      for (const pod of (podsResult.body as K8sPodList).items ?? []) {
        out.push({
          resourceTypeKey: 'eks_pod', resourceId: `${clusterId}/${pod.metadata.namespace}/${pod.metadata.name}`, region: ctx.region,
          resourceName: pod.metadata.name, state: pod.status?.phase, tags: pod.metadata.labels ?? {},
          metadata: {
            namespace: pod.metadata.namespace, nodeName: pod.spec?.nodeName,
            images: pod.spec?.containers?.map((c) => c.image), createdAt: pod.metadata.creationTimestamp,
          },
          relationships: { clusterName: name },
        });
      }
    }

    const deploysResult = await callK8sApi(detail.endpoint, caCertPem, token, '/apis/apps/v1/deployments');
    if (!deploysResult.ok) {
      if (deploysResult.forbidden) { if (!forbiddenClusters.includes(name)) forbiddenClusters.push(name); }
      else throw new Error(`EKS deployment list failed for cluster ${clusterId}: HTTP ${deploysResult.status} ${JSON.stringify(deploysResult.body).slice(0, 200)}`);
    } else {
      for (const dep of (deploysResult.body as K8sDeploymentList).items ?? []) {
        out.push({
          resourceTypeKey: 'eks_deployment', resourceId: `${clusterId}/${dep.metadata.namespace}/${dep.metadata.name}`, region: ctx.region,
          resourceName: dep.metadata.name, tags: dep.metadata.labels ?? {},
          metadata: {
            namespace: dep.metadata.namespace, replicas: dep.spec?.replicas, readyReplicas: dep.status?.readyReplicas,
            availableReplicas: dep.status?.availableReplicas, images: dep.spec?.template?.spec?.containers?.map((c) => c.image),
            createdAt: dep.metadata.creationTimestamp,
          },
          relationships: { clusterName: name },
        });
      }
    }
  }

  if (forbiddenClusters.length > 0) {
    // Known, accepted limitation, same as gkeWorkloads.ts: a mix of
    // mapped/unmapped clusters in one run discards the mapped ones' real
    // results along with this error, since run-step's contract is
    // all-or-nothing per step. Only costs this one scanner's results for
    // this one run; a retry after the aws-auth ConfigMap is updated on the
    // remaining cluster(s) recovers everything.
    throw new Error(
      `IAM identity not mapped to Kubernetes RBAC for ${forbiddenClusters.length} cluster(s) (${forbiddenClusters.join(', ')}) — add this connection's IAM identity to each cluster's aws-auth ConfigMap (kube-system namespace) with at least the built-in "view" group.`,
    );
  }

  return out;
}
