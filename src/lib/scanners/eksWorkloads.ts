import { fetch as undiciFetch, Agent } from 'undici';
import { AwsV4Signer } from 'aws4fetch';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const EKS_WORKLOAD_RESOURCE_TYPES = ['eks_pod', 'eks_deployment', 'eks_namespace', 'eks_node', 'eks_auth_mapping'] as const;

/**
 * VERIFIED against a real EKS cluster (2026-08-06) — deployed a real
 * cluster + managed node group, deployed a test Deployment, and confirmed
 * this scanner's compiled output correctly lists real pods/deployments with
 * accurate namespace/state/cluster metadata. That test also caught and
 * fixed a real bug: the presigned STS URL needs an explicit X-Amz-Expires
 * (see buildEksToken's doc comment) — without it every request failed with
 * 401 regardless of how correctly IAM/RBAC were configured on the cluster.
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
 * Either way, IAM identity alone isn't enough: the customer must also grant
 * this connection's IAM identity cluster access — either an EKS access
 * entry (API/API_AND_CONFIG_MAP auth mode clusters, the modern path,
 * confirmed working in the real test above via the AmazonEKSClusterAdminPolicy
 * managed access policy) or a mapping in the cluster's aws-auth ConfigMap
 * (CONFIG_MAP-only clusters, the legacy path — kube-system namespace):
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
 * Without that grant, requests here return 403 (identity authenticated,
 * RBAC denies it) on API/API_AND_CONFIG_MAP clusters, or 401 (identity
 * never recognized at all — confirmed empirically) on CONFIG_MAP-only
 * clusters with no matching ConfigMap entry. Either is surfaced as a clear,
 * actionable thrown error, not silently swallowed to "0 pods found" (which
 * would be indistinguishable from a real empty cluster).
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
 * with x-k8s-aws-id signed in as a header, base64url-encoded.
 *
 * X-Amz-Expires=60 in the URL is NOT optional — confirmed against a real
 * EKS cluster (2026-08-06): omitting it produces a validly-signed presigned
 * URL that EKS's server-side token reviewer nonetheless rejects outright
 * with 401 Unauthorized (a pure authentication failure, not an RBAC/403 —
 * the cluster never even recognized the caller's identity), regardless of
 * how correctly IAM/access-entries/aws-auth are configured on the
 * cluster side. aws4fetch's AwsV4Signer does not add this automatically
 * even with signQuery:true — it only signs whatever's already in the URL's
 * query string, so it must be appended before constructing the signer.
 */
async function buildEksToken(ctx: ScannerContext, clusterName: string): Promise<string> {
  const signer = new AwsV4Signer({
    url: `https://sts.${ctx.region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Expires=60`,
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

// Container-level state as reported by kubelet — this is the actual source
// of "why did it fail" (CrashLoopBackOff/OOMKilled/ImagePullBackOff all
// surface here, on the *container*, not the pod-level phase/reason, which
// is why the old scanner's pod.status?.phase alone couldn't answer it).
interface K8sContainerState {
  running?: { startedAt?: string };
  waiting?: { reason?: string; message?: string };
  terminated?: { reason?: string; exitCode?: number; signal?: number; message?: string; startedAt?: string; finishedAt?: string };
}
interface K8sContainerStatus {
  name: string; image: string; ready: boolean; started?: boolean; restartCount: number;
  state?: K8sContainerState; lastState?: K8sContainerState;
}
interface K8sPod {
  metadata: K8sObjectMeta;
  spec?: { nodeName?: string; containers?: { name: string; image: string }[]; nodeSelector?: Record<string, string>; tolerations?: { key?: string; operator?: string; value?: string; effect?: string }[] };
  status?: {
    phase?: string; reason?: string; message?: string; podIP?: string; hostIP?: string; qosClass?: string;
    containerStatuses?: K8sContainerStatus[];
    conditions?: { type: string; status: string; reason?: string; message?: string }[];
  };
}
interface K8sPodList { items?: K8sPod[] }

interface K8sProbe {
  httpGet?: { path?: string; port?: number | string; scheme?: string };
  tcpSocket?: { port?: number | string };
  exec?: { command?: string[] };
  initialDelaySeconds?: number; periodSeconds?: number; timeoutSeconds?: number; failureThreshold?: number; successThreshold?: number;
}
interface K8sEnvVar {
  name: string; value?: string;
  valueFrom?: { secretKeyRef?: { name: string; key: string }; configMapKeyRef?: { name: string; key: string }; fieldRef?: { fieldPath: string } };
}
interface K8sContainerSpec {
  name: string; image: string; imagePullPolicy?: string;
  command?: string[]; args?: string[];
  ports?: { containerPort: number; protocol?: string; name?: string }[];
  env?: K8sEnvVar[];
  resources?: { requests?: { cpu?: string; memory?: string }; limits?: { cpu?: string; memory?: string } };
  volumeMounts?: { name: string; mountPath: string; readOnly?: boolean }[];
  readinessProbe?: K8sProbe; livenessProbe?: K8sProbe; startupProbe?: K8sProbe;
}
interface K8sDeployment {
  metadata: K8sObjectMeta;
  spec?: {
    replicas?: number;
    strategy?: { type?: string; rollingUpdate?: { maxSurge?: string | number; maxUnavailable?: string | number } };
    revisionHistoryLimit?: number;
    template?: { spec?: { containers?: K8sContainerSpec[]; initContainers?: K8sContainerSpec[]; serviceAccountName?: string; nodeSelector?: Record<string, string> } };
  };
  status?: { readyReplicas?: number; availableReplicas?: number; updatedReplicas?: number; unavailableReplicas?: number; conditions?: { type: string; status: string; reason?: string; message?: string }[] };
}
interface K8sDeploymentList { items?: K8sDeployment[] }
interface K8sNamespace {
  metadata: K8sObjectMeta;
  status?: { phase?: string };
}
interface K8sNamespaceList { items?: K8sNamespace[] }

interface K8sResourceQuota {
  metadata: { name: string };
  spec?: { hard?: Record<string, string> };
  status?: { hard?: Record<string, string>; used?: Record<string, string> };
}
interface K8sResourceQuotaList { items?: K8sResourceQuota[] }

interface K8sNodeObjectMeta {
  name: string; uid?: string; creationTimestamp?: string;
  labels?: Record<string, string>; annotations?: Record<string, string>;
}
interface K8sNode {
  metadata: K8sNodeObjectMeta;
  spec?: { taints?: { key: string; value?: string; effect: string }[]; unschedulable?: boolean };
  status?: {
    addresses?: { type: string; address: string }[];
    nodeInfo?: {
      kernelVersion?: string; osImage?: string; containerRuntimeVersion?: string;
      kubeletVersion?: string; architecture?: string; operatingSystem?: string;
    };
    capacity?: Record<string, string>;
    allocatable?: Record<string, string>;
    conditions?: { type: string; status: string; reason?: string; message?: string }[];
  };
}
interface K8sNodeList { items?: K8sNode[] }

/**
 * Real Kubernetes Node objects (kubelet/kernel version, IPs, capacity,
 * Ready condition) -- distinct from eks.ts's eks_nodegroup, which is AWS's
 * own management abstraction over a group of nodes and exposes none of
 * this. A nodegroup can span nodes with different actual specs (e.g. mid
 * scale-out), so this is real per-node data a nodegroup summary can't give.
 * Standard AWS cloud-provider labels (topology.kubernetes.io/zone,
 * node.kubernetes.io/instance-type, eks.amazonaws.com/capacityType) are
 * read straight off metadata.labels, not re-derived -- they're already
 * exactly what the AWS cloud provider integration sets on every node.
 */
function findNodeAddress(node: K8sNode, type: string): string | undefined {
  return node.status?.addresses?.find((a) => a.type === type)?.address;
}
function isNodeReady(node: K8sNode): boolean {
  return node.status?.conditions?.find((c) => c.type === 'Ready')?.status === 'True';
}

interface AuthMapEntry { arn: string; username?: string; groups: string[] }

/**
 * Minimal parser for aws-auth's mapRoles/mapUsers YAML strings -- not a
 * general YAML parser (this codebase avoids heavy parsing dependencies the
 * same way xmlList.ts hand-rolls XML extraction instead of pulling in a DOM
 * parser), scoped exactly to the fixed, well-known block-list shape AWS's
 * own aws-auth documentation always produces:
 *   - rolearn: arn:...
 *     username: ...
 *     groups:
 *       - system:masters
 * Relies on indentation (0 = new entry, >0 = a field of the current entry,
 * a further-indented "- " = a groups member) rather than a real YAML
 * grammar. A hand-edited ConfigMap with flow-style groups (`groups:
 * [a, b]`) or unusual indentation won't parse correctly -- rare in
 * practice (every AWS/eksctl-generated aws-auth uses exactly this shape),
 * and a partial/empty result here is far less costly than it would be for
 * pods/deployments, since this is additive IAM-mapping context, not core
 * workload discovery.
 */
function parseAuthMapYaml(yaml: string): AuthMapEntry[] {
  const entries: AuthMapEntry[] = [];
  let current: AuthMapEntry | null = null;
  let inGroups = false;
  const stripQuotes = (s: string) => s.replace(/^['"]|['"]$/g, '');
  const applyField = (entry: AuthMapEntry, fieldLine: string) => {
    const colonIdx = fieldLine.indexOf(':');
    if (colonIdx === -1) return;
    const key = fieldLine.slice(0, colonIdx).trim();
    const value = stripQuotes(fieldLine.slice(colonIdx + 1).trim());
    if (key === 'rolearn' || key === 'userarn') entry.arn = value;
    else if (key === 'username') entry.username = value;
  };

  for (const rawLine of yaml.split('\n')) {
    const line = rawLine.replace(/\r$/, '');
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const leadingSpaces = line.length - line.trimStart().length;
    const content = line.trim();

    if (leadingSpaces === 0 && content.startsWith('- ')) {
      if (current) entries.push(current);
      current = { arn: '', groups: [] };
      inGroups = false;
      applyField(current, content.slice(2));
    } else if (current && content.startsWith('- ')) {
      if (inGroups) current.groups.push(stripQuotes(content.slice(2).trim()));
    } else if (current) {
      inGroups = content.startsWith('groups:');
      if (!inGroups) applyField(current, content);
    }
  }
  if (current) entries.push(current);
  return entries.filter(e => e.arn);
}

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
        const statuses = pod.status?.containerStatuses ?? [];
        out.push({
          resourceTypeKey: 'eks_pod', resourceId: `${clusterId}/${pod.metadata.namespace}/${pod.metadata.name}`, region: ctx.region,
          resourceName: pod.metadata.name, state: pod.status?.phase, tags: pod.metadata.labels ?? {},
          metadata: {
            namespace: pod.metadata.namespace, nodeName: pod.spec?.nodeName,
            images: pod.spec?.containers?.map((c) => c.image), createdAt: pod.metadata.creationTimestamp,
            podIP: pod.status?.podIP, hostIP: pod.status?.hostIP, qosClass: pod.status?.qosClass,
            podReason: pod.status?.reason, podMessage: pod.status?.message,
            restartCount: statuses.reduce((sum, s) => sum + (s.restartCount ?? 0), 0),
            containerStatuses: statuses, conditions: pod.status?.conditions,
            tolerations: pod.spec?.tolerations, nodeSelector: pod.spec?.nodeSelector,
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
        const containers = dep.spec?.template?.spec?.containers ?? [];
        out.push({
          resourceTypeKey: 'eks_deployment', resourceId: `${clusterId}/${dep.metadata.namespace}/${dep.metadata.name}`, region: ctx.region,
          resourceName: dep.metadata.name, tags: dep.metadata.labels ?? {},
          metadata: {
            namespace: dep.metadata.namespace, replicas: dep.spec?.replicas, readyReplicas: dep.status?.readyReplicas,
            availableReplicas: dep.status?.availableReplicas, updatedReplicas: dep.status?.updatedReplicas,
            unavailableReplicas: dep.status?.unavailableReplicas,
            images: containers.map((c) => c.image), createdAt: dep.metadata.creationTimestamp,
            // Full pod-template container spec — everything from the deployment
            // manifest's spec.template.spec.containers, at the same visibility a
            // "view"-RBAC kubectl user already has (env values that come from a
            // Secret are reported as a reference only, e.g. "from secret db-creds.password"
            // — we never call the Secrets API to resolve the actual value).
            containers, initContainers: dep.spec?.template?.spec?.initContainers,
            serviceAccountName: dep.spec?.template?.spec?.serviceAccountName,
            nodeSelector: dep.spec?.template?.spec?.nodeSelector,
            strategy: dep.spec?.strategy, revisionHistoryLimit: dep.spec?.revisionHistoryLimit,
            conditions: dep.status?.conditions,
          },
          relationships: { clusterName: name },
        });
      }
    }

    // Cluster-scoped, not namespace-scoped (a namespace isn't "in" a
    // namespace) — same endpoint pattern and token as pods/deployments,
    // just a different path. No forbidden-tracking special case needed:
    // any identity that can list pods/deployments in a namespace can list
    // namespaces themselves (namespace listing needs less RBAC, not more),
    // so a 403 here without one on pods/deployments would be a genuinely
    // unusual RBAC setup worth surfacing as its own real error rather than
    // silently folding into forbiddenClusters.
    const namespacesResult = await callK8sApi(detail.endpoint, caCertPem, token, '/api/v1/namespaces');
    if (!namespacesResult.ok) {
      if (namespacesResult.forbidden) { if (!forbiddenClusters.includes(name)) forbiddenClusters.push(name); }
      else throw new Error(`EKS namespace list failed for cluster ${clusterId}: HTTP ${namespacesResult.status} ${JSON.stringify(namespacesResult.body).slice(0, 200)}`);
    } else {
      const namespaces = ((namespacesResult.body as K8sNamespaceList).items ?? []).slice(0, 20);
      // ResourceQuota is a standard read-only object (unlike Secrets, it's
      // included in Kubernetes' own built-in "view" ClusterRole), so this
      // doesn't need any broader RBAC grant than everything else this
      // scanner already reads. One extra call per namespace -- capped to
      // the first 20 above to bound the fan-out, same generous-but-capped
      // shape as every other per-item loop in this file.
      const endpoint = detail.endpoint;
      const quotaResults = await Promise.all(namespaces.map(ns => callK8sApi(endpoint, caCertPem, token, `/api/v1/namespaces/${encodeURIComponent(ns.metadata.name)}/resourcequotas`)));
      for (let i = 0; i < namespaces.length; i++) {
        const ns = namespaces[i];
        const quotaRes = quotaResults[i];
        const quotas = quotaRes.ok ? ((quotaRes.body as K8sResourceQuotaList).items ?? []) : [];
        out.push({
          resourceTypeKey: 'eks_namespace', resourceId: `${clusterId}/${ns.metadata.name}`, region: ctx.region,
          resourceName: ns.metadata.name, state: ns.status?.phase, tags: ns.metadata.labels ?? {},
          metadata: {
            createdAt: ns.metadata.creationTimestamp,
            resourceQuotas: quotas.map(q => ({ name: q.metadata.name, hard: q.status?.hard ?? q.spec?.hard, used: q.status?.used })),
          },
          relationships: { clusterName: name },
        });
      }
    }

    // Cluster-scoped, like namespaces. Real per-node data (hostname, IPs,
    // kernel/kubelet/runtime versions, capacity/allocatable, Ready
    // condition) -- everything eks_nodegroup (eks.ts) can't give since it's
    // AWS's management abstraction, not the Kubernetes object itself.
    const nodesResult = await callK8sApi(detail.endpoint, caCertPem, token, '/api/v1/nodes');
    if (!nodesResult.ok) {
      if (nodesResult.forbidden) { if (!forbiddenClusters.includes(name)) forbiddenClusters.push(name); }
      else throw new Error(`EKS node list failed for cluster ${clusterId}: HTTP ${nodesResult.status} ${JSON.stringify(nodesResult.body).slice(0, 200)}`);
    } else {
      for (const node of (nodesResult.body as K8sNodeList).items ?? []) {
        out.push({
          resourceTypeKey: 'eks_node', resourceId: `${clusterId}/${node.metadata.name}`, region: ctx.region,
          resourceName: node.metadata.name, state: isNodeReady(node) ? 'Ready' : 'NotReady', tags: node.metadata.labels ?? {},
          metadata: {
            internalIp: findNodeAddress(node, 'InternalIP'), externalIp: findNodeAddress(node, 'ExternalIP'),
            hostname: findNodeAddress(node, 'Hostname'),
            instanceType: node.metadata.labels?.['node.kubernetes.io/instance-type'],
            zone: node.metadata.labels?.['topology.kubernetes.io/zone'],
            capacityType: node.metadata.labels?.['eks.amazonaws.com/capacityType'],
            kernelVersion: node.status?.nodeInfo?.kernelVersion, osImage: node.status?.nodeInfo?.osImage,
            containerRuntimeVersion: node.status?.nodeInfo?.containerRuntimeVersion,
            kubeletVersion: node.status?.nodeInfo?.kubeletVersion, architecture: node.status?.nodeInfo?.architecture,
            operatingSystem: node.status?.nodeInfo?.operatingSystem,
            capacityCpu: node.status?.capacity?.cpu, capacityMemory: node.status?.capacity?.memory, capacityPods: node.status?.capacity?.pods,
            allocatableCpu: node.status?.allocatable?.cpu, allocatableMemory: node.status?.allocatable?.memory, allocatablePods: node.status?.allocatable?.pods,
            annotations: node.metadata.annotations, createdAt: node.metadata.creationTimestamp,
            taints: node.spec?.taints, unschedulable: node.spec?.unschedulable, conditions: node.status?.conditions,
          },
          relationships: { clusterName: name },
        });
      }
    }

    // The legacy (pre-2023) auth mechanism, still the only one on
    // CONFIG_MAP-only clusters and often present alongside access entries
    // (eks.ts) on API_AND_CONFIG_MAP ones. Best-effort and additive, not
    // folded into forbiddenClusters/thrown like pods/deployments/
    // namespaces/nodes above: a cluster on pure "API" auth mode
    // legitimately has no aws-auth ConfigMap at all (404, not an error),
    // and losing this one piece of IAM-mapping context shouldn't cost the
    // real workload data already collected for this cluster this run.
    const authMapResult = await callK8sApi(detail.endpoint, caCertPem, token, '/api/v1/namespaces/kube-system/configmaps/aws-auth');
    if (authMapResult.ok) {
      const cm = authMapResult.body as { data?: { mapRoles?: string; mapUsers?: string } };
      for (const entry of parseAuthMapYaml(cm.data?.mapRoles ?? '')) {
        out.push({
          resourceTypeKey: 'eks_auth_mapping', resourceId: `${clusterId}/role/${entry.arn}`, region: ctx.region, resourceName: entry.arn.split('/').pop(),
          metadata: { kind: 'role', arn: entry.arn, username: entry.username, groups: entry.groups },
          relationships: { clusterName: name },
        });
      }
      for (const entry of parseAuthMapYaml(cm.data?.mapUsers ?? '')) {
        out.push({
          resourceTypeKey: 'eks_auth_mapping', resourceId: `${clusterId}/user/${entry.arn}`, region: ctx.region, resourceName: entry.arn.split('/').pop(),
          metadata: { kind: 'user', arn: entry.arn, username: entry.username, groups: entry.groups },
          relationships: { clusterName: name },
        });
      }
    } else if (authMapResult.status !== 404 && !authMapResult.forbidden) {
      console.error(`aws-auth ConfigMap fetch failed for cluster ${clusterId} (continuing without it): HTTP ${authMapResult.status}`);
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
