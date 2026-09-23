import { fetch as undiciFetch, Agent } from 'undici';
import { AwsV4Signer } from 'aws4fetch';
import type { ScannedResource, ScannerContext } from './types';
import { parseCpuMillicores, parseMemoryBytes } from '../k8sQuantity';
import { errorMessage, reportListingFailure } from './scannerSupport';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const EKS_WORKLOAD_RESOURCE_TYPES = ['eks_pod', 'eks_deployment', 'eks_namespace', 'eks_node', 'eks_auth_mapping'] as const;

/** Clusters whose workloads are read per region-step (each costs several K8s list calls). */
const MAX_CLUSTERS = 10;
/** Kubernetes list page size and page cap: 500 x 20 = 10,000 objects per kind per cluster. */
const K8S_PAGE_LIMIT = 500;
const K8S_MAX_PAGES = 20;
/** The presigned token carries X-Amz-Expires=60; mint a fresh one well before that. */
const TOKEN_REFRESH_MS = 45_000;
const CONNECT_TIMEOUT_MS = 10_000;
const HEADERS_TIMEOUT_MS = 30_000;
const BODY_TIMEOUT_MS = 60_000;

/**
 * VERIFIED against a real EKS cluster (2026-08-06): deployed a real cluster
 * + managed node group, deployed a test Deployment, and confirmed this
 * scanner's compiled output correctly lists real pods/deployments with
 * accurate namespace/state/cluster metadata. That test also caught and fixed
 * a real bug: the presigned STS URL needs an explicit X-Amz-Expires (see
 * buildEksToken's doc comment).
 *
 * Auth model: EKS requires a presigned STS GetCallerIdentity URL
 * (SigV4-signed with a required x-k8s-aws-id header naming the cluster),
 * base64url-encoded and prefixed "k8s-aws-v1.", the exact mechanism the
 * aws-iam-authenticator / client-go exec plugin uses.
 *
 * IAM identity alone isn't enough: the customer must also grant this
 * connection's IAM identity cluster access, either an EKS access entry
 * (API / API_AND_CONFIG_MAP clusters, e.g. with the AmazonEKSViewPolicy or
 * AmazonEKSClusterAdminPolicy access policy) or a mapping in the aws-auth
 * ConfigMap (CONFIG_MAP-only clusters, kube-system namespace):
 *
 *   - userarn: <this connection's IAM user or role ARN>
 *     username: horizonvigil-reader
 *     groups: ["view"]
 *
 * Without that grant, requests return 403 (RBAC denies) or 401 (identity
 * never recognized, CONFIG_MAP-only clusters). Both are reported as
 * PERMISSION_DENIED for that cluster; when EVERY attempted cluster is
 * denied, the scan throws the actionable message below.
 *
 * What changed in this revision, and why:
 *  - Every Kubernetes list paginates (limit + continue), so a large cluster
 *    is read in bounded pages; a page cap is reported, not silent.
 *  - One undici Agent per cluster (with connect/header/body timeouts),
 *    closed afterwards. The previous version created a new, never-closed
 *    Agent for every single request, leaking sockets, and had no timeouts.
 *  - The bearer token is re-minted every 45 s: it carries X-Amz-Expires=60,
 *    so on a big cluster later calls were rejected with 401.
 *  - Response bodies are parsed defensively; a network error or non-JSON
 *    body is a reported failure, not an exception that loses every cluster.
 *  - A failure on one cluster is reported (so finalize does not tombstone
 *    that cluster's pods) and the scan continues with the next cluster.
 *    Previously any non-403 error threw and discarded every cluster's data,
 *    and any 403 did the same.
 *  - All namespaces are emitted (previously only the first 20, so namespace
 *    21+ looked deleted every run); quotas come from one cluster-wide list.
 *  - More than 10 clusters, or a cluster that is not reachable (UPDATING is
 *    treated as reachable), is reported instead of silently skipped.
 *  - SECRETS: deployment container specs no longer store literal env var
 *    values or secret-looking command-line argument values. Names, and
 *    valueFrom references (secret/configMap names), are kept.
 *  - Evidence: a podSecurity summary (privileged, host namespaces, root,
 *    privilege escalation, hostPath, added capabilities, service account
 *    token automount) on pods and deployments, plus literal env vars whose
 *    names look like credentials.
 */

/**
 * aws4fetch's signed.headers is a real Headers instance at runtime, but this
 * project's Headers *type* doesn't declare .entries(); forEach is part of
 * every Headers-like interface, so it works regardless of declarations.
 */
function headersToObject(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => { out[key] = value; });
  return out;
}

function safeJson(text: string): unknown {
  if (!text) return {};
  try { return JSON.parse(text); } catch { return undefined; }
}

interface EksClusterDetail {
  name: string; status?: string; endpoint?: string;
  certificateAuthority?: { data?: string };
}

/** Signed GET against the EKS control-plane API (not the Kubernetes API). */
async function eksGet(ctx: ScannerContext, path: string): Promise<{ ok: boolean; status: number; body: unknown; error?: string }> {
  try {
    const signer = new AwsV4Signer({
      url: `https://eks.${ctx.region}.amazonaws.com${path}`,
      method: 'GET',
      accessKeyId: ctx.creds.accessKeyId, secretAccessKey: ctx.creds.secretAccessKey, sessionToken: ctx.creds.sessionToken,
      service: 'eks', region: ctx.region,
    });
    const signed = await signer.sign();
    // A plain object satisfies both aws4fetch's DOM Headers and undici's HeadersInit.
    const res = await undiciFetch(signed.url, { method: signed.method, headers: headersToObject(signed.headers), signal: AbortSignal.timeout(HEADERS_TIMEOUT_MS) });
    const text = await res.text();
    const body = safeJson(text);
    if (body === undefined) return { ok: false, status: res.status, body: null, error: `non-JSON body: ${text.slice(0, 200)}` };
    return { ok: res.ok, status: res.status, body, error: res.ok ? undefined : text.slice(0, 200) };
  } catch (err) {
    return { ok: false, status: 0, body: null, error: errorMessage(err) };
  }
}

async function getClusterDetail(ctx: ScannerContext, name: string): Promise<EksClusterDetail | null> {
  const r = await eksGet(ctx, `/clusters/${encodeURIComponent(name)}`);
  if (!r.ok) {
    console.error(`EKS GetCluster failed for ${name} in ${ctx.region} (continuing without it): HTTP ${r.status} ${r.error ?? ''}`);
    return null;
  }
  return ((r.body as { cluster?: EksClusterDetail } | null)?.cluster) ?? null;
}

/**
 * Builds the k8s-aws-v1 bearer token: a presigned STS GetCallerIdentity URL
 * with x-k8s-aws-id signed in as a header, base64url-encoded.
 *
 * X-Amz-Expires=60 in the URL is NOT optional. Confirmed against a real EKS
 * cluster (2026-08-06): omitting it produces a validly-signed presigned URL
 * that EKS's token reviewer rejects with 401. aws4fetch's AwsV4Signer does
 * not add it even with signQuery:true (it only signs what is already in the
 * query string), so it must be in the URL before signing.
 */
export async function buildEksToken(ctx: ScannerContext, clusterName: string): Promise<string> {
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

/** A bearer token that is re-minted before its 60 s presign window closes. */
export function tokenSource(mint: () => Promise<string>, now: () => number = Date.now, refreshMs = TOKEN_REFRESH_MS) {
  let token: string | null = null;
  let mintedAt = 0;
  return async (): Promise<string> => {
    if (token === null || now() - mintedAt >= refreshMs) {
      token = await mint();
      mintedAt = now();
    }
    return token;
  };
}

interface OwnerReference { kind: string; name: string; controller?: boolean }
interface K8sObjectMeta {
  name: string; namespace?: string; uid?: string; creationTimestamp?: string;
  labels?: Record<string, string>;
  // Lets a pod/deployment be rolled up to its owning ReplicaSet/Deployment/
  // DaemonSet/StatefulSet exactly (used by k8sCostAllocation.ts).
  ownerReferences?: OwnerReference[];
}

// Container-level state as reported by kubelet: the actual source of "why did
// it fail" (CrashLoopBackOff/OOMKilled/ImagePullBackOff surface here).
interface K8sContainerState {
  running?: { startedAt?: string };
  waiting?: { reason?: string; message?: string };
  terminated?: { reason?: string; exitCode?: number; signal?: number; message?: string; startedAt?: string; finishedAt?: string };
}
interface K8sContainerStatus {
  name: string; image: string; ready: boolean; started?: boolean; restartCount: number;
  state?: K8sContainerState; lastState?: K8sContainerState;
}
interface K8sSecurityContext {
  privileged?: boolean; runAsUser?: number; runAsNonRoot?: boolean; allowPrivilegeEscalation?: boolean;
  readOnlyRootFilesystem?: boolean; capabilities?: { add?: string[]; drop?: string[] };
}
interface K8sProbe {
  httpGet?: { path?: string; port?: number | string; scheme?: string };
  tcpSocket?: { port?: number | string };
  exec?: { command?: string[] };
  initialDelaySeconds?: number; periodSeconds?: number; timeoutSeconds?: number; failureThreshold?: number; successThreshold?: number;
}
interface K8sEnvVar {
  name: string; value?: string;
  valueFrom?: { secretKeyRef?: { name: string; key: string }; configMapKeyRef?: { name: string; key: string }; fieldRef?: { fieldPath: string }; resourceFieldRef?: unknown };
}
type K8sResources = { requests?: { cpu?: string; memory?: string }; limits?: { cpu?: string; memory?: string } };
interface K8sContainerSpec {
  name: string; image: string; imagePullPolicy?: string;
  command?: string[]; args?: string[];
  ports?: { containerPort: number; protocol?: string; name?: string; hostPort?: number }[];
  env?: K8sEnvVar[];
  envFrom?: { secretRef?: { name?: string }; configMapRef?: { name?: string }; prefix?: string }[];
  resources?: K8sResources;
  volumeMounts?: { name: string; mountPath: string; readOnly?: boolean }[];
  readinessProbe?: K8sProbe; livenessProbe?: K8sProbe; startupProbe?: K8sProbe;
  securityContext?: K8sSecurityContext;
}
export interface K8sPodSpec {
  nodeName?: string;
  containers?: K8sContainerSpec[]; initContainers?: K8sContainerSpec[];
  nodeSelector?: Record<string, string>; tolerations?: { key?: string; operator?: string; value?: string; effect?: string }[];
  serviceAccountName?: string; automountServiceAccountToken?: boolean;
  hostNetwork?: boolean; hostPID?: boolean; hostIPC?: boolean;
  securityContext?: { runAsUser?: number; runAsNonRoot?: boolean };
  volumes?: { name: string; hostPath?: { path?: string } }[];
}
interface K8sPod {
  metadata: K8sObjectMeta;
  spec?: K8sPodSpec;
  status?: {
    phase?: string; reason?: string; message?: string; podIP?: string; hostIP?: string; qosClass?: string;
    containerStatuses?: K8sContainerStatus[];
    conditions?: { type: string; status: string; reason?: string; message?: string }[];
  };
}
interface K8sDeployment {
  metadata: K8sObjectMeta;
  spec?: {
    replicas?: number;
    strategy?: { type?: string; rollingUpdate?: { maxSurge?: string | number; maxUnavailable?: string | number } };
    revisionHistoryLimit?: number;
    template?: { spec?: K8sPodSpec };
  };
  status?: { readyReplicas?: number; availableReplicas?: number; updatedReplicas?: number; unavailableReplicas?: number; conditions?: { type: string; status: string; reason?: string; message?: string }[] };
}
// A Pod's ownerReferences points to its ReplicaSet; the ReplicaSet's points to
// the Deployment. Fetched transiently (never persisted) to resolve that 2-hop
// chain to a stable workload name for k8sCostAllocation.ts.
interface K8sReplicaSet { metadata: K8sObjectMeta }
interface K8sNamespace { metadata: K8sObjectMeta; status?: { phase?: string } }
interface K8sResourceQuota {
  metadata: { name: string; namespace?: string };
  spec?: { hard?: Record<string, string> };
  status?: { hard?: Record<string, string>; used?: Record<string, string> };
}
interface K8sNodeObjectMeta {
  name: string; uid?: string; creationTimestamp?: string;
  labels?: Record<string, string>; annotations?: Record<string, string>;
}
interface K8sNode {
  metadata: K8sNodeObjectMeta;
  // providerID ("aws:///<az>/<instance-id>") is the exact join key to this
  // node's ec2_instance row (k8sCostAllocation.ts).
  spec?: { taints?: { key: string; value?: string; effect: string }[]; unschedulable?: boolean; providerID?: string };
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

function findNodeAddress(node: K8sNode, type: string): string | undefined {
  return node.status?.addresses?.find((a) => a.type === type)?.address;
}

// "aws:///<availability-zone>/<instance-id>" for the AWS cloud provider.
// Fargate nodes have no backing EC2 instance and return undefined.
const AWS_PROVIDER_ID_PATTERN = /^aws:\/\/\/[^/]+\/(i-[0-9a-f]+)$/;
export function extractEc2InstanceId(providerID: string | undefined): string | undefined {
  return providerID ? AWS_PROVIDER_ID_PATTERN.exec(providerID)?.[1] : undefined;
}
function isNodeReady(node: K8sNode): boolean {
  return node.status?.conditions?.find((c) => c.type === 'Ready')?.status === 'True';
}

/**
 * Sums each container's declared CPU/memory *request* across a pod's
 * containers (k8sCostAllocation.ts). A container with no request contributes
 * 0 (real K8s semantics); hasAnyRequest marks pods with no request at all.
 */
function sumPodResourceRequests(containers: { resources?: K8sResources }[]): { cpuMillicores: number; memoryBytes: number; hasAnyRequest: boolean } {
  let cpuMillicores = 0;
  let memoryBytes = 0;
  let hasAnyRequest = false;
  for (const c of containers) {
    const cpu = parseCpuMillicores(c.resources?.requests?.cpu);
    const mem = parseMemoryBytes(c.resources?.requests?.memory);
    if (cpu != null) { cpuMillicores += cpu; hasAnyRequest = true; }
    if (mem != null) { memoryBytes += mem; hasAnyRequest = true; }
  }
  return { cpuMillicores, memoryBytes, hasAnyRequest };
}

/** The controlling owner (controller: true), falling back to the first reference. */
function controllerOf(meta: K8sObjectMeta): OwnerReference | undefined {
  const refs = meta.ownerReferences ?? [];
  return refs.find((r) => r.controller) ?? refs[0];
}

/**
 * Resolves a pod's controlling workload for cost rollup: a ReplicaSet owner
 * is followed to its Deployment so the key is stable across rollouts. Bare
 * pods return undefined (grouped at namespace level, not given a fake name).
 */
function resolveWorkloadOwner(
  pod: K8sPod,
  replicaSetOwnerByKey: Map<string, OwnerReference | undefined>,
): { kind: string; name: string } | undefined {
  const owner = controllerOf(pod.metadata);
  if (!owner) return undefined;
  const plain = { kind: owner.kind, name: owner.name };
  if (owner.kind !== 'ReplicaSet') return plain;
  const rsOwner = replicaSetOwnerByKey.get(`${pod.metadata.namespace}/${owner.name}`);
  return rsOwner ? { kind: rsOwner.kind, name: rsOwner.name } : plain; // orphaned ReplicaSet kept as-is
}

// ---------------------------------------------------------------------------
// Secret redaction and security evidence
// ---------------------------------------------------------------------------

const SECRET_NAME = /(pass(word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth|conn(ection)?[_-]?str|dsn)/i;
/** `--password=x`, `-token=x`, `--db-secret x` style arguments: value replaced. */
const SECRET_ARG_INLINE = /^(--?[\w.-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|credential)[\w.-]*=).+$/i;
const SECRET_ARG_FLAG = /^--?[\w.-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|credential)[\w.-]*$/i;
/** Credentials embedded in a URL (scheme://user:pass@host). */
const URL_CREDS = /([a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:)[^@\s/]+@/gi;
export const REDACTED = '[REDACTED]';

function redactArgs(args: string[] | undefined): string[] | undefined {
  if (!args) return args;
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i]);
    if (SECRET_ARG_INLINE.test(a)) { out.push(a.replace(SECRET_ARG_INLINE, `$1${REDACTED}`)); continue; }
    out.push(a.replace(URL_CREDS, `$1${REDACTED}@`));
    // `--password value`: redact the following value if it is not itself a flag.
    if (SECRET_ARG_FLAG.test(a) && i + 1 < args.length && !String(args[i + 1]).startsWith('-')) {
      out.push(REDACTED);
      i += 1;
    }
  }
  return out;
}

/**
 * A container spec safe to persist: literal env values are removed (kept:
 * the name, whether a literal value was set, and valueFrom references),
 * secret-looking argument values and URL credentials are redacted. The
 * probe/exec commands are passed through the same argument redaction.
 */
export function redactContainer(c: K8sContainerSpec) {
  const redactProbe = (p: K8sProbe | undefined) => (p?.exec ? { ...p, exec: { command: redactArgs(p.exec.command) } } : p);
  return {
    ...c,
    command: redactArgs(c.command),
    args: redactArgs(c.args),
    env: c.env?.map((e) => ({
      name: e.name,
      hasLiteralValue: e.value !== undefined,
      ...(e.valueFrom ? { valueFrom: e.valueFrom } : {}),
    })),
    readinessProbe: redactProbe(c.readinessProbe),
    livenessProbe: redactProbe(c.livenessProbe),
    startupProbe: redactProbe(c.startupProbe),
  };
}

/** Env var names that carry a LITERAL value (not a secretKeyRef) and look like credentials. */
export function plaintextSecretEnvNames(containers: K8sContainerSpec[]): string[] {
  const names = new Set<string>();
  for (const c of containers) for (const e of c.env ?? []) {
    if (e.value !== undefined && e.value !== '' && SECRET_NAME.test(e.name)) names.add(`${c.name}:${e.name}`);
  }
  return [...names];
}

/**
 * Pod Security Standards evidence for one pod spec (baseline / restricted).
 * Evidence only; posture decides severity.
 */
export function podSecurityEvidence(spec: K8sPodSpec | undefined) {
  if (!spec) return { collected: false };
  const containers = [...(spec.containers ?? []), ...(spec.initContainers ?? [])];
  const podRunAsNonRoot = spec.securityContext?.runAsNonRoot === true;
  const podRunAsUser = spec.securityContext?.runAsUser;
  const added = new Set<string>();
  for (const c of containers) for (const cap of c.securityContext?.capabilities?.add ?? []) added.add(cap);
  const hostPathVolumes = (spec.volumes ?? []).filter((v) => v.hostPath).map((v) => v.hostPath?.path ?? '');
  return {
    collected: true,
    privilegedContainers: containers.filter((c) => c.securityContext?.privileged === true).map((c) => c.name),
    hostNetwork: spec.hostNetwork === true,
    hostPID: spec.hostPID === true,
    hostIPC: spec.hostIPC === true,
    hostPorts: containers.flatMap((c) => (c.ports ?? []).map((p) => p.hostPort).filter((p): p is number => typeof p === 'number' && p > 0)),
    hostPathVolumes,
    // A container may run as root unless runAsNonRoot is set, or runAsUser is non-zero, at container or pod level.
    containersMayRunAsRoot: containers.filter((c) => {
      const sc = c.securityContext;
      const nonRoot = sc?.runAsNonRoot ?? podRunAsNonRoot;
      const uid = sc?.runAsUser ?? podRunAsUser;
      return !(nonRoot || (uid !== undefined && uid !== 0));
    }).map((c) => c.name),
    // allowPrivilegeEscalation defaults to true when unset.
    containersAllowingPrivilegeEscalation: containers.filter((c) => c.securityContext?.allowPrivilegeEscalation !== false).map((c) => c.name),
    containersWithoutReadOnlyRootFs: containers.filter((c) => c.securityContext?.readOnlyRootFilesystem !== true).map((c) => c.name),
    addedCapabilities: [...added].sort(),
    serviceAccountName: spec.serviceAccountName ?? 'default',
    // Unset means the token IS mounted.
    automountServiceAccountToken: spec.automountServiceAccountToken !== false,
    imagesWithoutDigestOrWithLatest: containers.map((c) => c.image).filter((i) => !!i && !i.includes('@') && (/:latest$/.test(i) || !/:[^/]+$/.test(i))),
  };
}

// ---------------------------------------------------------------------------
// aws-auth ConfigMap
// ---------------------------------------------------------------------------

interface AuthMapEntry { arn: string; username?: string; groups: string[] }

/**
 * Minimal parser for aws-auth's mapRoles/mapUsers YAML, scoped to the
 * block-list shape AWS/eksctl always produce:
 *   - rolearn: arn:...
 *     username: ...
 *     groups:
 *       - system:masters
 * Also accepts flow-style groups (`groups: [a, b]`) and a list indented under
 * its key. Additive IAM-mapping context, not core discovery.
 */
export function parseAuthMapYaml(yaml: string): AuthMapEntry[] {
  const entries: AuthMapEntry[] = [];
  let current: AuthMapEntry | null = null;
  let inGroups = false;
  let entryIndent: number | null = null;
  const stripQuotes = (s: string) => s.replace(/^['"]|['"]$/g, '');
  const applyField = (entry: AuthMapEntry, fieldLine: string) => {
    const colonIdx = fieldLine.indexOf(':');
    if (colonIdx === -1) return;
    const key = fieldLine.slice(0, colonIdx).trim();
    const value = stripQuotes(fieldLine.slice(colonIdx + 1).trim());
    if (key === 'rolearn' || key === 'userarn') entry.arn = value;
    else if (key === 'username') entry.username = value;
    else if (key === 'groups') {
      inGroups = value === '';
      const flow = /^\[(.*)\]$/.exec(value);
      if (flow) entry.groups.push(...flow[1].split(',').map((g) => stripQuotes(g.trim())).filter(Boolean));
    }
  };

  for (const rawLine of yaml.split('\n')) {
    const line = rawLine.replace(/\r$/, '');
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const indent = line.length - line.trimStart().length;
    const content = line.trim();

    if (content.startsWith('- ') && (entryIndent === null || indent <= entryIndent)) {
      if (current) entries.push(current);
      entryIndent = indent;
      current = { arn: '', groups: [] };
      inGroups = false;
      applyField(current, content.slice(2));
    } else if (current && content.startsWith('- ')) {
      if (inGroups) current.groups.push(stripQuotes(content.slice(2).trim()));
    } else if (current) {
      inGroups = false;
      applyField(current, content);
    }
  }
  if (current) entries.push(current);
  return entries.filter((e) => e.arn);
}

// ---------------------------------------------------------------------------
// Kubernetes API access
// ---------------------------------------------------------------------------

export interface K8sListResult<T> {
  items: T[];
  ok: boolean;
  /** true when the list was read to the end. */
  complete: boolean;
  status: number;
  /** 401/403: identity not recognized or RBAC denied. */
  forbidden: boolean;
  error?: string;
}

type K8sGet = (path: string) => Promise<{ ok: boolean; status: number; body: unknown; error?: string }>;

/**
 * Reads a Kubernetes list with limit/continue pagination. A failure after the
 * first page returns what was read with complete=false (the caller reports
 * truncation). 410 Gone means the continue token expired mid-walk.
 */
export async function k8sListAll<T>(get: K8sGet, path: string, limit = K8S_PAGE_LIMIT, maxPages = K8S_MAX_PAGES): Promise<K8sListResult<T>> {
  const items: T[] = [];
  let cont: string | undefined;
  for (let page = 0; page < maxPages; page++) {
    const sep = path.includes('?') ? '&' : '?';
    const r = await get(`${path}${sep}limit=${limit}${cont ? `&continue=${encodeURIComponent(cont)}` : ''}`);
    if (!r.ok) {
      const forbidden = r.status === 401 || r.status === 403;
      return { items, ok: page > 0, complete: false, status: r.status, forbidden, error: r.error };
    }
    const body = (r.body ?? {}) as { items?: T[]; metadata?: { continue?: string } };
    items.push(...(Array.isArray(body.items) ? body.items : []));
    cont = body.metadata?.continue || undefined;
    if (!cont) return { items, ok: true, complete: true, status: r.status, forbidden: false };
  }
  return { items, ok: true, complete: false, status: 200, forbidden: false };
}

function k8sClient(endpoint: string, caCertPem: string, token: () => Promise<string>): { get: K8sGet; close: () => Promise<void> } {
  const agent = new Agent({
    connect: { ca: caCertPem, timeout: CONNECT_TIMEOUT_MS },
    headersTimeout: HEADERS_TIMEOUT_MS,
    bodyTimeout: BODY_TIMEOUT_MS,
  });
  const get: K8sGet = async (path) => {
    try {
      const res = await undiciFetch(`${endpoint}${path}`, {
        headers: { Authorization: `Bearer ${await token()}`, Accept: 'application/json' },
        dispatcher: agent,
      });
      const text = await res.text();
      const body = safeJson(text);
      if (body === undefined) return { ok: false, status: res.status || 0, body: null, error: `non-JSON body: ${text.slice(0, 200)}` };
      return { ok: res.ok, status: res.status, body, error: res.ok ? undefined : text.slice(0, 200) };
    } catch (err) {
      return { ok: false, status: 0, body: null, error: errorMessage(err) };
    }
  };
  return { get, close: () => agent.close().catch(() => undefined) };
}

/** Cluster names, paginated. A failure is reported and yields [] (never thrown). */
async function listClusterNames(ctx: ScannerContext): Promise<string[] | null> {
  const names: string[] = [];
  let token: string | undefined;
  for (let page = 0; page < 20; page++) {
    const r = await eksGet(ctx, `/clusters?maxResults=100${token ? `&nextToken=${encodeURIComponent(token)}` : ''}`);
    if (!r.ok) {
      console.error(`EKS ListClusters failed in ${ctx.region} (continuing without it): HTTP ${r.status} ${r.error ?? ''}`);
      reportListingFailure(ctx, { service: 'eks', action: 'ListClusters', region: ctx.region, httpStatus: r.status, truncated: page > 0 });
      return page > 0 ? names : null;
    }
    const body = (r.body ?? {}) as { clusters?: string[]; nextToken?: string };
    names.push(...(body.clusters ?? []).filter((n) => typeof n === 'string'));
    token = body.nextToken || undefined;
    if (!token) return names;
  }
  reportListingFailure(ctx, { service: 'eks', action: 'ListClusters', region: ctx.region, truncated: true });
  return names;
}

const K8S_ACTIONS = ['k8s:ListPods', 'k8s:ListDeployments', 'k8s:ListNamespaces', 'k8s:ListNodes', 'k8s:GetAwsAuth'] as const;

export async function scanEksWorkloads(ctx: ScannerContext): Promise<ScannedResource[]> {
  const listed = await listClusterNames(ctx);
  if (listed === null) {
    for (const action of K8S_ACTIONS) reportListingFailure(ctx, { service: 'eks', action, region: ctx.region });
    return [];
  }
  const names = [...new Set(listed)];
  const clusters = names.slice(0, MAX_CLUSTERS);
  if (names.length > clusters.length) {
    console.error(`EKS workloads ${ctx.region}: ${names.length} clusters; workloads read for the first ${clusters.length}.`);
    for (const action of K8S_ACTIONS) reportListingFailure(ctx, { service: 'eks', action, region: ctx.region, truncated: true });
  }

  const out: ScannedResource[] = [];
  const forbiddenClusters: string[] = [];
  let attempted = 0;

  const report = (action: string, r: { status: number; forbidden?: boolean }, truncated = false) =>
    reportListingFailure(ctx, { service: 'eks', action, region: ctx.region, httpStatus: r.forbidden ? 403 : r.status, truncated });

  for (const name of clusters) {
    const detail = await getClusterDetail(ctx, name);
    const status = detail?.status;
    // UPDATING clusters keep serving the Kubernetes API.
    const reachable = !!detail && (status === 'ACTIVE' || status === 'UPDATING') && !!detail.endpoint && !!detail.certificateAuthority?.data;
    if (!reachable) {
      // CREATING has no workloads yet and DELETING is going away; anything else
      // (describe failed, FAILED, PENDING, missing endpoint) keeps last-known rows.
      if (status !== 'CREATING' && status !== 'DELETING') {
        for (const action of K8S_ACTIONS) report(action, { status: 0 });
      }
      continue;
    }
    attempted += 1;

    const endpoint = detail.endpoint as string;
    const caCertPem = Buffer.from(detail.certificateAuthority?.data ?? '', 'base64').toString('utf8');
    const token = tokenSource(() => buildEksToken(ctx, name));
    const k8s = k8sClient(endpoint, caCertPem, token);
    const clusterId = `${ctx.region}/${name}`;
    let clusterForbidden = false;
    const handleFailure = (action: string, r: K8sListResult<unknown>) => {
      if (r.forbidden) clusterForbidden = true;
      else console.error(`EKS ${action} failed for cluster ${clusterId} (continuing): HTTP ${r.status} ${r.error ?? ''}`);
      report(action, r, r.ok && !r.complete);
    };

    try {
      // ReplicaSets resolve a pod's Deployment; a failure just leaves raw ReplicaSet owners.
      const replicaSets = await k8sListAll<K8sReplicaSet>(k8s.get, '/apis/apps/v1/replicasets');
      const replicaSetOwnerByKey = new Map<string, OwnerReference | undefined>();
      for (const rs of replicaSets.items) {
        if (rs?.metadata?.name) replicaSetOwnerByKey.set(`${rs.metadata.namespace}/${rs.metadata.name}`, controllerOf(rs.metadata));
      }

      const pods = await k8sListAll<K8sPod>(k8s.get, '/api/v1/pods');
      if (!pods.complete) handleFailure('k8s:ListPods', pods);
      for (const pod of pods.items) {
        if (!pod?.metadata?.name) continue;
        const statuses = pod.status?.containerStatuses ?? [];
        const requests = sumPodResourceRequests(pod.spec?.containers ?? []);
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
            // Running-pod requests (k8sCostAllocation.ts); distinct from the deployment's template.
            cpuRequestMillicores: requests.cpuMillicores, memoryRequestBytes: requests.memoryBytes, hasResourceRequest: requests.hasAnyRequest,
            ownerReferences: pod.metadata.ownerReferences, workloadOwner: resolveWorkloadOwner(pod, replicaSetOwnerByKey),
            podSecurity: podSecurityEvidence(pod.spec),
          },
          relationships: { clusterName: name },
        });
      }

      const deployments = await k8sListAll<K8sDeployment>(k8s.get, '/apis/apps/v1/deployments');
      if (!deployments.complete) handleFailure('k8s:ListDeployments', deployments);
      for (const dep of deployments.items) {
        if (!dep?.metadata?.name) continue;
        const tpl = dep.spec?.template?.spec;
        const containers = tpl?.containers ?? [];
        const initContainers = tpl?.initContainers ?? [];
        out.push({
          resourceTypeKey: 'eks_deployment', resourceId: `${clusterId}/${dep.metadata.namespace}/${dep.metadata.name}`, region: ctx.region,
          resourceName: dep.metadata.name, tags: dep.metadata.labels ?? {},
          metadata: {
            namespace: dep.metadata.namespace, replicas: dep.spec?.replicas, readyReplicas: dep.status?.readyReplicas,
            availableReplicas: dep.status?.availableReplicas, updatedReplicas: dep.status?.updatedReplicas,
            unavailableReplicas: dep.status?.unavailableReplicas,
            images: containers.map((c) => c.image), createdAt: dep.metadata.creationTimestamp,
            // Pod-template container spec with literal env values and secret-looking
            // arguments REDACTED (see redactContainer). Secrets are never read.
            containers: containers.map(redactContainer),
            initContainers: tpl?.initContainers ? initContainers.map(redactContainer) : undefined,
            serviceAccountName: tpl?.serviceAccountName,
            nodeSelector: tpl?.nodeSelector,
            strategy: dep.spec?.strategy, revisionHistoryLimit: dep.spec?.revisionHistoryLimit,
            conditions: dep.status?.conditions,
            podSecurity: podSecurityEvidence(tpl),
            plaintextSecretEnvVars: plaintextSecretEnvNames([...containers, ...initContainers]),
          },
          relationships: { clusterName: name },
        });
      }

      const namespaces = await k8sListAll<K8sNamespace>(k8s.get, '/api/v1/namespaces');
      if (!namespaces.complete) handleFailure('k8s:ListNamespaces', namespaces);
      if (namespaces.items.length > 0) {
        // ResourceQuota is in the built-in "view" ClusterRole; one cluster-wide list replaces a call per namespace.
        const quotas = await k8sListAll<K8sResourceQuota>(k8s.get, '/api/v1/resourcequotas');
        const quotasByNs = new Map<string, K8sResourceQuota[]>();
        for (const q of quotas.items) {
          const ns = q?.metadata?.namespace;
          if (!ns) continue;
          const list = quotasByNs.get(ns) ?? [];
          list.push(q);
          quotasByNs.set(ns, list);
        }
        for (const ns of namespaces.items) {
          if (!ns?.metadata?.name) continue;
          out.push({
            resourceTypeKey: 'eks_namespace', resourceId: `${clusterId}/${ns.metadata.name}`, region: ctx.region,
            resourceName: ns.metadata.name, state: ns.status?.phase, tags: ns.metadata.labels ?? {},
            metadata: {
              createdAt: ns.metadata.creationTimestamp,
              resourceQuotasCollected: quotas.complete,
              resourceQuotas: (quotasByNs.get(ns.metadata.name) ?? []).map((q) => ({ name: q.metadata.name, hard: q.status?.hard ?? q.spec?.hard, used: q.status?.used })),
              // Pod Security Admission level enforced on this namespace, if any.
              podSecurityEnforce: ns.metadata.labels?.['pod-security.kubernetes.io/enforce'] ?? null,
            },
            relationships: { clusterName: name },
          });
        }
      }

      const nodes = await k8sListAll<K8sNode>(k8s.get, '/api/v1/nodes');
      if (!nodes.complete) handleFailure('k8s:ListNodes', nodes);
      for (const node of nodes.items) {
        if (!node?.metadata?.name) continue;
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
            // Exact node -> ec2_instance join; undefined for Fargate nodes.
            providerID: node.spec?.providerID, ec2InstanceId: extractEc2InstanceId(node.spec?.providerID),
          },
          relationships: { clusterName: name },
        });
      }

      // Legacy aws-auth ConfigMap (absent, 404, on pure API auth-mode clusters).
      const authMap = await k8s.get('/api/v1/namespaces/kube-system/configmaps/aws-auth');
      if (authMap.ok) {
        const cm = (authMap.body ?? {}) as { data?: { mapRoles?: string; mapUsers?: string } };
        for (const [kind, yaml] of [['role', cm.data?.mapRoles], ['user', cm.data?.mapUsers]] as const) {
          for (const entry of parseAuthMapYaml(yaml ?? '')) {
            out.push({
              resourceTypeKey: 'eks_auth_mapping', resourceId: `${clusterId}/${kind}/${entry.arn}`, region: ctx.region, resourceName: entry.arn.split('/').pop(),
              metadata: { kind, arn: entry.arn, username: entry.username, groups: entry.groups, grantsClusterAdmin: entry.groups.includes('system:masters') },
              relationships: { clusterName: name },
            });
          }
        }
      } else if (authMap.status !== 404) {
        if (authMap.status !== 401 && authMap.status !== 403) {
          console.error(`aws-auth ConfigMap fetch failed for cluster ${clusterId} (continuing without it): HTTP ${authMap.status} ${authMap.error ?? ''}`);
        }
        report('k8s:GetAwsAuth', { status: authMap.status, forbidden: authMap.status === 401 || authMap.status === 403 });
      }
    } finally {
      await k8s.close();
    }
    if (clusterForbidden) forbiddenClusters.push(name);
  }

  if (forbiddenClusters.length > 0) {
    const message = `IAM identity not mapped to Kubernetes RBAC for ${forbiddenClusters.length} cluster(s) (${forbiddenClusters.join(', ')}) — grant this connection's IAM identity read access with an EKS access entry (e.g. AmazonEKSViewPolicy) or an aws-auth ConfigMap mapping (kube-system namespace) to at least the built-in "view" group.`;
    // Every reachable cluster denied: nothing useful was read, so fail loudly with the fix.
    if (forbiddenClusters.length === attempted) throw new Error(message);
    // Otherwise keep the mapped clusters' data; the denied ones were reported (not tombstoned).
    console.error(message);
  }

  return out;
}
