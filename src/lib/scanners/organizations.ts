import { callJsonApi } from '../awsApi';
import type { AwsCreds } from '../awsApi';
import { incompleteSink } from '../pagination';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ORGANIZATIONS_RESOURCE_TYPES = ['organizations_account', 'organizations_ou', 'organizations_scp', 'tag_policy'] as const;

const HOST = 'organizations.us-east-1.amazonaws.com';
const TARGET_PREFIX = 'AWSOrganizationsV20161128';

/**
 * Organizations list calls return at most 20 items per page by default and
 * paginate on NextToken. None of the calls in the previous version followed
 * NextToken, so an organization with 21 accounts lost the 21st -- and
 * finalize read it as deleted.
 */
const PAGE_SIZE = 20;
const MAX_PAGES = 100;

/** SCP → attachment-target lookups (ListTargetsForPolicy), bounded. */
const MAX_SCP_TARGET_LOOKUPS = 50;
const SCP_TARGET_CONCURRENCY = 3;

export interface OrgAccount {
  Id: string; Arn?: string; Name?: string; Email?: string;
  /** Deprecated by AWS in favour of `State`; still read as a fallback. */
  Status?: string;
  State?: string;
  JoinedMethod?: string;
  JoinedTimestamp?: number;
}
interface Root { Id: string; Arn?: string; Name?: string; PolicyTypes?: { Type?: string; Status?: string }[] }
interface OrgUnit { Id: string; Arn?: string; Name?: string }
interface OrgPolicy { Id: string; Arn?: string; Name?: string; Description?: string; AwsManaged?: boolean }
interface PolicyTarget { TargetId?: string; Type?: string; Name?: string }
interface Organization { Id?: string; FeatureSet?: string; MasterAccountId?: string; MasterAccountEmail?: string }

type JsonCall = (target: string, body?: Record<string, unknown>) => ReturnType<typeof callJsonApi>;

function makeCall(creds: AwsCreds): JsonCall {
  return (target, body = {}) =>
    callJsonApi(creds, { service: 'organizations', region: 'us-east-1', host: HOST, target: `${TARGET_PREFIX}.${target}`, body });
}

export interface ListAllResult<T> {
  items: T[];
  /** true only when AWS stopped handing out NextToken. */
  complete: boolean;
  /** true when the FIRST page failed (nothing was read at all). */
  firstPageFailed: boolean;
  error?: string;
}

/** Every page of one Organizations list call. Never throws. */
export async function listAll<T>(call: JsonCall, target: string, body: Record<string, unknown>, key: string): Promise<ListAllResult<T>> {
  const items: T[] = [];
  const seen = new Set<string>();
  let token: string | undefined;

  for (let page = 0; page < MAX_PAGES; page++) {
    const result = await call(target, { ...body, MaxResults: PAGE_SIZE, ...(token ? { NextToken: token } : {}) });
    if (!result.ok) {
      const error = result.errorMessage ?? result.errorCode ?? `status ${result.status}`;
      return { items, complete: false, firstPageFailed: page === 0, error };
    }
    const payload = (result.body ?? {}) as Record<string, unknown>;
    const pageItems = payload[key];
    if (Array.isArray(pageItems)) items.push(...(pageItems as T[]));

    const next = typeof payload.NextToken === 'string' && payload.NextToken !== '' ? payload.NextToken : undefined;
    if (!next) return { items, complete: true, firstPageFailed: false };
    if (seen.has(next)) return { items, complete: false, firstPageFailed: false, error: `${target} returned a repeated NextToken` };
    seen.add(next);
    token = next;
  }
  return { items, complete: false, firstPageFailed: false, error: `${target} exceeded ${MAX_PAGES} pages` };
}

/** Organizations' JSON protocol returns timestamps as epoch SECONDS. */
function toIso(value: number | string | undefined): string | null {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value === 'number') return Number.isFinite(value) ? new Date(value * 1000).toISOString() : null;
  return value;
}

/**
 * AWS Organizations — global service, single endpoint in us-east-1
 * regardless of ctx.region, same convention as IAM. Every call here only
 * succeeds for the org's management account (or a delegated administrator);
 * a member account gets AWSOrganizationsNotInUseException / AccessDenied on
 * the very first call, which is the expected, common case — logged and
 * returned as empty rather than treated as a failure.
 *
 * What changed:
 *
 *  - EVERY list call paginates (see PAGE_SIZE). Any organization larger than
 *    20 accounts, OUs or policies was silently truncated before.
 *
 *  - Each account is emitted ONCE. The previous version emitted it from
 *    ListAccounts and AGAIN from the OU tree -- two rows with the same
 *    (type, id), which reconciliation reports as DUPLICATE_LOCAL. The tree now
 *    enriches the ListAccounts row with its parent and depth.
 *
 *  - A partial read is REPORTED. A failed ListAccountsForParent /
 *    ListOrganizationalUnitsForParent, or the node cap, used to drop OUs
 *    silently, and finalize then tombstoned them.
 *
 *  - SCPs carry their attachment targets, and roots carry the org's feature
 *    set (SCPs only take effect under FeatureSet=ALL).
 *
 * AWS-01: the OU walk is recursive and shared with the hierarchy view, so the
 * product cannot DISPLAY a hierarchy it does not STORE.
 */
export async function scanOrganizations(ctx: ScannerContext): Promise<ScannedResource[]> {
  const call = makeCall(ctx.creds);
  const onIncomplete = incompleteSink(ctx.creds);

  const accounts = await listAll<OrgAccount>(call, 'ListAccounts', {}, 'Accounts');
  if (accounts.firstPageFailed) {
    console.error(`Organizations ListAccounts failed (continuing without it — likely not the management account): ${accounts.error}`);
    return [];
  }
  if (!accounts.complete) {
    const detail = `Organizations ListAccounts incomplete after ${accounts.items.length} account(s): ${accounts.error}`;
    console.error(detail);
    onIncomplete('PAGINATION_TRUNCATED', detail);
  }

  const orgResult = await call('DescribeOrganization');
  const organization = orgResult.ok ? ((orgResult.body as { Organization?: Organization })?.Organization ?? null) : null;

  const tree = await listOrganizationTree(ctx.creds);
  if (!tree.ok) {
    const detail = `Organizations hierarchy unavailable: ${tree.error}`;
    console.error(detail);
    onIncomplete('PAGINATION_TRUNCATED', detail);
  } else if (!tree.complete) {
    const detail = `Organizations hierarchy incomplete: ${tree.incompleteReasons.slice(0, 5).join('; ')}`;
    console.error(detail);
    onIncomplete('PAGINATION_TRUNCATED', detail);
  }

  const flat = tree.ok ? flattenOrgTree(tree.roots) : [];
  const placement = new Map(flat.filter((n) => n.kind === 'account').map((n) => [n.id, n]));

  const out: ScannedResource[] = [];
  const emittedAccounts = new Set<string>();

  for (const a of accounts.items) {
    if (!a?.Id || emittedAccounts.has(a.Id)) continue;
    emittedAccounts.add(a.Id);
    const node = placement.get(a.Id);
    out.push({
      resourceTypeKey: 'organizations_account', resourceId: a.Id, region: null, resourceName: a.Name,
      state: a.State ?? a.Status,
      metadata: {
        email: a.Email, joinedTimestamp: a.JoinedTimestamp, joinedAtIso: toIso(a.JoinedTimestamp), arn: a.Arn,
        joinedMethod: a.JoinedMethod ?? null,
        isManagementAccount: organization?.MasterAccountId ? organization.MasterAccountId === a.Id : null,
        nodeType: 'account',
        depth: node?.depth ?? null,
      },
      relationships: { parentId: node?.parentId ?? null },
    });
  }

  /**
   * Full hierarchy, flattened into inventory rows. Identity is the AWS-native
   * id (ou-…, r-…, 12-digit account id) — never the display name, which a
   * rename changes and which is not unique across an org.
   */
  for (const node of flat) {
    if (node.kind === 'ou' || node.kind === 'root') {
      out.push({
        resourceTypeKey: 'organizations_ou',
        resourceId: node.id,
        region: null,
        resourceName: node.name,
        state: node.kind,
        relationships: { parentId: node.parentId },
        metadata: {
          nodeType: node.kind,
          depth: node.depth,
          ...(node.kind === 'root' ? {
            organizationId: organization?.Id ?? null,
            featureSet: organization?.FeatureSet ?? null,
            managementAccountId: organization?.MasterAccountId ?? null,
          } : {}),
        },
      });
    } else if (!emittedAccounts.has(node.id)) {
      // Seen in the tree but not in ListAccounts (only possible when
      // ListAccounts was cut short). Emitted once, from the tree.
      emittedAccounts.add(node.id);
      out.push({
        resourceTypeKey: 'organizations_account',
        resourceId: node.id,
        region: null,
        resourceName: node.name,
        state: node.status,
        relationships: { parentId: node.parentId },
        metadata: { email: node.email, nodeType: 'account', depth: node.depth },
      });
    }
  }

  const [scps, tagPolicies] = await Promise.all([
    listAll<OrgPolicy>(call, 'ListPolicies', { Filter: 'SERVICE_CONTROL_POLICY' }, 'Policies'),
    listAll<OrgPolicy>(call, 'ListPolicies', { Filter: 'TAG_POLICY' }, 'Policies'),
  ]);
  for (const [label, res] of [['SERVICE_CONTROL_POLICY', scps], ['TAG_POLICY', tagPolicies]] as const) {
    if (!res.complete && !res.firstPageFailed) {
      const detail = `Organizations ListPolicies(${label}) incomplete: ${res.error}`;
      console.error(detail);
      onIncomplete('PAGINATION_TRUNCATED', detail);
    } else if (res.firstPageFailed) {
      console.error(`Organizations ListPolicies(${label}) failed (continuing without it): ${res.error}`);
    }
  }

  // Where each SCP is attached. A deny-guardrail SCP that is attached nowhere
  // protects nothing, so this is posture evidence, not decoration.
  const scpTargets = new Map<string, { targets: PolicyTarget[]; complete: boolean }>();
  const scpLookups = scps.items.filter((p) => !!p?.Id).slice(0, MAX_SCP_TARGET_LOOKUPS);
  await mapWithConcurrency(scpLookups, SCP_TARGET_CONCURRENCY, async (p) => {
    const res = await listAll<PolicyTarget>(call, 'ListTargetsForPolicy', { PolicyId: p.Id }, 'Targets');
    scpTargets.set(p.Id, { targets: res.items, complete: res.complete });
  });

  for (const p of scps.items) {
    if (!p?.Id) continue;
    const t = scpTargets.get(p.Id);
    out.push({
      resourceTypeKey: 'organizations_scp', resourceId: p.Id, region: null, resourceName: p.Name,
      metadata: {
        description: p.Description, awsManaged: p.AwsManaged, arn: p.Arn ?? null,
        targetsCollected: t?.complete ?? false,
        targetCount: t ? t.targets.length : null,
      },
      relationships: {
        targetIds: t ? t.targets.map((x) => x.TargetId).filter((v): v is string => !!v) : [],
      },
    });
  }

  for (const p of tagPolicies.items) {
    if (!p?.Id) continue;
    out.push({ resourceTypeKey: 'tag_policy', resourceId: p.Id, region: null, resourceName: p.Name, metadata: { description: p.Description, awsManaged: p.AwsManaged, arn: p.Arn ?? null } });
  }

  return out;
}

/**
 * A one-time/on-demand lookup for the bulk-import endpoint (routes/
 * bulkImport.ts) -- deliberately separate from scanOrganizations: bulk-import
 * needs the real per-account status to filter out suspended/closed accounts,
 * and needs a real error (not a quiet empty list) when the connection isn't
 * the org's management account.
 *
 * Now paginated. A partial list is returned as an ERROR rather than as a
 * short success, because importing "all accounts" from a truncated list would
 * silently skip accounts.
 */
export async function listOrganizationAccounts(creds: AwsCreds): Promise<{ ok: true; accounts: OrgAccount[] } | { ok: false; error: string }> {
  const res = await listAll<OrgAccount>(makeCall(creds), 'ListAccounts', {}, 'Accounts');
  if (res.firstPageFailed) {
    return { ok: false, error: res.error ?? 'AWS Organizations ListAccounts failed -- is this connection\'s account the Organization\'s management account (or a delegated administrator)?' };
  }
  if (!res.complete) {
    return { ok: false, error: `AWS Organizations ListAccounts could not be read completely (${res.items.length} account(s) read): ${res.error}` };
  }
  // `Status` is deprecated in favour of `State`; keep callers reading Status working.
  return { ok: true, accounts: res.items.map((a) => ({ ...a, Status: a.Status ?? a.State })) };
}

// ── Hierarchy flattening (AWS-01) ──────────────────────────────────────────

export interface FlatOrgNode {
  kind: 'root' | 'ou' | 'account';
  id: string;
  name: string;
  /** Native id of the containing root/OU. Null only for a root. */
  parentId: string | null;
  depth: number;
  email?: string;
  status?: string;
}

/**
 * Flattens the OU tree into rows, preserving parentage and depth.
 *
 * Pure, so every hierarchy rule is testable without an AWS account.
 * Cycle-safe by construction: `seen` means a malformed or hostile response
 * that points an OU at its own ancestor terminates instead of recursing
 * forever.
 */
export function flattenOrgTree(roots: readonly OrgTreeNode[]): FlatOrgNode[] {
  const out: FlatOrgNode[] = [];
  const seen = new Set<string>();

  const walk = (node: OrgTreeNode, parentId: string | null, depth: number) => {
    if (seen.has(node.id)) return;
    seen.add(node.id);

    out.push({ kind: node.type, id: node.id, name: node.name, parentId, depth });

    for (const a of node.accounts) {
      // An account can only sit in one OU; a duplicate is kept once, under the
      // first parent, rather than emitting a row that contradicts itself.
      if (seen.has(a.id)) continue;
      seen.add(a.id);
      out.push({
        kind: 'account', id: a.id, name: a.name, parentId: node.id,
        depth: depth + 1, email: a.email, status: a.status,
      });
    }

    for (const child of node.children) walk(child, node.id, depth + 1);
  };

  for (const root of roots) walk(root, null, 0);
  return out;
}

// ── Full OU tree (spec §25) ────────────────────────────────────────────────

export interface OrgTreeNode {
  type: 'root' | 'ou';
  id: string;
  name: string;
  accounts: { id: string; name: string; email?: string; status?: string }[];
  children: OrgTreeNode[];
}

/**
 * Recursive walk of the AWS Organizations OU tree, shared by the discovery
 * scanner and the Hierarchy view (routes/organizations.ts).
 *
 * Every list call paginates. `complete` is false -- with the reasons -- when
 * any parent's accounts or child OUs could not be read in full, or when
 * `maxNodes` stopped the walk; the scanner reports that as degraded coverage
 * so a missing OU is never read as a deleted one. Calls are sequential on
 * purpose: Organizations' API rate limit is low.
 *
 * A member account gets AWSOrganizationsNotInUseException on ListRoots,
 * returned as `{ ok: false }` so the route can fall back to the flat view.
 */
export async function listOrganizationTree(
  creds: AwsCreds,
  maxNodes = 500,
): Promise<{ ok: true; roots: OrgTreeNode[]; complete: boolean; incompleteReasons: string[] } | { ok: false; error: string }> {
  const call = makeCall(creds);

  const rootsResult = await listAll<Root>(call, 'ListRoots', {}, 'Roots');
  if (rootsResult.firstPageFailed) {
    return { ok: false, error: rootsResult.error ?? 'AWS Organizations ListRoots failed — is this the management account?' };
  }

  const incompleteReasons: string[] = [];
  if (!rootsResult.complete) incompleteReasons.push(`ListRoots: ${rootsResult.error}`);

  let visited = 0;
  const onPath = new Set<string>();

  const walk = async (id: string, name: string, type: 'root' | 'ou'): Promise<OrgTreeNode> => {
    visited++;
    const node: OrgTreeNode = { type, id, name, accounts: [], children: [] };
    if (visited > maxNodes) {
      incompleteReasons.push(`node cap ${maxNodes} reached at ${id}`);
      return node;
    }
    // A malformed response pointing an OU at its own ancestor must terminate.
    if (onPath.has(id)) {
      incompleteReasons.push(`cycle at ${id}`);
      return node;
    }
    onPath.add(id);

    const accounts = await listAll<OrgAccount>(call, 'ListAccountsForParent', { ParentId: id }, 'Accounts');
    if (!accounts.complete) incompleteReasons.push(`ListAccountsForParent(${id}): ${accounts.error}`);
    for (const a of accounts.items) {
      if (!a?.Id) continue;
      node.accounts.push({ id: a.Id, name: a.Name ?? a.Id, email: a.Email, status: a.State ?? a.Status });
    }

    const ous = await listAll<OrgUnit>(call, 'ListOrganizationalUnitsForParent', { ParentId: id }, 'OrganizationalUnits');
    if (!ous.complete) incompleteReasons.push(`ListOrganizationalUnitsForParent(${id}): ${ous.error}`);
    for (const ou of ous.items) {
      if (!ou?.Id) continue;
      node.children.push(await walk(ou.Id, ou.Name ?? ou.Id, 'ou'));
    }

    onPath.delete(id);
    return node;
  };

  const roots: OrgTreeNode[] = [];
  for (const root of rootsResult.items) {
    if (!root?.Id) continue;
    roots.push(await walk(root.Id, root.Name ?? 'Root', 'root'));
  }
  return { ok: true, roots, complete: incompleteReasons.length === 0, incompleteReasons };
}