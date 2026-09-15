import { callJsonApi } from '../awsApi';
import type { AwsCreds } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ORGANIZATIONS_RESOURCE_TYPES = ['organizations_account', 'organizations_ou', 'organizations_scp', 'tag_policy'] as const;

export interface OrgAccount { Id: string; Arn?: string; Name?: string; Email?: string; Status?: string; JoinedTimestamp?: number }
interface ListAccountsResponse { Accounts?: OrgAccount[] }
interface Root { Id: string; Arn?: string; Name?: string }
interface ListRootsResponse { Roots?: Root[] }
interface OrgUnit { Id: string; Arn?: string; Name?: string }
interface ListOUsResponse { OrganizationalUnits?: OrgUnit[] }
interface OrgPolicy { Id: string; Arn?: string; Name?: string; Description?: string; AwsManaged?: boolean }
interface ListPoliciesResponse { Policies?: OrgPolicy[] }

/**
 * AWS Organizations — global service, single endpoint in us-east-1
 * regardless of ctx.region, same convention as IAM. Every call here only
 * succeeds for the org's management account (or a delegated administrator);
 * a member account gets AWSOrganizationsNotInUseException on the very first
 * call, which is the expected, common case for most connections — logged
 * and returned as empty rather than treated as a failure.
 *
 * AWS-01: the OU walk is now RECURSIVE and shared with the hierarchy view.
 *
 * This scanner used to list only the direct children of each root, and said
 * so — a tracked gap for orgs with nested OUs. Meanwhile listOrganizationTree
 * below already walked the full tree correctly, but only to render a view;
 * nothing persisted it. So the product could DISPLAY a nested hierarchy it
 * could not STORE.
 *
 * Both now use the same walk. Writing a second recursion would have left two
 * implementations of one traversal free to disagree about depth, cycles and
 * bounds — and the shallow one was already the wrong answer.
 */
export async function scanOrganizations(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = 'organizations.us-east-1.amazonaws.com';
  const call = async (target: string, body: Record<string, unknown> = {}) =>
    callJsonApi(ctx.creds, { service: 'organizations', region: 'us-east-1', host, target: `AWSOrganizationsV20161128.${target}`, body });

  const accountsResult = await call('ListAccounts');
  if (!accountsResult.ok) {
    console.error(`Organizations ListAccounts failed (continuing without it — likely not the management account): ${accountsResult.errorMessage ?? accountsResult.errorCode ?? accountsResult.status}`);
    return [];
  }

  const out: ScannedResource[] = [];
  for (const a of (accountsResult.body as ListAccountsResponse).Accounts ?? []) {
    out.push({
      resourceTypeKey: 'organizations_account', resourceId: a.Id, region: null, resourceName: a.Name,
      state: a.Status, metadata: { email: a.Email, joinedTimestamp: a.JoinedTimestamp, arn: a.Arn },
    });
  }

  /**
   * Full hierarchy, flattened into inventory rows.
   *
   * Every OU carries its parent, and every account carries the OU it sits
   * in, so the nested shape is reconstructable from flat rows without a
   * second table. Identity is the AWS-native id (ou-…, r-…, the 12-digit
   * account id) — never the display name, which a rename changes and which
   * is not unique across an org.
   */
  const tree = await listOrganizationTree(ctx.creds);
  if (tree.ok) {
    for (const node of flattenOrgTree(tree.roots)) {
      if (node.kind === 'ou' || node.kind === 'root') {
        out.push({
          resourceTypeKey: 'organizations_ou',
          resourceId: node.id,
          region: null,
          resourceName: node.name,
          state: node.kind,
          // parentId is null for a root. Storing the depth makes a nesting
          // regression visible in data rather than only in a rendered tree.
          relationships: { parentId: node.parentId },
          metadata: { nodeType: node.kind, depth: node.depth },
        });
      } else {
        // An account's membership is an attribute of the account, so moving
        // it between OUs updates one row rather than rewriting the tree.
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
  }

  const scpResult = await call('ListPolicies', { Filter: 'SERVICE_CONTROL_POLICY' });
  for (const p of (scpResult.ok ? (scpResult.body as ListPoliciesResponse).Policies : []) ?? []) {
    out.push({ resourceTypeKey: 'organizations_scp', resourceId: p.Id, region: null, resourceName: p.Name, metadata: { description: p.Description, awsManaged: p.AwsManaged } });
  }

  const tagPolicyResult = await call('ListPolicies', { Filter: 'TAG_POLICY' });
  for (const p of (tagPolicyResult.ok ? (tagPolicyResult.body as ListPoliciesResponse).Policies : []) ?? []) {
    out.push({ resourceTypeKey: 'tag_policy', resourceId: p.Id, region: null, resourceName: p.Name, metadata: { description: p.Description, awsManaged: p.AwsManaged } });
  }

  return out;
}

/**
 * A one-time/on-demand lookup for the bulk-import endpoint (routes/
 * bulkImport.ts) -- deliberately separate from scanOrganizations above
 * rather than reusing its output, even though both call the same
 * ListAccounts API: that function returns ScannedResource[] shaped for the
 * discovery pipeline's own resource inventory (region:null, no Status
 * field, run on every scheduled scan of an already-connected account) and
 * silently swallows a not-the-management-account failure by returning [] --
 * exactly wrong for bulk-import, which needs the real Status per account to
 * filter out suspended/closed accounts, and needs a real error (not a quiet
 * empty list) when the given connection isn't the org's management account
 * at all.
 */
export async function listOrganizationAccounts(creds: AwsCreds): Promise<{ ok: true; accounts: OrgAccount[] } | { ok: false; error: string }> {
  const result = await callJsonApi(creds, {
    service: 'organizations', region: 'us-east-1', host: 'organizations.us-east-1.amazonaws.com',
    target: 'AWSOrganizationsV20161128.ListAccounts', body: {},
  });
  if (!result.ok) {
    return { ok: false, error: result.errorMessage ?? result.errorCode ?? `AWS Organizations ListAccounts failed (status ${result.status}) -- is this connection's account the Organization's management account (or a delegated administrator)?` };
  }
  return { ok: true, accounts: (result.body as ListAccountsResponse).Accounts ?? [] };
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
 * Pure, so every hierarchy rule below is testable without an AWS account —
 * which matters because this environment has no Organizations access, and a
 * rule that can only be checked against a management account is a rule that
 * never gets checked.
 *
 * Cycle-safe by construction: `seen` means a malformed or hostile response
 * that points an OU at its own ancestor terminates instead of recursing
 * forever. AWS should never return one, but "should never" is not a bound.
 */
export function flattenOrgTree(roots: readonly OrgTreeNode[]): FlatOrgNode[] {
  const out: FlatOrgNode[] = [];
  const seen = new Set<string>();

  const walk = (node: OrgTreeNode, parentId: string | null, depth: number) => {
    if (seen.has(node.id)) return;
    seen.add(node.id);

    out.push({ kind: node.type, id: node.id, name: node.name, parentId, depth });

    for (const a of node.accounts) {
      // An account can only sit in one OU, so a duplicate here means the
      // same account was returned under two parents — kept once, under the
      // first, rather than emitting a row that contradicts itself.
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
 * A recursive walk of the real AWS Organizations OU tree for the bulk-import
 * / Hierarchy view (routes/organizations.ts's `/organizations/hierarchy`).
 * Separate from `scanOrganizations` (the discovery-pipeline scanner, which is
 * deliberately shallow — see its doc comment): this one walks arbitrarily
 * deep via `ListOrganizationalUnitsForParent` + `ListAccountsForParent` on
 * each node. `maxNodes` bounds a pathological deployment; every call only
 * succeeds for the management account (or a delegated administrator) — a
 * member account gets AWSOrganizationsNotInUseException on `ListRoots`,
 * returned here as `{ ok: false }` so the route can fall back to the flat
 * "group by account id" view. NOT runnable in this environment (needs
 * PLATFORM_AWS_* to assume a cross-account role); shipped as pattern code.
 */
export async function listOrganizationTree(
  creds: AwsCreds,
  maxNodes = 500,
): Promise<{ ok: true; roots: OrgTreeNode[] } | { ok: false; error: string }> {
  const call = (target: string, body: Record<string, unknown> = {}) =>
    callJsonApi(creds, { service: 'organizations', region: 'us-east-1', host: 'organizations.us-east-1.amazonaws.com', target: `AWSOrganizationsV20161128.${target}`, body });

  const rootsResult = await call('ListRoots');
  if (!rootsResult.ok) {
    return { ok: false, error: rootsResult.errorMessage ?? rootsResult.errorCode ?? `AWS Organizations ListRoots failed (status ${rootsResult.status}) — is this the management account?` };
  }

  let visited = 0;
  const walk = async (id: string, name: string, type: 'root' | 'ou'): Promise<OrgTreeNode> => {
    visited++;
    const node: OrgTreeNode = { type, id, name, accounts: [], children: [] };
    if (visited > maxNodes) return node;

    const accountsResult = await call('ListAccountsForParent', { ParentId: id });
    for (const a of (accountsResult.ok ? (accountsResult.body as ListAccountsResponse).Accounts : []) ?? []) {
      node.accounts.push({ id: a.Id, name: a.Name ?? a.Id, email: a.Email, status: a.Status });
    }

    const ousResult = await call('ListOrganizationalUnitsForParent', { ParentId: id });
    for (const ou of (ousResult.ok ? (ousResult.body as ListOUsResponse).OrganizationalUnits : []) ?? []) {
      node.children.push(await walk(ou.Id, ou.Name ?? ou.Id, 'ou'));
    }
    return node;
  };

  const roots: OrgTreeNode[] = [];
  for (const root of (rootsResult.body as ListRootsResponse).Roots ?? []) {
    roots.push(await walk(root.Id, root.Name ?? 'Root', 'root'));
  }
  return { ok: true, roots };
}
