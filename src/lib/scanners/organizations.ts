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
 * OU listing is shallow: only the direct children of each root, not a
 * recursive walk of the full OU tree — a real, tracked gap for orgs with
 * nested OUs, not silently different from what it claims to cover
 * (OrganizationsResourceTypes lists 'organizations_ou' generically, this
 * scanner just doesn't walk arbitrarily deep).
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

  const rootsResult = await call('ListRoots');
  const roots = rootsResult.ok ? (rootsResult.body as ListRootsResponse).Roots ?? [] : [];
  for (const root of roots) {
    const ousResult = await call('ListOrganizationalUnitsForParent', { ParentId: root.Id });
    for (const ou of (ousResult.ok ? (ousResult.body as ListOUsResponse).OrganizationalUnits : []) ?? []) {
      out.push({ resourceTypeKey: 'organizations_ou', resourceId: ou.Id, region: null, resourceName: ou.Name, relationships: { parentId: root.Id } });
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
