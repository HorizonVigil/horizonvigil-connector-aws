import { beforeEach, describe, it, expect, vi } from 'vitest';

const callJsonApiMock = vi.fn();
vi.mock('../awsApi', async (importOriginal: () => Promise<Record<string, unknown>>) => ({
  ...(await importOriginal()),
  callJsonApi: (...args: unknown[]) => callJsonApiMock(...args),
}));

import { flattenOrgTree, listOrganizationAccounts, listOrganizationTree, scanOrganizations, type OrgTreeNode } from './organizations';

/**
 * AWS-01 — OU hierarchy.
 *
 * These rules are tested against the pure flattener rather than a live
 * Organizations API, and that is deliberate: this environment has no
 * management-account access, and a rule that can only be checked against a
 * real org is a rule that never gets checked.
 *
 * The shape under test:
 *
 *   Root
 *     ├── OU Production
 *     │     ├── OU EU            (nested)
 *     │     │     └── account 3
 *     │     └── account 2
 *     └── account 1
 */
const acct = (id: string, name: string, status = 'ACTIVE') => ({ id, name, email: `${id}@example.test`, status });

const TREE: OrgTreeNode[] = [{
  type: 'root', id: 'r-root', name: 'Root',
  accounts: [acct('111111111111', 'sandbox')],
  children: [{
    type: 'ou', id: 'ou-prod', name: 'Production',
    accounts: [acct('222222222222', 'prod-core')],
    children: [{
      type: 'ou', id: 'ou-eu', name: 'EU',
      accounts: [acct('333333333333', 'prod-eu')],
      children: [],
    }],
  }],
}];

describe('flattenOrgTree', () => {
  it('emits every root, OU and account', () => {
    const flat = flattenOrgTree(TREE);
    expect(flat.map((n) => n.id).sort()).toEqual([
      '111111111111', '222222222222', '333333333333', 'ou-eu', 'ou-prod', 'r-root',
    ]);
  });

  /** The gap AWS-01 existed to close: nested OUs were never persisted. */
  it('walks nested OUs to arbitrary depth', () => {
    const flat = flattenOrgTree(TREE);
    const eu = flat.find((n) => n.id === 'ou-eu')!;
    expect(eu.parentId).toBe('ou-prod');
    expect(eu.depth).toBe(2);
    const deepAccount = flat.find((n) => n.id === '333333333333')!;
    expect(deepAccount.parentId).toBe('ou-eu');
    expect(deepAccount.depth).toBe(3);
  });

  it('gives a root a null parent and depth zero', () => {
    const root = flattenOrgTree(TREE).find((n) => n.id === 'r-root')!;
    expect(root.parentId).toBeNull();
    expect(root.depth).toBe(0);
    expect(root.kind).toBe('root');
  });

  it('attaches each account to the OU that contains it', () => {
    const flat = flattenOrgTree(TREE);
    expect(flat.find((n) => n.id === '111111111111')!.parentId).toBe('r-root');
    expect(flat.find((n) => n.id === '222222222222')!.parentId).toBe('ou-prod');
  });

  /**
   * Identity is the AWS-native id. A rename changes the display name and
   * nothing else — if identity were the name, a rename would look like a
   * delete plus a create and take the OU's history with it.
   */
  it('a rename preserves identity and parentage', () => {
    const renamed: OrgTreeNode[] = JSON.parse(JSON.stringify(TREE));
    renamed[0].children[0].name = 'Production-EMEA';
    const before = flattenOrgTree(TREE).find((n) => n.id === 'ou-prod')!;
    const after = flattenOrgTree(renamed).find((n) => n.id === 'ou-prod')!;
    expect(after.id).toBe(before.id);
    expect(after.parentId).toBe(before.parentId);
    expect(after.name).toBe('Production-EMEA');
  });

  /** Account movement updates one row's parent, not the tree's identity. */
  it('an account moved between OUs changes only its parent', () => {
    const moved: OrgTreeNode[] = JSON.parse(JSON.stringify(TREE));
    moved[0].children[0].accounts = [];
    moved[0].children[0].children[0].accounts.push(acct('222222222222', 'prod-core'));
    const after = flattenOrgTree(moved).find((n) => n.id === '222222222222')!;
    expect(after.parentId).toBe('ou-eu');
    expect(after.id).toBe('222222222222');
  });

  /**
   * Idempotency: the same input must produce the same output, or repeated
   * reconciliation would churn rows and their lifecycle timestamps.
   */
  it('is idempotent — repeated flattening is identical', () => {
    expect(flattenOrgTree(TREE)).toEqual(flattenOrgTree(TREE));
  });

  it('produces no duplicate ids', () => {
    const ids = flattenOrgTree(TREE).map((n) => n.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  /**
   * A malformed or hostile response pointing an OU at its own ancestor must
   * terminate. AWS should never return one, but "should never" is not a
   * bound, and an unbounded recursion here would hang the whole scan.
   */
  it('terminates on a cyclic tree instead of recursing forever', () => {
    const cyclic: OrgTreeNode = { type: 'root', id: 'r-1', name: 'Root', accounts: [], children: [] };
    const child: OrgTreeNode = { type: 'ou', id: 'ou-1', name: 'A', accounts: [], children: [cyclic] };
    cyclic.children.push(child);
    const flat = flattenOrgTree([cyclic]);
    expect(flat.map((n) => n.id)).toEqual(['r-1', 'ou-1']);
  });

  it('keeps an account once when it appears under two parents', () => {
    const dup: OrgTreeNode[] = JSON.parse(JSON.stringify(TREE));
    dup[0].children[0].children[0].accounts.push(acct('222222222222', 'prod-core'));
    const rows = flattenOrgTree(dup).filter((n) => n.id === '222222222222');
    expect(rows).toHaveLength(1);
    expect(rows[0].parentId).toBe('ou-prod');
  });

  it('handles an empty organization and an OU with no children', () => {
    expect(flattenOrgTree([])).toEqual([]);
    const bare: OrgTreeNode[] = [{ type: 'root', id: 'r-9', name: 'Root', accounts: [], children: [] }];
    expect(flattenOrgTree(bare)).toHaveLength(1);
  });

  it('carries account status so a suspended account is distinguishable', () => {
    const susp: OrgTreeNode[] = [{
      type: 'root', id: 'r-1', name: 'Root',
      accounts: [acct('444444444444', 'old', 'SUSPENDED')], children: [],
    }];
    expect(flattenOrgTree(susp).find((n) => n.id === '444444444444')!.status).toBe('SUSPENDED');
  });
});

/**
 * Scanner-level behaviour, driven through a mocked Organizations API.
 *
 * Organizations pages at 20 items by default. Every list call used to read
 * page one only, so the 21st account (or OU, or SCP) was silently dropped and
 * then tombstoned.
 */
type JsonReq = { target: string; body: Record<string, unknown> };
type Failure = { normalizedCode?: string };

const ok = (body: unknown) => Promise.resolve({ ok: true, status: 200, body });
const denied = () => Promise.resolve({ ok: false, status: 400, body: null, errorCode: 'AWSOrganizationsNotInUseException' });
const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const account = (n: number) => ({ Id: String(100000000000 + n), Name: `acct-${n}`, Email: `a${n}@example.test`, State: 'ACTIVE' });

/** 25 accounts over two pages, all directly under the root; one SCP. */
function serveOrg(opts: { failOuWalk?: boolean } = {}) {
  const all = Array.from({ length: 25 }, (_, i) => account(i));
  const page = (items: unknown[], key: string, token: unknown) => (token === 'p2'
    ? ok({ [key]: items.slice(20) })
    : ok({ [key]: items.slice(0, 20), NextToken: 'p2' }));
  callJsonApiMock.mockImplementation((_c: unknown, req: JsonReq) => {
    const op = req.target.split('.').pop();
    switch (op) {
      case 'ListAccounts': return page(all, 'Accounts', req.body.NextToken);
      case 'DescribeOrganization': return ok({ Organization: { Id: 'o-1', FeatureSet: 'ALL', MasterAccountId: all[0].Id } });
      case 'ListRoots': return ok({ Roots: [{ Id: 'r-1', Name: 'Root' }] });
      case 'ListAccountsForParent': return page(all, 'Accounts', req.body.NextToken);
      case 'ListOrganizationalUnitsForParent': return opts.failOuWalk ? denied() : ok({ OrganizationalUnits: [] });
      case 'ListPolicies': return ok({ Policies: req.body.Filter === 'SERVICE_CONTROL_POLICY' ? [{ Id: 'p-1', Name: 'deny-leave' }] : [] });
      case 'ListTargetsForPolicy': return ok({ Targets: [{ TargetId: 'r-1', Type: 'ROOT' }] });
      default: return denied();
    }
  });
}

beforeEach(() => { callJsonApiMock.mockReset(); });

describe('scanOrganizations', () => {
  it('reads every page of accounts (Organizations pages at 20)', async () => {
    serveOrg();
    const out = await scanOrganizations({ creds, region: 'us-east-1' });
    expect(out.filter((r) => r.resourceTypeKey === 'organizations_account')).toHaveLength(25);
  });

  it('emits each account ONCE, enriched with its parent', async () => {
    serveOrg();
    const out = await scanOrganizations({ creds, region: 'us-east-1' });
    const ids = out.filter((r) => r.resourceTypeKey === 'organizations_account').map((r) => r.resourceId);
    expect(new Set(ids).size).toBe(ids.length);
    const first = out.find((r) => r.resourceId === account(0).Id);
    expect(first?.relationships?.parentId).toBe('r-1');
    expect(first?.metadata).toMatchObject({ isManagementAccount: true, depth: 1 });
  });

  it('records the org feature set on the root and SCP attachment targets', async () => {
    serveOrg();
    const out = await scanOrganizations({ creds, region: 'us-east-1' });
    expect(out.find((r) => r.resourceId === 'r-1')?.metadata).toMatchObject({ featureSet: 'ALL', organizationId: 'o-1' });
    const scp = out.find((r) => r.resourceTypeKey === 'organizations_scp');
    expect(scp?.relationships?.targetIds).toEqual(['r-1']);
    expect(scp?.metadata).toMatchObject({ targetsCollected: true, targetCount: 1 });
  });

  it('REPORTS a partial OU walk so missing OUs are not tombstoned', async () => {
    const failures: Failure[] = [];
    serveOrg({ failOuWalk: true });
    await scanOrganizations({ creds: { ...creds, onCallFailure: (f: Failure) => failures.push(f) }, region: 'us-east-1' });
    expect(failures.some((f) => f.normalizedCode === 'PAGINATION_TRUNCATED')).toBe(true);
  });

  it('returns nothing for a member account (not an error)', async () => {
    callJsonApiMock.mockImplementation(() => denied());
    expect(await scanOrganizations({ creds, region: 'us-east-1' })).toEqual([]);
  });
});

describe('listOrganizationTree / listOrganizationAccounts', () => {
  it('flags an incomplete tree instead of returning a quietly short one', async () => {
    serveOrg({ failOuWalk: true });
    const tree = await listOrganizationTree(creds);
    expect(tree.ok).toBe(true);
    if (tree.ok) expect(tree.complete).toBe(false);
  });

  it('bulk import reads every page', async () => {
    serveOrg();
    const res = await listOrganizationAccounts(creds);
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.accounts).toHaveLength(25);
      expect(res.accounts[0].Status).toBe('ACTIVE');
    }
  });
});
/**
 * Scoping the listing to an organizational unit.
 *
 * `ListAccounts` tops out at 100 pages x 20 accounts, so an Organization
 * larger than 2,000 accounts cannot be read in one call at all. Reading it a
 * branch at a time is the only way it is importable — and it is the control a
 * customer wants regardless, to onboard Production without also onboarding
 * every sandbox.
 */
describe('listOrganizationAccounts scoped to an OU', () => {
  beforeEach(() => callJsonApiMock.mockReset());

  const page = (accounts: unknown[], nextToken?: string) =>
    Promise.resolve({ ok: true, status: 200, body: { Accounts: accounts, ...(nextToken ? { NextToken: nextToken } : {}) } });

  it('calls ListAccountsForParent with the OU id when scoped', async () => {
    callJsonApiMock.mockImplementation(() => page([{ Id: '111122223333', Name: 'prod-a', Status: 'ACTIVE' }]));

    const result = await listOrganizationAccounts({ accessKeyId: 'AKIA_TEST', secretAccessKey: 's' }, 'ou-abc1-def2');

    expect(result.ok).toBe(true);
    const [, req] = callJsonApiMock.mock.calls[0];
    expect((req as { target: string }).target).toContain('ListAccountsForParent');
    expect((req as { body: Record<string, unknown> }).body).toMatchObject({ ParentId: 'ou-abc1-def2' });
  });

  it('calls ListAccounts for the whole organization when unscoped', async () => {
    callJsonApiMock.mockImplementation(() => page([{ Id: '111122223333', Name: 'a', Status: 'ACTIVE' }]));

    await listOrganizationAccounts({ accessKeyId: 'AKIA_TEST', secretAccessKey: 's' });

    const [, req] = callJsonApiMock.mock.calls[0];
    expect((req as { target: string }).target).toContain('ListAccounts');
    expect((req as { target: string }).target).not.toContain('ForParent');
    expect((req as { body: Record<string, unknown> }).body).not.toHaveProperty('ParentId');
  });

  it('pages a scoped listing to completion', async () => {
    // 20 per page is the AWS maximum, so anything real is multi-page. A
    // scoped read that stopped at page one would silently import a fraction
    // of an OU.
    callJsonApiMock
      .mockImplementationOnce(() => page([{ Id: '1', Status: 'ACTIVE' }], 'tok'))
      .mockImplementationOnce(() => page([{ Id: '2', Status: 'ACTIVE' }]));

    const result = await listOrganizationAccounts({ accessKeyId: 'AKIA_TEST', secretAccessKey: 's' }, 'ou-1');

    expect(result.ok && result.accounts.map((a) => a.Id)).toEqual(['1', '2']);
    expect(callJsonApiMock).toHaveBeenCalledTimes(2);
  });

  /**
   * An unscoped listing that hit the page cap must point at the way out.
   * "Could not be read completely" alone leaves a customer with a 3,000
   * account org and nothing to do.
   */
  it('tells an over-sized organization to scope by OU', async () => {
    callJsonApiMock.mockImplementation(() => page([{ Id: 'x', Status: 'ACTIVE' }], 'always-more'));

    const result = await listOrganizationAccounts({ accessKeyId: 'AKIA_TEST', secretAccessKey: 's' });

    expect(result.ok).toBe(false);
    expect(!result.ok && result.error).toMatch(/organizational unit/i);
  });

  it('does not suggest scoping when the read was ALREADY scoped', async () => {
    // Telling someone who passed an OU to pass an OU is noise, and hides the
    // real cause (a single OU genuinely above the cap).
    callJsonApiMock.mockImplementation(() => page([{ Id: 'x', Status: 'ACTIVE' }], 'always-more'));

    const result = await listOrganizationAccounts({ accessKeyId: 'AKIA_TEST', secretAccessKey: 's' }, 'ou-1');

    expect(result.ok).toBe(false);
    expect(!result.ok && result.error).toContain('ListAccountsForParent(ou-1)');
    expect(!result.ok && result.error).not.toMatch(/pass an OU id/i);
  });
});
