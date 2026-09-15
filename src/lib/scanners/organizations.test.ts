import { describe, it, expect } from 'vitest';
import { flattenOrgTree, type OrgTreeNode } from './organizations';

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
