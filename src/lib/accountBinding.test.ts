import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

import { checkAccountBinding, isPlaceholderAccountId } from './accountBinding';

/**
 * The production case, measured 2026-09-22: 10 ACCOUNT_MISMATCH quarantine
 * records from 2026-09-10 reading
 *
 *   "Resource belongs to AWS account 604179600483, but this connection is
 *    bound to 000000000000."
 *
 * A connection collected a real estate under a placeholder id, admission
 * refused every resource it read, and validation reported success throughout.
 */
const REAL_ACCOUNT = '604179600483';
const PLACEHOLDER = '000000000000';

describe('checkAccountBinding', () => {
  it('matches when the stated and observed accounts agree', () => {
    expect(checkAccountBinding(REAL_ACCOUNT, REAL_ACCOUNT)).toEqual({
      state: 'matched',
      accountId: REAL_ACCOUNT,
    });
  });

  it('catches the exact production mismatch', () => {
    const result = checkAccountBinding(PLACEHOLDER, REAL_ACCOUNT);

    expect(result.state).toBe('mismatched');
    if (result.state !== 'mismatched') throw new Error('unreachable');
    expect(result.claimed).toBe(PLACEHOLDER);
    expect(result.observed).toBe(REAL_ACCOUNT);
  });

  it('says what it costs and both ways to fix it', () => {
    const result = checkAccountBinding(PLACEHOLDER, REAL_ACCOUNT);
    if (result.state !== 'mismatched') throw new Error('unreachable');

    // A message naming neither account cannot be acted on, and the ids are
    // not secret — admission already prints them in its own quarantine detail.
    expect(result.message).toContain(REAL_ACCOUNT);
    expect(result.message).toContain(PLACEHOLDER);
    expect(result.message).toContain('nothing reaches inventory');
    expect(result.message).toMatch(/Correct the account id|connect credentials/);
  });

  /**
   * The distinction that matters most. "We did not check" and "we checked and
   * it matched" must never produce the same answer — treating the first as the
   * second is how this went unnoticed for 12 days in the first place.
   */
  it('reports UNVERIFIED rather than matched when the connection states no account', () => {
    expect(checkAccountBinding(null, REAL_ACCOUNT)).toEqual({
      state: 'unverified',
      reason: 'no_claimed_account',
    });
  });

  it('reports UNVERIFIED rather than matched when STS returned no account', () => {
    expect(checkAccountBinding(REAL_ACCOUNT, null)).toEqual({
      state: 'unverified',
      reason: 'no_observed_account',
    });
  });

  it('treats an empty or whitespace id as absent, not as a value to compare', () => {
    expect(checkAccountBinding('   ', REAL_ACCOUNT).state).toBe('unverified');
    expect(checkAccountBinding(REAL_ACCOUNT, '').state).toBe('unverified');
  });

  it('ignores surrounding whitespace when comparing', () => {
    expect(checkAccountBinding(` ${REAL_ACCOUNT} `, REAL_ACCOUNT).state).toBe('matched');
  });
});

describe('isPlaceholderAccountId', () => {
  it('recognises the all-zeros placeholder', () => {
    // Twelve digits, passes every format check this codebase applies, and is
    // not an account.
    expect(isPlaceholderAccountId(PLACEHOLDER)).toBe(true);
  });

  it('does not flag a real account id', () => {
    expect(isPlaceholderAccountId(REAL_ACCOUNT)).toBe(false);
    expect(isPlaceholderAccountId('100000000000')).toBe(false);
    expect(isPlaceholderAccountId('000000000001')).toBe(false);
  });

  it('is not fooled by length', () => {
    expect(isPlaceholderAccountId('00000000000')).toBe(false);
    expect(isPlaceholderAccountId('0000000000000')).toBe(false);
  });

  it('handles absent values', () => {
    expect(isPlaceholderAccountId(null)).toBe(false);
    expect(isPlaceholderAccountId(undefined)).toBe(false);
  });
});

/**
 * The wiring. A binding check nothing calls leaves the connection exactly as
 * broken as before.
 */
describe('validation enforces the account binding', () => {
  const PERMISSIONS = readFileSync('src/routes/permissions.ts', 'utf8');
  const ACCOUNTS = readFileSync('src/routes/accounts.ts', 'utf8');

  it('validation compares STS against the stated account', () => {
    expect(PERMISSIONS).toContain('checkAccountBinding(connection.aws_account_id, identity?.accountId)');
  });

  it('a mismatch fails the run, whatever the permission verdict said', () => {
    // Every permission can be granted and the connection still collect
    // nothing, because admission refuses all of it.
    expect(PERMISSIONS).toContain("const overallStatus = accountMismatch ? 'failed' : verdict.status;");
  });

  it('the mismatch explanation takes precedence over the capability summary', () => {
    expect(PERMISSIONS).toContain('error_message: accountMismatchMessage ?? (');
  });

  it('validation actually selects the account id it compares', () => {
    // The two selects feeding runConnectionValidation omitted
    // aws_account_id entirely, so the comparison had nothing to compare.
    const selects = PERMISSIONS.match(/select: 'id[^']*'/g) ?? [];
    const feedingValidation = selects.filter((s) => s.includes('credentials_encrypted'));
    expect(feedingValidation.length).toBeGreaterThanOrEqual(2);
    for (const s of feedingValidation) expect(s, s).toContain('aws_account_id');
  });

  it('the placeholder is refused before a connection can be created with it', () => {
    expect(ACCOUNTS).toMatch(/\/\^0\{12\}\$\/\.test\(body\.awsAccountId\)/);
  });
});
