/**
 * Does this connection's stated AWS account match the one its credentials
 * actually belong to?
 *
 * WHY THIS EXISTS
 *
 * STS answers `GetCallerIdentity` with the account the credentials belong to,
 * and validation was RECORDING that as `identity_account_id` without ever
 * comparing it to `cloud_connections.aws_account_id`.
 *
 * Production carries the consequence: 10 ACCOUNT_MISMATCH quarantine records
 * from 2026-09-10 reading "Resource belongs to AWS account 604179600483, but
 * this connection is bound to 000000000000." A connection collected a real
 * estate under a placeholder id, admission refused every single resource it
 * read, and validation reported success throughout. A scan ran to completion
 * and produced nothing but quarantine rows.
 *
 * Keys for a DIFFERENT account authenticate perfectly well, which is what
 * makes this quiet: nothing fails, and the connection simply points at another
 * estate while every screen keeps showing the original account's name and
 * history. Credential rotation already refuses this for exactly that reason;
 * this applies the same rule at validation, where the binding is first
 * checkable.
 */

export type AccountBinding =
  /** Stated and observed ids agree. */
  | { state: 'matched'; accountId: string }
  /** They disagree — every resource collected will be refused admission. */
  | { state: 'mismatched'; claimed: string; observed: string; message: string }
  /**
   * The check could not be made. NOT the same as matched, and never reported
   * as though it were: a connection with no stated id, or an STS response with
   * no account, has not been shown to be correctly bound.
   */
  | { state: 'unverified'; reason: 'no_claimed_account' | 'no_observed_account' };

/** AWS's all-zeros placeholder. Twelve digits, passes every format check, is not an account. */
export function isPlaceholderAccountId(value: string | null | undefined): boolean {
  return typeof value === 'string' && /^0{12}$/.test(value.trim());
}

export function checkAccountBinding(
  claimedAccountId: string | null | undefined,
  observedAccountId: string | null | undefined,
): AccountBinding {
  const claimed = claimedAccountId?.trim() || null;
  const observed = observedAccountId?.trim() || null;

  if (!claimed) return { state: 'unverified', reason: 'no_claimed_account' };
  if (!observed) return { state: 'unverified', reason: 'no_observed_account' };
  if (claimed === observed) return { state: 'matched', accountId: claimed };

  return {
    state: 'mismatched',
    claimed,
    observed,
    // Says what is wrong, what it costs, and both ways to fix it. Account ids
    // are not secret -- admission already names them in its own quarantine
    // detail, and a message that withholds them cannot be acted on.
    message:
      `These credentials belong to AWS account ${observed}, but this connection is bound to ${claimed}. `
      + 'Every resource collected with them is refused as an account mismatch, so nothing reaches inventory. '
      + 'Correct the account id on the connection, or connect credentials for the account it names.',
  };
}
