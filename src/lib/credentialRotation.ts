import type { Db } from '@horizonvigil/shared-lib';
import type { Env } from '../env';
import { encryptCredentials, maskAccessKey } from './crypto';
import { checkCallerIdentity } from './permissionChecks';

/**
 * Validate-before-activate credential rotation (§5, AWS-P0-03).
 *
 * The defect: the credential update endpoint encrypted the NEW keys straight
 * over `cloud_connections.credentials_encrypted`, set the connection to
 * `pending`, and relied on some later validation to notice a problem. So a
 * typo took a working connection down, and the old credential — the one that
 * worked — had already been destroyed. There was no candidate state, no
 * atomic cutover, and nothing to roll back to.
 *
 * The order here is the whole fix:
 *   1. prove the candidate authenticates, and against the RIGHT account
 *   2. archive the outgoing secret so rollback is possible
 *   3. only then swap
 *
 * A failed candidate never touches the live connection.
 */

export interface RotationResult {
  ok: boolean;
  /** Stable machine code so the UI can explain the failure without parsing prose. */
  code?: 'candidate_authentication_failed' | 'candidate_account_mismatch' | 'no_active_credential';
  message?: string;
  identityArn?: string | null;
  accountId?: string | null;
  versionId?: string;
}

/**
 * Proves a candidate credential before it is allowed anywhere near the
 * connection.
 *
 * The account-match check is not ceremony: pasting the keys of a DIFFERENT
 * AWS account authenticates perfectly well, and would silently repoint the
 * connection at someone else's estate while every screen kept the original
 * account's name and history. That is a tenancy failure wearing the costume
 * of a successful rotation.
 */
export async function validateCandidate(
  env: Env,
  candidate: { accessKeyId: string; secretAccessKey: string },
  expectedAccountId: string,
): Promise<RotationResult> {
  const { result, identity } = await checkCallerIdentity({
    accessKeyId: candidate.accessKeyId,
    secretAccessKey: candidate.secretAccessKey,
  });

  if (result.status !== 'granted' || !identity) {
    return {
      ok: false,
      code: 'candidate_authentication_failed',
      // result.detail is AWS's own sanitized message; it never contains the secret.
      message: `The new credentials were rejected by AWS: ${result.detail}`,
    };
  }

  if (identity.accountId && expectedAccountId && identity.accountId !== expectedAccountId) {
    return {
      ok: false,
      code: 'candidate_account_mismatch',
      message: `Those credentials belong to AWS account ${identity.accountId}, but this connection is for ${expectedAccountId}. Rotating would silently repoint this connection at a different account.`,
      accountId: identity.accountId,
    };
  }

  return { ok: true, identityArn: identity.arn, accountId: identity.accountId };
}

/**
 * Atomically cuts over to a validated candidate, archiving the outgoing
 * secret first so the change is reversible.
 *
 * `credential_versions` carries a partial unique index allowing at most one
 * `active` row per connection, so "two live credentials" is unrepresentable
 * rather than merely unlikely — the retire must land before the activate.
 */
export async function activateCandidate(
  db: Db,
  env: Env,
  input: {
    orgId: string;
    connectionId: string;
    actorId: string | null;
    candidate: { accessKeyId: string; secretAccessKey: string };
    identityArn: string | null;
    accountId: string | null;
    /** The blob currently live on the connection, archived for rollback. */
    outgoingEncrypted: unknown;
  },
): Promise<string> {
  const encrypted = await encryptCredentials(env.ENCRYPTION_KEY, input.candidate);
  // All state transitions and the live credential replacement must happen in
  // one database transaction. A sequence of client-side REST writes can be
  // interrupted between any two calls, leaving the version history and the
  // credential actually used by the connection disagreeing.
  return db.rpc<string>('rotate_aws_access_key', {
    p_org_id: input.orgId,
    p_connection_id: input.connectionId,
    p_actor_id: input.actorId,
    p_credentials_encrypted: encrypted,
    p_masked_access_key: maskAccessKey(input.candidate.accessKeyId),
    p_identity_arn: input.identityArn,
    p_account_id: input.accountId,
    p_outgoing_credentials_encrypted: input.outgoingEncrypted,
  });
}

/**
 * Restores the most recently retired credential.
 *
 * Only possible because activation archived the outgoing blob; without that
 * step "rollback" would be a button that cannot do anything.
 */
export async function rollbackToPrevious(db: Db, connectionId: string): Promise<RotationResult> {
  const retiring = await db.select<{ id: string; credentials_encrypted: unknown; nonsecret_identity_metadata: { maskedAccessKey?: string } }[]>(
    'credential_versions',
    {
      select: 'id,credentials_encrypted,nonsecret_identity_metadata',
      filters: { connection_id: `eq.${connectionId}`, status: 'eq.retiring' },
      order: 'retired_at.desc',
      limit: 1,
    },
  );
  const previous = retiring[0];
  if (!previous?.credentials_encrypted) {
    return { ok: false, code: 'no_active_credential', message: 'There is no archived previous credential to roll back to.' };
  }

  const versionId = await db.rpc<string>('rollback_aws_access_key', {
    p_connection_id: connectionId,
    p_previous_version_id: previous.id,
  });
  return { ok: true, versionId };
}
