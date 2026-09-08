import { errJson } from '@horizonvigil/shared-lib';

/**
 * Fail-closed gate for direct provider mutation (Phase 0.5 of the
 * 2026-09-08 all-cloud production-readiness work).
 *
 * Both audits are unambiguous on this:
 *   "No direct provider mutation ships in V1."
 *   "Optimization can offer automated resize using the same credential used
 *    for collection if it happens to have EC2 write permission."
 *   "Remove from V1 - P0. Offer manual guide, ticket, or IaC draft only
 *    until execution credentials and governance are certified."
 *
 * The concrete risk is real, not theoretical: this service's remediation
 * pathway calls StopInstances / ModifyInstanceAttribute / StartInstances /
 * ReleaseAddress using the SAME stored connection credential used for
 * read-only collection. There is no separate execution identity, no
 * certified worker, no canary, no emergency stop, and no provider-verified
 * outcome -- so the safety contract the audits require around a mutating
 * action does not exist yet.
 *
 * The ENTIRE remediation capability is gated, not just the three mutating
 * endpoints, because gating only execute/finish-resize/rollback would leave
 * request/approve reachable -- a workflow a user could start but never
 * finish, which the implementation prompt explicitly forbids ("Never expose
 * half of a workflow or a UI action whose server behavior is not
 * complete").
 *
 * OFF unless PROVIDER_REMEDIATION_ENABLED === 'true', so an unset variable
 * on any environment denies rather than exposes.
 */
export function isProviderRemediationEnabled(env: unknown): boolean {
  return (env as { PROVIDER_REMEDIATION_ENABLED?: string } | null)?.PROVIDER_REMEDIATION_ENABLED === 'true';
}

/** Stable, machine-parseable denial that discloses no request, resource or credential detail. */
export function remediationDisabledResponse(): Response {
  return errJson(403, 'entitlement_required: provider_remediation');
}

/**
 * Fail-closed gate for permanent connection purge (Phase 0.6).
 *
 * 2026-09-08 audits, P0: "'Delete Permanently' removes a connection,
 * resources, and history after one generic Confirm click" and "Bulk delete
 * can permanently remove several accounts and all history without listing
 * names, dependencies, retention/legal-hold effects, or requiring typed
 * confirmation" -> disposition "Disable by default - P0", and the Days 0-7
 * containment step "Disable permanent purge and unsafe bulk actions."
 *
 * The endpoint issues an immediate cascading DELETE across every table with
 * a connection_id FK. None of the controls the audits require exist yet:
 * no impact preview or authoritative object counts, no dependency/retention
 * or legal-hold check, no typed confirmation, no recent-MFA reauthentication,
 * no If-Match/idempotency key, no asynchronous checkpointed purge job, no
 * per-item result, and no recovery window.
 *
 * Disconnect (DELETE /accounts/:id) is unaffected and remains the supported
 * way to stop collection -- it is a reversible status flip that preserves
 * history, so gating purge does not strand anyone.
 *
 * OFF unless CONNECTION_PURGE_ENABLED === 'true'.
 */
export function isConnectionPurgeEnabled(env: unknown): boolean {
  return (env as { CONNECTION_PURGE_ENABLED?: string } | null)?.CONNECTION_PURGE_ENABLED === 'true';
}

/** Stable denial that discloses no connection name, id, or object count. */
export function purgeDisabledResponse(): Response {
  return errJson(403, 'entitlement_required: connection_purge');
}
