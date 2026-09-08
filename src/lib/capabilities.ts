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
