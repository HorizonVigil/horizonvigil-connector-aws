/**
 * Explainable account health (spec §8, §37).
 *
 * Every input here is an existing `cloud_connections` column plus the single
 * latest `connection_validation_runs` row — nothing new is stored, and the
 * score is a documented weighted roll-up of five named signals, never an
 * opaque number:
 *
 *   connection      (35) — is the connection itself in a good state?
 *   permissions     (25) — did the last real permission-validation pass?
 *   discovery       (15) — has resource discovery ever completed?
 *   sync_freshness  (15) — how long since the last successful sync?
 *   credentials     (10) — are long-lived keys within their rotation window?
 *
 * score = Σ(weight · signalScore) / Σ(weight of non-unknown signals) · 100
 * where signalScore is ok→1, warn→0.5, fail→0. Signals whose state can't be
 * determined yet (e.g. a brand-new pending connection) are excluded from the
 * denominator rather than counted against the account; if every signal is
 * unknown the state is `unknown`, not a low score.
 *
 * This module is deliberately duplicated (not shared) into connector-azure
 * and connector-gcp — same convention as crypto.ts / discoveryFinalize.ts.
 * Pure and fully unit-tested (health.test.ts).
 */

export type HealthState = 'healthy' | 'warning' | 'critical' | 'unknown';
export type SignalStatus = 'ok' | 'warn' | 'fail' | 'unknown';

export interface HealthSignal {
  key: 'connection' | 'permissions' | 'discovery' | 'sync_freshness' | 'credentials';
  label: string;
  status: SignalStatus;
  detail: string;
  weight: number;
}

export interface AccountHealth {
  connectionId: string;
  /**
   * 0-100, or NULL when there is no basis for a score at all.
   *
   * Null rather than 0 because 0 reads as "scored, and terrible" -- the
   * audit caught a DISCONNECTED account reporting score 100 with state
   * 'unknown', which is worse still. Per the capability-health standard,
   * disconnected and suspended connections have no health score and do not
   * contribute to provider-level health.
   */
  score: number | null;
  state: HealthState;
  signals: HealthSignal[];
}

export interface HealthConnectionInput {
  id: string;
  status: string; // pending | connected | error | disconnected | expired
  connection_method: string; // access_key | cross_account_role | service_account_key | ...
  error_message: string | null;
  last_sync_at: string | null;
  last_discovery_at: string | null;
  last_permission_check_at: string | null;
  key_rotated_at: string | null;
}

export interface HealthValidationInput {
  status: string; // running | succeeded | failed
  finished_at: string | null;
  error_message: string | null;
  deniedChecks?: number;
  erroredChecks?: number;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** connection methods that mean "no long-lived secret to rotate". */
const KEYLESS_METHODS = new Set(['cross_account_role', 'service_account_impersonation', 'client_certificate']);

function ageDays(iso: string | null, now: number): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  return Number.isNaN(t) ? null : Math.max(0, Math.floor((now - t) / DAY_MS));
}

function connectionSignal(conn: HealthConnectionInput): HealthSignal {
  const base = { key: 'connection' as const, label: 'Connection', weight: 35 };
  switch (conn.status) {
    case 'disconnected':
      return { ...base, status: 'unknown', detail: 'This connection is disconnected — health is not tracked for it.' };
    case 'error':
    case 'expired':
      return { ...base, status: 'fail', detail: conn.error_message || `Connection status is "${conn.status}".` };
    case 'pending':
      return { ...base, status: 'warn', detail: 'Connected but not yet validated — run permission validation.' };
    case 'connected':
      return conn.error_message
        ? { ...base, status: 'warn', detail: conn.error_message }
        : { ...base, status: 'ok', detail: 'Connected and reporting no errors.' };
    default:
      return { ...base, status: 'unknown', detail: `Unrecognized connection status "${conn.status}".` };
  }
}

function permissionsSignal(conn: HealthConnectionInput, run: HealthValidationInput | null): HealthSignal {
  const base = { key: 'permissions' as const, label: 'Permissions', weight: 25 };
  if (!run || !conn.last_permission_check_at) {
    return { ...base, status: 'unknown', detail: 'Permission validation has never been run for this connection.' };
  }
  if (run.status === 'running') {
    return { ...base, status: 'unknown', detail: 'A permission-validation run is currently in progress.' };
  }
  if (run.status === 'failed') {
    return { ...base, status: 'fail', detail: run.error_message || 'The last permission-validation run failed.' };
  }
  const denied = run.deniedChecks ?? 0;
  const errored = run.erroredChecks ?? 0;
  if (denied + errored > 0) {
    return { ...base, status: 'warn', detail: `Last validation passed overall, but ${denied} permission${denied === 1 ? '' : 's'} denied and ${errored} check${errored === 1 ? '' : 's'} errored.` };
  }
  return { ...base, status: 'ok', detail: 'Last permission validation passed with no denied checks.' };
}

function discoverySignal(conn: HealthConnectionInput, now: number): HealthSignal {
  const base = { key: 'discovery' as const, label: 'Discovery', weight: 15 };
  const age = ageDays(conn.last_discovery_at, now);
  if (age === null) {
    return { ...base, status: 'warn', detail: 'Resource discovery has never completed for this connection.' };
  }
  return { ...base, status: 'ok', detail: age === 0 ? 'Resource discovery completed today.' : `Resource discovery last completed ${age} day${age === 1 ? '' : 's'} ago.` };
}

function syncFreshnessSignal(conn: HealthConnectionInput, now: number): HealthSignal {
  const base = { key: 'sync_freshness' as const, label: 'Sync freshness', weight: 15 };
  const age = ageDays(conn.last_sync_at, now);
  if (age === null) {
    return { ...base, status: 'warn', detail: 'This connection has never completed a successful sync.' };
  }
  if (age < 1) return { ...base, status: 'ok', detail: 'Synced within the last 24 hours.' };
  if (age < 7) return { ...base, status: 'warn', detail: `Last synced ${age} day${age === 1 ? '' : 's'} ago.` };
  return { ...base, status: 'fail', detail: `Data is stale — last synced ${age} days ago.` };
}

function credentialsSignal(conn: HealthConnectionInput, now: number): HealthSignal {
  const base = { key: 'credentials' as const, label: 'Credentials', weight: 10 };
  if (KEYLESS_METHODS.has(conn.connection_method)) {
    return { ...base, status: 'ok', detail: 'Uses short-lived / keyless credentials — nothing to rotate.' };
  }
  const age = ageDays(conn.key_rotated_at, now);
  if (age === null) {
    // Rotation isn't tracked for every credential type (e.g. an Azure SP
    // secret) — don't count that against the account, just mark it unknown.
    return { ...base, status: 'unknown', detail: 'Long-lived credentials in use; their rotation date is not tracked.' };
  }
  if (age > 90) return { ...base, status: 'fail', detail: `Credentials are ${age} days old — rotation is overdue (90-day policy).` };
  if (age > 75) return { ...base, status: 'warn', detail: `Credentials are ${age} days old — rotation due soon.` };
  return { ...base, status: 'ok', detail: `Credentials rotated ${age} day${age === 1 ? '' : 's'} ago.` };
}

const SCORE_BY_STATUS: Record<SignalStatus, number | null> = { ok: 1, warn: 0.5, fail: 0, unknown: null };

export function computeHealth(
  conn: HealthConnectionInput,
  latestRun: HealthValidationInput | null,
  now: number = Date.now(),
): AccountHealth {
  const signals: HealthSignal[] = [
    connectionSignal(conn),
    permissionsSignal(conn, latestRun),
    discoverySignal(conn, now),
    syncFreshnessSignal(conn, now),
    credentialsSignal(conn, now),
  ];

  let weighted = 0;
  let denom = 0;
  for (const s of signals) {
    const v = SCORE_BY_STATUS[s.status];
    if (v === null) continue;
    weighted += v * s.weight;
    denom += s.weight;
  }

  // Nothing measurable at all: no score, rather than a 0 that reads as a
  // failing grade.
  if (denom === 0) {
    return { connectionId: conn.id, score: null, state: 'unknown', signals };
  }

  /**
   * A disconnected connection is not being collected from, so there is no
   * current evidence to score. Returning early means it cannot contribute a
   * number to any provider rollup either.
   *
   * The audit found this reported as `score: 100, state: unknown` -- the
   * state was corrected but the score was left, so an aggregate that read
   * `score` still saw a perfect account. AWS was summarised as 100% healthy
   * with one of two connections disconnected.
   */
  if (conn.status === 'disconnected') {
    return { connectionId: conn.id, score: null, state: 'unknown', signals };
  }

  const score = Math.round((weighted / denom) * 100);
  const connFail = signals.find((s) => s.key === 'connection')?.status === 'fail';
  // FIXED 2026-09-08 (live audit): excluding 'unknown' signals from the
  // denominator (rather than counting them against the account) was a
  // deliberate choice to avoid punishing brand-new connections -- but its
  // side effect is exactly what the audit caught live: a connection whose
  // permissions have NEVER been validated can still average its other four
  // signals to 100/'healthy', silently implying full health. Per the
  // capability-health standard this must satisfy ("unknown or never-run
  // checks cannot yield a perfect score"), any unknown signal caps the
  // achievable state at 'warning' -- the per-signal detail text already
  // says exactly which check was never run, this just stops the rollup
  // from hiding that behind a clean top-line score.
  const hasUnknownSignal = signals.some((s) => s.status === 'unknown');

  let state: HealthState;
  if (connFail) state = 'critical';
  else if (score >= 85) state = hasUnknownSignal ? 'warning' : 'healthy';
  else if (score >= 60) state = 'warning';
  else state = 'critical';

  return { connectionId: conn.id, score, state, signals };
}

/** Roll a set of per-account healths into the spec §6 counters. */
export function summarizeHealth(healths: AccountHealth[]): {
  total: number; healthy: number; warning: number; critical: number; unknown: number; healthPercent: number | null;
} {
  const counts = { total: healths.length, healthy: 0, warning: 0, critical: 0, unknown: 0 };
  for (const h of healths) counts[h.state]++;
  const rated = counts.total - counts.unknown;
  return {
    ...counts,
    healthPercent: rated === 0 ? null : Math.round((counts.healthy / rated) * 100),
  };
}
