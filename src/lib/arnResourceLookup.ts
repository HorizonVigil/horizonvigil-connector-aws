import type { Db } from '@horizonvigil/shared-lib';

interface CloudResourceRow {
  id: string;
  resource_id: string;
  resource_name: string | null;
}

/**
 * Best-effort batch match of findings' loosely-typed resourceArn values back
 * to real cloud_resources rows for this connection, in at most two DB round
 * trips regardless of how many findings are in the batch — this step
 * already runs under a Workers subrequest budget (see runMetricStep's
 * pre-batched instance lookup in discovery.ts for the established pattern),
 * applied here to a DB lookup instead of an AWS call.
 *
 * resourceArn is populated inconsistently across finding sources — a full
 * ARN for Security Hub/IAM Access Analyzer, but already the raw AWS-native
 * id for GuardDuty/AWS Config/Trusted Advisor — and cloud_resources
 * .resource_id itself varies by resource type (opaque IAM RoleId/UserId, a
 * bucket name, a full ARN, or a queue URL), so no single deterministic
 * parse covers every case. Each finding contributes up to two candidate
 * strings — the raw value as-is, and an ARN's trailing segment when it
 * looks like an ARN — matched first against resource_id (covers types whose
 * id IS the ARN, and raw short-id sources), then resource_name (covers IAM
 * role/user names, SQS queue names, OIDC/SAML provider names). A finding
 * whose candidates match nothing is simply absent from the returned map —
 * the caller keeps resource_id null exactly as before this ever ran; this
 * never blocks an insert.
 */
export async function resolveFindingResourceIds(
  db: Db,
  connectionId: string,
  rawValues: (string | null | undefined)[],
): Promise<Map<string, string>> {
  const candidateSet = new Set<string>();
  for (const raw of rawValues) {
    if (!raw) continue;
    candidateSet.add(raw);
    const trailing = trailingSegment(raw);
    if (trailing) candidateSet.add(trailing);
  }
  if (candidateSet.size === 0) return new Map();

  const inList = `in.(${[...candidateSet].map(quoteForIn).join(',')})`;

  const [byId, byName] = await Promise.all([
    db.select<CloudResourceRow[]>('cloud_resources', {
      select: 'id,resource_id,resource_name',
      filters: { connection_id: `eq.${connectionId}`, resource_id: inList, deleted_at: 'is.null' },
    }),
    db.select<CloudResourceRow[]>('cloud_resources', {
      select: 'id,resource_id,resource_name',
      filters: { connection_id: `eq.${connectionId}`, resource_name: inList, deleted_at: 'is.null' },
    }),
  ]);

  // Candidate string -> cloud_resources.id. resource_id matches are applied
  // second so they win over a resource_name match on the same candidate
  // string (a resource_id hit is unambiguous; a name could theoretically
  // collide across resource types).
  const byCandidate = new Map<string, string>();
  for (const row of byName) if (row.resource_name) byCandidate.set(row.resource_name, row.id);
  for (const row of byId) byCandidate.set(row.resource_id, row.id);

  const result = new Map<string, string>(); // original rawValue -> cloud_resources.id
  for (const raw of rawValues) {
    if (!raw) continue;
    const direct = byCandidate.get(raw);
    if (direct) {
      result.set(raw, direct);
      continue;
    }
    const trailing = trailingSegment(raw);
    if (trailing) {
      const viaTrailing = byCandidate.get(trailing);
      if (viaTrailing) result.set(raw, viaTrailing);
    }
  }
  return result;
}

/** `arn:aws:iam::123456789012:role/MyRole` -> `MyRole`. `arn:aws:s3:::my-bucket` -> `my-bucket`. Returns null for anything not ARN-shaped. */
function trailingSegment(value: string): string | null {
  if (!value.startsWith('arn:')) return null;
  const parts = value.split(':');
  if (parts.length < 6) return null;
  const resourcePart = parts.slice(5).join(':');
  const segments = resourcePart.split(/[/:]/).filter(Boolean);
  return segments.length > 0 ? segments[segments.length - 1] : null;
}

function quoteForIn(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}
