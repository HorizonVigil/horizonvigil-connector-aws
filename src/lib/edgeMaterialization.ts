import type { Db } from '@horizonvigil/shared-lib';

interface ResourceRow { id: string; resource_type_key: string; relationships: Record<string, unknown> | null }
interface IdentityRow { id: string; identity_type: string; native_label: string | null; display_name: string | null }

export interface EdgeRow {
  connection_id: string;
  source_resource_id: string | null; source_identity_id: string | null;
  target_resource_id: string | null; target_identity_id: string | null;
  relationship_type: string; confidence: number; source_engine: string;
  metadata: Record<string, unknown>; last_seen_at: string; deleted_at: null;
}

/**
 * Derives cloud_resource_edges rows from resource/identity data already
 * sitting in cloud_resources.relationships and cloud_identities -- no new
 * API calls, same "reshape what was already fetched" convention as
 * extractMonitoringAlarmRows/extractCloudIdentityRows. Runs once per full
 * scan cycle (called from runFinalize, not per-step) because the resources
 * and identities it joins are scanned by different steps (lambda.ts,
 * eks.ts, iam.ts) that don't run in a fixed order relative to each other --
 * deriving edges mid-scan could see a Lambda before its role has been
 * scanned yet, or vice versa.
 *
 * Scope for this first pass: exactly the two relationships the
 * attack_path_findings RPC already computes ad hoc as a hand-written SQL
 * CASE/join (ASSUMES, for lambda_function/eks_cluster/eks_nodegroup →
 * their execution role) plus one more real relationship already sitting
 * unused in scanner output (CONTAINS, for iam_instance_profile → the
 * role(s) it wraps). This is deliberately not "every one of the 19
 * relationship types" on day one -- HAS_PERMISSION (needs full policy
 * resolution), CAN_ACCESS, STORES_DATA etc. are real future work, not
 * fabricated here just to populate more rows.
 */
export async function materializeResourceEdges(db: Db, connectionId: string): Promise<{ edgeCount: number }> {
  const [resources, identities] = await Promise.all([
    db.select<ResourceRow[]>('cloud_resources', {
      select: 'id,resource_type_key,relationships',
      filters: { connection_id: `eq.${connectionId}`, resource_type_key: 'in.(lambda_function,eks_cluster,eks_nodegroup,iam_instance_profile)', deleted_at: 'is.null' },
      limit: 10000,
    }),
    db.select<IdentityRow[]>('cloud_identities', {
      select: 'id,identity_type,native_label,display_name',
      filters: { connection_id: `eq.${connectionId}`, identity_type: 'eq.role', deleted_at: 'is.null' },
      limit: 10000,
    }),
  ]);
  if (resources.length === 0 || identities.length === 0) return { edgeCount: 0 };

  const roleByArn = new Map(identities.filter((i) => i.native_label).map((i) => [i.native_label as string, i.id]));
  const roleByName = new Map(identities.filter((i) => i.display_name).map((i) => [i.display_name as string, i.id]));

  const now = new Date().toISOString();
  const edges: EdgeRow[] = [];
  const pushAssumes = (resourceId: string, roleArn: unknown, engine: string) => {
    if (typeof roleArn !== 'string') return;
    const identityId = roleByArn.get(roleArn);
    if (!identityId) return;
    edges.push({
      connection_id: connectionId, source_resource_id: resourceId, source_identity_id: null,
      target_resource_id: null, target_identity_id: identityId,
      relationship_type: 'ASSUMES', confidence: 1.0, source_engine: engine,
      metadata: { roleArn }, last_seen_at: now, deleted_at: null,
    });
  };

  for (const r of resources) {
    const rel = r.relationships ?? {};
    if (r.resource_type_key === 'lambda_function') pushAssumes(r.id, rel.roleArn, 'lambda');
    else if (r.resource_type_key === 'eks_cluster') pushAssumes(r.id, rel.roleArn, 'eks');
    else if (r.resource_type_key === 'eks_nodegroup') pushAssumes(r.id, rel.nodeRoleArn, 'eks');
    else if (r.resource_type_key === 'iam_instance_profile') {
      const roleNames = Array.isArray(rel.roleNames) ? (rel.roleNames as unknown[]) : [];
      for (const name of roleNames) {
        if (typeof name !== 'string') continue;
        const identityId = roleByName.get(name);
        if (!identityId) continue;
        edges.push({
          connection_id: connectionId, source_resource_id: r.id, source_identity_id: null,
          target_resource_id: null, target_identity_id: identityId,
          relationship_type: 'CONTAINS', confidence: 1.0, source_engine: 'iam_instance_profile',
          metadata: { roleName: name }, last_seen_at: now, deleted_at: null,
        });
      }
    }
  }

  if (edges.length === 0) return { edgeCount: 0 };

  // source_key/target_key are generated stored columns (coalesce of the
  // resource/identity pair) specifically so PostgREST's on_conflict -- which
  // can only target real column names, never an arbitrary expression -- has
  // something to reference; see the migration that added them for why the
  // first attempt here (an expression-based unique index) couldn't work.
  await db.insert(
    'cloud_resource_edges?on_conflict=connection_id,source_key,target_key,relationship_type',
    edges,
    'resolution=merge-duplicates,return=minimal',
  );
  return { edgeCount: edges.length };
}
