/**
 * AWS-10 — network topology edges from direct provider references.
 *
 * The existing materialiser covers workload-to-IAM-role relationships, which
 * is correct but starved here: this estate holds 1 EC2 instance, 0 Lambdas
 * and 0 EKS clusters, so it produced 3 edges fleet-wide.
 *
 * Meanwhile the types that DO have volume all carry populated
 * `relationships`: 113 subnets, 61 security groups, 35 VPCs. Every one of
 * those payloads is a field AWS returned directly —
 *
 *   subnet          { vpcId }
 *   security_group  { vpcId }
 *   ec2_instance    { vpcId, subnetId, securityGroupIds[], ... }
 *   ebs_volume      { attachedInstanceIds[] }
 *
 * — so these are DIRECT_PROVIDER_REFERENCE edges at confidence 1.0, not
 * inferences. Building the graph from data already fetched is the same
 * "reshape what was already collected" rule the rest of this file follows;
 * it costs no additional provider calls.
 */
import type { Db } from '@horizonvigil/shared-lib';
import type { EdgeRelationshipType } from './edgeVocabulary';

export interface TopologyEdge {
  connection_id: string;
  source_resource_id: string | null;
  source_identity_id: null;
  target_resource_id: string | null;
  target_identity_id: null;
  /**
   * Typed, not `string`. The first cut of this file emitted CONTAINED_BY,
   * ATTACHED_TO and PROTECTED_BY as bare strings; the database permitted
   * none of them, so every insert raised 23514 and the best-effort caller
   * turned a total write failure into an empty graph. See edgeVocabulary.ts.
   */
  relationship_type: EdgeRelationshipType;
  confidence: number;
  source_engine: string;
  metadata: Record<string, unknown>;
  last_seen_at: string;
  deleted_at: null;
}

interface TopologyResource {
  id: string;
  resource_type_key: string;
  resource_id: string;
  relationships: Record<string, unknown> | null;
}

/** Types whose provider payload carries a resolvable reference. */
export const TOPOLOGY_TYPES = ['vpc', 'subnet', 'security_group', 'ec2_instance', 'ebs_volume'] as const;

const asString = (v: unknown): string | null => (typeof v === 'string' && v.trim() !== '' ? v : null);
const asStringArray = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.trim() !== '') : [];

/**
 * Builds topology edges from already-fetched resources.
 *
 * Pure so the rules are testable without a database — the edge set this
 * produces is the part worth asserting, not the SQL that stores it.
 *
 * **An edge is only emitted when BOTH ends resolve to a canonical resource
 * this connection has actually discovered.** A reference to a VPC we have
 * never seen is a dangling assertion, and a graph that contains edges to
 * resources the inventory cannot show is worse than a smaller honest graph:
 * every downstream traversal would hit a target it cannot render.
 */
export function buildTopologyEdges(
  connectionId: string,
  resources: readonly TopologyResource[],
  now: string,
): TopologyEdge[] {
  // Native provider id -> canonical row id, per type. Keyed by type as well
  // as id because AWS native ids are only unique within their own namespace.
  const byTypeAndNative = new Map<string, string>();
  for (const r of resources) byTypeAndNative.set(`${r.resource_type_key}:${r.resource_id}`, r.id);

  const edges: TopologyEdge[] = [];
  const push = (
    sourceId: string,
    targetType: string,
    targetNative: string | null,
    relationship: EdgeRelationshipType,
    engine: string,
  ) => {
    if (!targetNative) return;
    const targetId = byTypeAndNative.get(`${targetType}:${targetNative}`);
    // Unresolved target: the reference is real but the resource is not in
    // our inventory. Skipped deliberately rather than stored with a null end.
    if (!targetId || targetId === sourceId) return;
    edges.push({
      connection_id: connectionId,
      source_resource_id: sourceId,
      source_identity_id: null,
      target_resource_id: targetId,
      target_identity_id: null,
      relationship_type: relationship,
      // Read directly off a provider API field. Nothing here is inferred.
      confidence: 1.0,
      source_engine: engine,
      metadata: { via: 'direct_provider_reference', targetNativeId: targetNative },
      last_seen_at: now,
      deleted_at: null,
    });
  };

  for (const r of resources) {
    const rel = r.relationships ?? {};
    switch (r.resource_type_key) {
      // BELONGS_TO, not CONTAINED_BY. The database's vocabulary already had
      // the inverse of CONTAINS; adding a synonym would force every consumer
      // to check two names for one relationship forever.
      case 'subnet':
        push(r.id, 'vpc', asString(rel.vpcId), 'BELONGS_TO', 'vpc');
        break;
      case 'security_group':
        push(r.id, 'vpc', asString(rel.vpcId), 'BELONGS_TO', 'vpc');
        break;
      case 'ec2_instance':
        push(r.id, 'vpc', asString(rel.vpcId), 'BELONGS_TO', 'ec2');
        // Placement, not attachment: an instance is launched into a subnet
        // and cannot be moved between subnets while it exists, so this is a
        // different relationship from the detachable volume binding below.
        push(r.id, 'subnet', asString(rel.subnetId), 'DEPLOYED_TO', 'ec2');
        for (const sg of asStringArray(rel.securityGroupIds)) {
          push(r.id, 'security_group', sg, 'PROTECTED_BY', 'ec2');
        }
        break;
      case 'ebs_volume':
        for (const instanceId of asStringArray(rel.attachedInstanceIds)) {
          push(r.id, 'ec2_instance', instanceId, 'ATTACHED_TO', 'ebs');
        }
        break;
      default:
        break;
    }
  }
  return edges;
}

/**
 * Reads the topology resources for a connection and persists their edges.
 *
 * Only ACTIVE, non-deleted rows are considered. An edge must bind to the
 * generation that is live now — pointing at a tombstoned generation would
 * recreate the history-merging defect AWS-09 closed.
 */
export async function materializeNetworkTopology(db: Db, connectionId: string): Promise<{ edgeCount: number }> {
  const resources = await db.select<TopologyResource[]>('cloud_resources', {
    select: 'id,resource_type_key,resource_id,relationships',
    filters: {
      connection_id: `eq.${connectionId}`,
      resource_type_key: `in.(${TOPOLOGY_TYPES.join(',')})`,
      deleted_at: 'is.null',
      lifecycle_state: 'eq.ACTIVE',
    },
    limit: 10000,
  });
  if (resources.length === 0) return { edgeCount: 0 };

  const edges = buildTopologyEdges(connectionId, resources, new Date().toISOString());
  if (edges.length === 0) return { edgeCount: 0 };

  await db.insert(
    'cloud_resource_edges?on_conflict=connection_id,source_key,target_key,relationship_type',
    edges,
    'resolution=merge-duplicates,return=minimal',
  );
  return { edgeCount: edges.length };
}
