import { describe, it, expect } from 'vitest';
import { buildTopologyEdges } from './networkTopology';

const NOW = '2026-09-15T00:00:00Z';
const CONN = 'conn-1';

const r = (id: string, type: string, native: string, relationships: Record<string, unknown> | null = null) =>
  ({ id, resource_type_key: type, resource_id: native, relationships });

describe('buildTopologyEdges — AWS-10', () => {
  const vpc = r('row-vpc', 'vpc', 'vpc-1');
  const subnet = r('row-subnet', 'subnet', 'subnet-1', { vpcId: 'vpc-1' });
  const sg = r('row-sg', 'security_group', 'sg-1', { vpcId: 'vpc-1' });
  const ec2 = r('row-ec2', 'ec2_instance', 'i-1', {
    vpcId: 'vpc-1', subnetId: 'subnet-1', securityGroupIds: ['sg-1'],
  });
  const vol = r('row-vol', 'ebs_volume', 'vol-1', { attachedInstanceIds: ['i-1'] });
  const all = [vpc, subnet, sg, ec2, vol];

  it('derives the full topology from direct provider references', () => {
    const edges = buildTopologyEdges(CONN, all, NOW);
    const shape = edges.map((e) => `${e.source_resource_id} -${e.relationship_type}-> ${e.target_resource_id}`).sort();
    // Every type below is in the database's CHECK vocabulary. The original
    // set named CONTAINED_BY and used ATTACHED_TO for subnet placement;
    // neither CONTAINED_BY nor PROTECTED_BY existed in the constraint, so
    // this exact assertion passed while every production insert raised
    // 23514. See edgeVocabulary.ts.
    expect(shape).toEqual([
      'row-ec2 -BELONGS_TO-> row-vpc',
      'row-ec2 -DEPLOYED_TO-> row-subnet',
      'row-ec2 -PROTECTED_BY-> row-sg',
      'row-sg -BELONGS_TO-> row-vpc',
      'row-subnet -BELONGS_TO-> row-vpc',
      'row-vol -ATTACHED_TO-> row-ec2',
    ]);
  });

  /**
   * These are read off provider API fields, not inferred, so they carry full
   * confidence. If a future rule guesses, it must not reuse this value —
   * presenting an inference as a provider-confirmed fact is NO-GO 10.
   */
  it('marks every edge as a direct provider reference at confidence 1.0', () => {
    for (const e of buildTopologyEdges(CONN, all, NOW)) {
      expect(e.confidence).toBe(1.0);
      expect(e.metadata.via).toBe('direct_provider_reference');
    }
  });

  /**
   * The load-bearing rule. A reference to something absent from inventory is
   * a dangling assertion — every downstream traversal would hit a target it
   * cannot render.
   */
  it('emits no edge when the target is not in inventory', () => {
    const orphan = r('row-subnet', 'subnet', 'subnet-9', { vpcId: 'vpc-does-not-exist' });
    expect(buildTopologyEdges(CONN, [orphan], NOW)).toEqual([]);
  });

  it('does not confuse native ids across types', () => {
    // Same native string, different namespaces. Resolving by id alone would
    // wire the subnet to the security group.
    const a = r('row-a', 'subnet', 'shared-id', { vpcId: 'shared-id' });
    const b = r('row-b', 'security_group', 'shared-id');
    expect(buildTopologyEdges(CONN, [a, b], NOW)).toEqual([]);
  });

  it('never emits a self-edge', () => {
    const selfref = r('row-x', 'subnet', 'vpc-1', { vpcId: 'vpc-1' });
    expect(buildTopologyEdges(CONN, [selfref], NOW)).toEqual([]);
  });

  it('handles missing, empty and malformed relationship payloads', () => {
    expect(buildTopologyEdges(CONN, [r('a', 'subnet', 's-1', null)], NOW)).toEqual([]);
    expect(buildTopologyEdges(CONN, [r('a', 'subnet', 's-1', {})], NOW)).toEqual([]);
    expect(buildTopologyEdges(CONN, [r('a', 'subnet', 's-1', { vpcId: 42 })], NOW)).toEqual([]);
    expect(buildTopologyEdges(CONN, [r('a', 'ec2_instance', 'i-1', { securityGroupIds: 'sg-1' })], NOW)).toEqual([]);
  });

  it('emits one edge per security group on a multi-homed instance', () => {
    const sg2 = r('row-sg2', 'security_group', 'sg-2', { vpcId: 'vpc-1' });
    const multi = r('row-ec2', 'ec2_instance', 'i-1', { securityGroupIds: ['sg-1', 'sg-2'] });
    const edges = buildTopologyEdges(CONN, [vpc, sg, sg2, multi], NOW);
    const protectedBy = edges.filter((e) => e.relationship_type === 'PROTECTED_BY');
    expect(protectedBy.map((e) => e.target_resource_id).sort()).toEqual(['row-sg', 'row-sg2']);
  });

  it('skips unknown resource types rather than guessing at their payload', () => {
    expect(buildTopologyEdges(CONN, [r('a', 'kms_key', 'k-1', { vpcId: 'vpc-1' }), vpc], NOW)).toEqual([]);
  });
});
