import { describe, it, expect } from 'vitest';
import { computeClusterAllocation, type NodeInput, type PodInput } from './k8sCostAllocation';

function node(overrides: Partial<NodeInput> & Pick<NodeInput, 'nodeName'>): NodeInput {
  return { allocatableCpuMillicores: 4000, monthlyCost: 100, ...overrides };
}
function pod(overrides: Partial<PodInput> & Pick<PodInput, 'podName' | 'namespace'>): PodInput {
  return { nodeName: 'node-1', cpuRequestMillicores: 0, hasResourceRequest: false, ...overrides };
}

describe('computeClusterAllocation', () => {
  it('allocates node cost proportionally to CPU request share', () => {
    const nodes = [node({ nodeName: 'node-1', allocatableCpuMillicores: 4000, monthlyCost: 100 })];
    const pods = [
      pod({ podName: 'p1', namespace: 'default', cpuRequestMillicores: 1000, hasResourceRequest: true }), // 25% -> $25
      pod({ podName: 'p2', namespace: 'default', cpuRequestMillicores: 3000, hasResourceRequest: true }), // 75% -> $75
    ];
    const result = computeClusterAllocation(nodes, pods);
    expect(result.pods.find((p) => p.podName === 'p1')?.monthlyCost).toBe(25);
    expect(result.pods.find((p) => p.podName === 'p2')?.monthlyCost).toBe(75);
    expect(result.totalAllocatedCost).toBe(100);
    expect(result.totalIdleCost).toBe(0);
  });

  it('the idle remainder sums correctly when pods do not fully request a node\'s allocatable capacity', () => {
    const nodes = [node({ nodeName: 'node-1', allocatableCpuMillicores: 4000, monthlyCost: 100 })];
    const pods = [pod({ podName: 'p1', namespace: 'default', cpuRequestMillicores: 1000, hasResourceRequest: true })]; // 25% -> $25
    const result = computeClusterAllocation(nodes, pods);
    expect(result.totalNodeCost).toBe(100);
    expect(result.totalAllocatedCost).toBe(25);
    expect(result.totalIdleCost).toBe(75);
  });

  it('excludes a pod with no declared CPU request rather than assigning it a $0 share that looks like a real answer', () => {
    const nodes = [node({ nodeName: 'node-1' })];
    const pods = [pod({ podName: 'p1', namespace: 'default', hasResourceRequest: false, cpuRequestMillicores: 0 })];
    const result = computeClusterAllocation(nodes, pods);
    expect(result.excludedPodCount).toBe(1);
    expect(result.pods[0].monthlyCost).toBeNull();
    expect(result.pods[0].excludedReason).toBe('no_cpu_request');
    // Its node's cost is untouched -- folds into idle, not zeroed or dropped.
    expect(result.totalIdleCost).toBe(100);
  });

  it('excludes a Fargate-style pod with no matching node (no fabricated cost)', () => {
    const nodes: NodeInput[] = [];
    const pods = [pod({ podName: 'p1', namespace: 'default', nodeName: 'fargate-ip-10-0-0-1', cpuRequestMillicores: 500, hasResourceRequest: true })];
    const result = computeClusterAllocation(nodes, pods);
    expect(result.excludedPodCount).toBe(1);
    expect(result.pods[0].excludedReason).toBe('no_matching_node');
    expect(result.totalAllocatedCost).toBe(0);
  });

  it('excludes pods on a node whose cost could not be resolved (CUR and Pricing API both unavailable)', () => {
    const nodes = [node({ nodeName: 'node-1', monthlyCost: null })];
    const pods = [pod({ podName: 'p1', namespace: 'default', cpuRequestMillicores: 1000, hasResourceRequest: true })];
    const result = computeClusterAllocation(nodes, pods);
    expect(result.excludedPodCount).toBe(1);
    expect(result.pods[0].excludedReason).toBe('node_cost_unavailable');
    expect(result.excludedNodeCount).toBe(1);
    expect(result.totalNodeCost).toBe(0); // the unresolved node contributes nothing, not a guess
  });

  it('rolls pod cost up to its resolved Deployment (via the ReplicaSet hop), not a raw ReplicaSet name', () => {
    const nodes = [node({ nodeName: 'node-1', allocatableCpuMillicores: 2000, monthlyCost: 60 })];
    const pods = [
      pod({ podName: 'web-7d9f8c6b5d-abcde', namespace: 'prod', cpuRequestMillicores: 1000, hasResourceRequest: true, workloadOwner: { kind: 'Deployment', name: 'web' } }),
      pod({ podName: 'web-7d9f8c6b5d-fghij', namespace: 'prod', cpuRequestMillicores: 1000, hasResourceRequest: true, workloadOwner: { kind: 'Deployment', name: 'web' } }),
    ];
    const result = computeClusterAllocation(nodes, pods);
    expect(result.byWorkload).toHaveLength(1);
    expect(result.byWorkload[0]).toMatchObject({ kind: 'Deployment', name: 'web', namespace: 'prod', monthlyCost: 60, podCount: 2 });
  });

  it('rolls pod cost up by namespace', () => {
    const nodes = [node({ nodeName: 'node-1', allocatableCpuMillicores: 2000, monthlyCost: 40 })];
    const pods = [
      pod({ podName: 'p1', namespace: 'team-a', cpuRequestMillicores: 1000, hasResourceRequest: true }),
      pod({ podName: 'p2', namespace: 'team-b', cpuRequestMillicores: 1000, hasResourceRequest: true }),
    ];
    const result = computeClusterAllocation(nodes, pods);
    const teamA = result.byNamespace.find((n) => n.namespace === 'team-a');
    const teamB = result.byNamespace.find((n) => n.namespace === 'team-b');
    expect(teamA?.monthlyCost).toBe(20);
    expect(teamB?.monthlyCost).toBe(20);
  });

  it('sums total node cost across multiple nodes, including ones with no scheduled pods', () => {
    const nodes = [
      node({ nodeName: 'node-1', monthlyCost: 50 }),
      node({ nodeName: 'node-2', monthlyCost: 30 }), // no pods land here -- fully idle
    ];
    const pods = [pod({ podName: 'p1', namespace: 'default', nodeName: 'node-1', cpuRequestMillicores: 4000, hasResourceRequest: true })];
    const result = computeClusterAllocation(nodes, pods);
    expect(result.totalNodeCost).toBe(80);
    expect(result.totalAllocatedCost).toBe(50);
    expect(result.totalIdleCost).toBe(30);
  });
});
