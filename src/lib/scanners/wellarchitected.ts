import { createAwsClient } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const WELLARCHITECTED_RESOURCE_TYPES = ['well_architected_workload'] as const;

interface WorkloadSummary {
  WorkloadArn: string; WorkloadId?: string; WorkloadName?: string; Owner?: string; ImprovementStatus?: string;
  Lenses?: string[]; UpdatedAt?: number; RiskCounts?: Record<string, number>;
}
interface ListWorkloadsResponse { WorkloadSummaries?: WorkloadSummary[] }

/** AWS Well-Architected Tool — REST-JSON, POST /workloadsSummaries (confirmed against AWS's API reference). */
export async function scanWellArchitected(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'wellarchitected', ctx.region);
  const res = await client.fetch(`https://wellarchitected.${ctx.region}.amazonaws.com/workloadsSummaries`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
  });
  const text = await res.text();
  if (!res.ok) {
    console.error(`Well-Architected ListWorkloads failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const workloads = ((text ? JSON.parse(text) : {}) as ListWorkloadsResponse).WorkloadSummaries ?? [];
  return workloads.map((w) => ({
    resourceTypeKey: 'well_architected_workload', resourceId: w.WorkloadArn, region: ctx.region, resourceName: w.WorkloadName,
    state: w.ImprovementStatus, metadata: { owner: w.Owner, lenses: w.Lenses, updatedAt: w.UpdatedAt, riskCounts: w.RiskCounts },
  }));
}
