import { reportWalk, walkJsonRpc } from './restJson';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SSM_RESOURCE_TYPES = [
  'ssm_parameter', 'ssm_automation', 'ssm_document', 'ssm_managed_instance', 'ssm_maintenance_window', 'ssm_patch_baseline',
  'systems_manager_inventory',
] as const;

interface SsmParameter {
  Name: string; Type?: string; LastModifiedDate?: number; Version?: number; Tier?: string;
}
interface AutomationExecution {
  AutomationExecutionId: string; DocumentName?: string; AutomationExecutionStatus?: string; ExecutionStartTime?: number; ExecutionEndTime?: number;
}
interface SsmDocument {
  Name: string; DocumentType?: string; DocumentVersion?: string; Owner?: string; PlatformTypes?: string[];
}
interface ManagedInstance {
  InstanceId: string; PingStatus?: string; PlatformType?: string; PlatformName?: string; AgentVersion?: string; IPAddress?: string; ComputerName?: string;
}
interface MaintenanceWindow {
  WindowId: string; Name?: string; Enabled?: boolean; Duration?: number; Cutoff?: number;
}
interface PatchBaseline {
  BaselineId: string; BaselineName?: string; OperatingSystem?: string;
}

/**
 * Parameters, plus five more account/region-scoped resource types — all
 * JSON-RPC, same signer, one call each. Owner='Self' on ListDocuments
 * mirrors iam.ts's Scope=Local reasoning: without it, AWS's own ~1,500+
 * published documents would swamp the inventory with things nobody created.
 * Every list is paginated. An incomplete walk is reported through the
 * collection failure sink so finalization preserves previously collected
 * rows instead of treating an unread page as deletion.
 */
export async function scanSsm(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `ssm.${ctx.region}.amazonaws.com`;
  const walk = <T>(action: string, itemsKey: string, body: Record<string, unknown>) =>
    walkJsonRpc<T>(ctx, { service: 'ssm', host: endpoint, target: `AmazonSSM.${action}`, body }, itemsKey, {
      tokenIn: 'NextToken', tokenOut: 'NextToken', maxPages: 200,
    });

  const out: ScannedResource[] = [];

  const [params, automations, documents, instances, windows, baselines, inventory] = await Promise.all([
    walk<SsmParameter>('DescribeParameters', 'Parameters', { MaxResults: 50 }),
    walk<AutomationExecution>('DescribeAutomationExecutions', 'AutomationExecutionMetadataList', { MaxResults: 50 }),
    walk<SsmDocument>('ListDocuments', 'DocumentIdentifiers', { Filters: [{ Key: 'Owner', Values: ['Self'] }], MaxResults: 50 }),
    walk<ManagedInstance>('DescribeInstanceInformation', 'InstanceInformationList', { MaxResults: 50 }),
    walk<MaintenanceWindow>('DescribeMaintenanceWindows', 'WindowIdentities', { MaxResults: 50 }),
    walk<PatchBaseline>('DescribePatchBaselines', 'BaselineIdentities', { MaxResults: 50 }),
    walk<{ Id?: string; Data?: Record<string, unknown> }>('GetInventory', 'Entities', { MaxResults: 50 }),
  ]);

  const walks = [
    ['DescribeParameters', params], ['DescribeAutomationExecutions', automations], ['ListDocuments', documents],
    ['DescribeInstanceInformation', instances], ['DescribeMaintenanceWindows', windows],
    ['DescribePatchBaselines', baselines], ['GetInventory', inventory],
  ] as const;
  for (const [action, result] of walks) reportWalk(ctx, result, 'ssm', action);

  for (const p of params.items) {
    out.push({
      resourceTypeKey: 'ssm_parameter', resourceId: `${ctx.region}:${p.Name}`, region: ctx.region, resourceName: p.Name,
      metadata: { type: p.Type, lastModifiedDate: p.LastModifiedDate, version: p.Version, tier: p.Tier },
    });
  }

  for (const a of automations.items) {
    out.push({
      resourceTypeKey: 'ssm_automation', resourceId: a.AutomationExecutionId, region: ctx.region, resourceName: a.DocumentName,
      state: a.AutomationExecutionStatus, metadata: { startTime: a.ExecutionStartTime, endTime: a.ExecutionEndTime },
    });
  }

  for (const d of documents.items) {
    out.push({
      resourceTypeKey: 'ssm_document', resourceId: `${ctx.region}:${d.Name}`, region: ctx.region, resourceName: d.Name,
      metadata: { documentType: d.DocumentType, documentVersion: d.DocumentVersion, platformTypes: d.PlatformTypes },
    });
  }

  for (const i of instances.items) {
    out.push({
      resourceTypeKey: 'ssm_managed_instance', resourceId: i.InstanceId, region: ctx.region, resourceName: i.ComputerName ?? i.InstanceId,
      state: i.PingStatus, metadata: { platformType: i.PlatformType, platformName: i.PlatformName, agentVersion: i.AgentVersion, ipAddress: i.IPAddress },
    });
  }

  for (const w of windows.items) {
    out.push({
      resourceTypeKey: 'ssm_maintenance_window', resourceId: w.WindowId, region: ctx.region, resourceName: w.Name,
      state: w.Enabled ? 'enabled' : 'disabled', metadata: { durationHours: w.Duration, cutoffHours: w.Cutoff },
    });
  }

  for (const b of baselines.items) {
    // AWS ships one default baseline per OS ("AWS-AmazonLinuxDefaultPatchBaseline",
    // "AWS-WindowsDefaultPatchBaseline", ...) in every account/region with
    // zero setup. Confirmed via a real discovery run: without this filter, a
    // 17-region scan returned 289 "patch baselines" that were almost
    // entirely these, same AWS-managed-noise problem as prefix lists above.
    if (b.BaselineName?.startsWith('AWS-')) continue;
    out.push({
      resourceTypeKey: 'ssm_patch_baseline', resourceId: b.BaselineId, region: ctx.region, resourceName: b.BaselineName,
      metadata: { operatingSystem: b.OperatingSystem },
    });
  }

  // Inventory is one entry per managed instance (AWS:InstanceInformation
  // plus whatever other inventory types that instance's SSM Agent config
  // collects), not a separate top-level catalog — GetInventory returns one
  // Entities[] item per instance with a Data map keyed by inventory type
  // name, summarized here to which types are present rather than dumping
  // every field of every type.
  for (const e of inventory.items) {
    if (!e.Id) continue;
    out.push({
      resourceTypeKey: 'systems_manager_inventory', resourceId: `${ctx.region}:${e.Id}`, region: ctx.region, resourceName: e.Id,
      metadata: { inventoryTypes: Object.keys(e.Data ?? {}) }, relationships: { instanceId: e.Id },
    });
  }

  return out;
}
