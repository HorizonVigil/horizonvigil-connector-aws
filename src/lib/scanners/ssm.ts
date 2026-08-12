import { callJsonApi } from '../awsApi';
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
 * Each capped at its own default/max page size with no follow-up
 * pagination — accounts with more than that in one region need pagination
 * support, not built yet.
 */
export async function scanSsm(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `ssm.${ctx.region}.amazonaws.com`;
  const call = async (action: string, body: Record<string, unknown>) => {
    const result = await callJsonApi(ctx.creds, { service: 'ssm', region: ctx.region, host: endpoint, target: `AmazonSSM.${action}`, body });
    if (!result.ok) {
      console.error(`SSM ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return null;
    }
    return result.body as Record<string, unknown>;
  };

  const out: ScannedResource[] = [];

  const paramsBody = await call('DescribeParameters', { MaxResults: 50 });
  for (const p of (paramsBody?.Parameters as SsmParameter[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'ssm_parameter', resourceId: `${ctx.region}:${p.Name}`, region: ctx.region, resourceName: p.Name,
      metadata: { type: p.Type, lastModifiedDate: p.LastModifiedDate, version: p.Version, tier: p.Tier },
    });
  }

  const automationsBody = await call('DescribeAutomationExecutions', { MaxResults: 50 });
  for (const a of (automationsBody?.AutomationExecutionMetadataList as AutomationExecution[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'ssm_automation', resourceId: a.AutomationExecutionId, region: ctx.region, resourceName: a.DocumentName,
      state: a.AutomationExecutionStatus, metadata: { startTime: a.ExecutionStartTime, endTime: a.ExecutionEndTime },
    });
  }

  const documentsBody = await call('ListDocuments', { Filters: [{ Key: 'Owner', Values: ['Self'] }], MaxResults: 50 });
  for (const d of (documentsBody?.DocumentIdentifiers as SsmDocument[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'ssm_document', resourceId: `${ctx.region}:${d.Name}`, region: ctx.region, resourceName: d.Name,
      metadata: { documentType: d.DocumentType, documentVersion: d.DocumentVersion, platformTypes: d.PlatformTypes },
    });
  }

  const instancesBody = await call('DescribeInstanceInformation', { MaxResults: 50 });
  for (const i of (instancesBody?.InstanceInformationList as ManagedInstance[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'ssm_managed_instance', resourceId: i.InstanceId, region: ctx.region, resourceName: i.ComputerName ?? i.InstanceId,
      state: i.PingStatus, metadata: { platformType: i.PlatformType, platformName: i.PlatformName, agentVersion: i.AgentVersion, ipAddress: i.IPAddress },
    });
  }

  const windowsBody = await call('DescribeMaintenanceWindows', { MaxResults: 50 });
  for (const w of (windowsBody?.WindowIdentities as MaintenanceWindow[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'ssm_maintenance_window', resourceId: w.WindowId, region: ctx.region, resourceName: w.Name,
      state: w.Enabled ? 'enabled' : 'disabled', metadata: { durationHours: w.Duration, cutoffHours: w.Cutoff },
    });
  }

  const baselinesBody = await call('DescribePatchBaselines', { MaxResults: 50 });
  for (const b of (baselinesBody?.BaselineIdentities as PatchBaseline[] | undefined) ?? []) {
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
  const inventoryBody = await call('GetInventory', { MaxResults: 50 });
  for (const e of (inventoryBody?.Entities as { Id?: string; Data?: Record<string, unknown> }[] | undefined) ?? []) {
    if (!e.Id) continue;
    out.push({
      resourceTypeKey: 'systems_manager_inventory', resourceId: `${ctx.region}:${e.Id}`, region: ctx.region, resourceName: e.Id,
      metadata: { inventoryTypes: Object.keys(e.Data ?? {}) }, relationships: { instanceId: e.Id },
    });
  }

  return out;
}
