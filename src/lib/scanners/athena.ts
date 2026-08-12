import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AmazonAthena';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const ATHENA_RESOURCE_TYPES = ['athena_workgroup', 'athena_data_catalog'] as const;

interface WorkGroupSummary {
  Name: string; State?: string; Description?: string; CreationTime?: number;
  EngineVersion?: { EffectiveEngineVersion?: string };
}
interface DataCatalogSummary {
  CatalogName: string; Type?: string;
}

/** Two independent list calls, both already return everything needed with no per-item fan-out. */
export async function scanAthena(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `athena.${ctx.region}.amazonaws.com`;
  const out: ScannedResource[] = [];

  const workgroups = await callJsonApi(ctx.creds, { service: 'athena', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListWorkGroups`, body: {} });
  if (!workgroups.ok) {
    console.error(`Athena ListWorkGroups failed in ${ctx.region} (continuing without it): ${workgroups.errorMessage ?? workgroups.errorCode ?? workgroups.status}`);
  } else {
    for (const wg of (workgroups.body as { WorkGroups?: WorkGroupSummary[] }).WorkGroups ?? []) {
      out.push({
        resourceTypeKey: 'athena_workgroup', resourceId: wg.Name, region: ctx.region, resourceName: wg.Name,
        state: wg.State,
        metadata: { description: wg.Description, createdAt: wg.CreationTime, engineVersion: wg.EngineVersion?.EffectiveEngineVersion },
      });
    }
  }

  const catalogs = await callJsonApi(ctx.creds, { service: 'athena', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListDataCatalogs`, body: {} });
  if (!catalogs.ok) {
    console.error(`Athena ListDataCatalogs failed in ${ctx.region} (continuing without it): ${catalogs.errorMessage ?? catalogs.errorCode ?? catalogs.status}`);
  } else {
    for (const dc of (catalogs.body as { DataCatalogsSummary?: DataCatalogSummary[] }).DataCatalogsSummary ?? []) {
      out.push({
        resourceTypeKey: 'athena_data_catalog', resourceId: dc.CatalogName, region: ctx.region, resourceName: dc.CatalogName,
        metadata: { type: dc.Type },
      });
    }
  }

  return out;
}
