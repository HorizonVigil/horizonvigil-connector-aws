import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AWSInsightsIndexService';
const HOST = 'ce.us-east-1.amazonaws.com';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CE_RESOURCE_TYPES = ['cost_category', 'cost_anomaly_monitor'] as const;

interface CostCategoryReference {
  CostCategoryArn: string; Name: string; EffectiveStart?: string; EffectiveEnd?: string; NumberOfRules?: number;
}
interface AnomalyMonitor {
  MonitorArn: string; MonitorName: string; MonitorType?: string; MonitorDimension?: string; CreationDate?: string;
}

/**
 * Cost Explorer is a single account-wide, us-east-1-only endpoint
 * regardless of the connection's own scan regions — same reasoning as
 * iam.ts, registered as a GLOBAL_SCANNERS entry in discovery.ts, not
 * REGIONAL_SCANNERS. Deliberately scoped to inventory (which cost
 * categories/anomaly monitors exist), not dollar amounts — actual cost
 * data ingestion is a separate, already-real path (routes/cost.ts,
 * routes/cur.ts), untouched by this scanner.
 *
 * UNVERIFIED against a real account's actual Cost Explorer response shape
 * until this runs against a live connection and gets checked -- same
 * disclosed-uncertainty convention as inspectorFindings.ts.
 */
export async function scanCostExplorer(ctx: ScannerContext): Promise<ScannedResource[]> {
  const out: ScannedResource[] = [];

  const categories = await callJsonApi(ctx.creds, { service: 'ce', region: 'us-east-1', host: HOST, target: `${TARGET_PREFIX}.ListCostCategoryDefinitions`, body: {} });
  if (!categories.ok) {
    console.error(`Cost Explorer ListCostCategoryDefinitions failed (continuing without it): ${categories.errorMessage ?? categories.errorCode ?? categories.status}`);
  } else {
    for (const cc of (categories.body as { CostCategoryReferences?: CostCategoryReference[] }).CostCategoryReferences ?? []) {
      out.push({
        resourceTypeKey: 'cost_category', resourceId: cc.CostCategoryArn, region: null, resourceName: cc.Name,
        metadata: { effectiveStart: cc.EffectiveStart, effectiveEnd: cc.EffectiveEnd, numberOfRules: cc.NumberOfRules },
      });
    }
  }

  const monitors = await callJsonApi(ctx.creds, { service: 'ce', region: 'us-east-1', host: HOST, target: `${TARGET_PREFIX}.GetAnomalyMonitors`, body: {} });
  if (!monitors.ok) {
    console.error(`Cost Explorer GetAnomalyMonitors failed (continuing without it): ${monitors.errorMessage ?? monitors.errorCode ?? monitors.status}`);
  } else {
    for (const mon of (monitors.body as { AnomalyMonitors?: AnomalyMonitor[] }).AnomalyMonitors ?? []) {
      out.push({
        resourceTypeKey: 'cost_anomaly_monitor', resourceId: mon.MonitorArn, region: null, resourceName: mon.MonitorName,
        metadata: { type: mon.MonitorType, dimension: mon.MonitorDimension, createdAt: mon.CreationDate },
      });
    }
  }

  return out;
}
