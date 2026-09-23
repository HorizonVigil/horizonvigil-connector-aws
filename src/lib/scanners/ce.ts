import { reportWalk, walkJsonRpc } from './restJson';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AWSInsightsIndexService';
const HOST = 'ce.us-east-1.amazonaws.com';

/**
 * Pages per list. Cost Explorer bills per API request (paginated requests
 * included), so the cap is deliberately small; a capped walk is reported.
 */
const MAX_PAGES = 5;

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CE_RESOURCE_TYPES = ['cost_category', 'cost_anomaly_monitor'] as const;

interface CostCategoryReference {
  CostCategoryArn: string; Name: string; EffectiveStart?: string; EffectiveEnd?: string; NumberOfRules?: number;
  DefaultValue?: string;
}
interface AnomalyMonitor {
  MonitorArn: string; MonitorName: string; MonitorType?: string; MonitorDimension?: string; CreationDate?: string;
  LastEvaluatedDate?: string;
}

/**
 * Cost Explorer inventory — a single account-wide, us-east-1-only endpoint
 * (GLOBAL_SCANNERS entry). Scoped to which cost categories and anomaly
 * monitors exist, not dollar amounts (routes/cost.ts and routes/cur.ts own
 * cost data).
 *
 * Both lists now paginate (NextToken), and failures or a capped walk are
 * reported rather than returned as [] -- which finalize read as deletions.
 */
export async function scanCostExplorer(ctx: ScannerContext): Promise<ScannedResource[]> {
  const [categories, monitors] = await Promise.all([
    walkJsonRpc<CostCategoryReference>(ctx, {
      service: 'ce', region: 'us-east-1', host: HOST, target: `${TARGET_PREFIX}.ListCostCategoryDefinitions`, body: { MaxResults: 100 },
    }, 'CostCategoryReferences', { maxPages: MAX_PAGES }),
    walkJsonRpc<AnomalyMonitor>(ctx, {
      service: 'ce', region: 'us-east-1', host: HOST, target: `${TARGET_PREFIX}.GetAnomalyMonitors`, body: { MaxResults: 100 },
    }, 'AnomalyMonitors', { tokenIn: 'NextPageToken', tokenOut: 'NextPageToken', maxPages: MAX_PAGES }),
  ]);
  reportWalk(ctx, categories, 'ce', 'ListCostCategoryDefinitions', 'us-east-1');
  reportWalk(ctx, monitors, 'ce', 'GetAnomalyMonitors', 'us-east-1');

  const out: ScannedResource[] = [];
  for (const cc of categories.items) {
    if (!cc?.CostCategoryArn) continue;
    out.push({
      resourceTypeKey: 'cost_category', resourceId: cc.CostCategoryArn, region: null, resourceName: cc.Name,
      metadata: { effectiveStart: cc.EffectiveStart, effectiveEnd: cc.EffectiveEnd, numberOfRules: cc.NumberOfRules, defaultValue: cc.DefaultValue ?? null },
    });
  }
  for (const mon of monitors.items) {
    if (!mon?.MonitorArn) continue;
    out.push({
      resourceTypeKey: 'cost_anomaly_monitor', resourceId: mon.MonitorArn, region: null, resourceName: mon.MonitorName,
      metadata: { type: mon.MonitorType, dimension: mon.MonitorDimension, createdAt: mon.CreationDate, lastEvaluatedDate: mon.LastEvaluatedDate ?? null },
    });
  }
  return out;
}