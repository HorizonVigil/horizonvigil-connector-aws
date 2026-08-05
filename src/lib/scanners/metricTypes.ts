/**
 * A single (resource, metric, timestamp) datapoint bound for
 * resource_metrics — distinct from ScannedResource/ScannedFinding since it
 * doesn't describe a thing that exists, it describes a measurement over
 * time. `resourceDbId` is cloud_resources.id (the row's own uuid), already
 * known at ingestion time since metric scanners are only ever called for
 * resources this connection has already discovered — unlike
 * resourceArn/resourceId elsewhere in this codebase, there's no AWS-side
 * identifier to resolve here.
 */
export interface ScannedMetric {
  resourceDbId: string;
  resourceTypeKey: string;
  metricName: string;
  namespace: string;
  unit?: string;
  region: string;
  ts: string;
  value: number;
}
