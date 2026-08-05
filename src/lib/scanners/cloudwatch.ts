import { callQueryApi, callJsonApi } from '../awsApi';
import { extractSection, extractListItems, field } from '../xmlList';
import type { ScannedResource, ScannerContext } from './types';

const ALARMS_VERSION = '2010-08-01';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CLOUDWATCH_RESOURCE_TYPES = ['cloudwatch_alarm', 'cloudwatch_log_group', 'cloudwatch_dashboard', 'cloudwatch_metric_stream'] as const;

interface LogGroup {
  logGroupName: string; arn?: string; creationTime?: number; storedBytes?: number; retentionInDays?: number;
}

/**
 * Covers two catalog entries under one scanner, like rds.ts/backup.ts, but
 * these two are actually different AWS services with different wire
 * protocols: alarms are CloudWatch's classic Query-protocol API (signed as
 * service "monitoring" — that's the real SigV4 service name behind the
 * "cloudwatch" console branding, not "cloudwatch" itself), log groups are
 * CloudWatch Logs' JSON-RPC API (a genuinely separate service, "logs").
 */
export async function scanCloudWatch(ctx: ScannerContext): Promise<ScannedResource[]> {
  const out: ScannedResource[] = [];

  const alarmsEndpoint = `monitoring.${ctx.region}.amazonaws.com`;
  const alarmsResult = await callQueryApi(ctx.creds, { service: 'monitoring', region: ctx.region, host: alarmsEndpoint, action: 'DescribeAlarms', version: ALARMS_VERSION });
  if (!alarmsResult.ok) {
    console.error(`CloudWatch DescribeAlarms failed in ${ctx.region} (continuing without it): ${alarmsResult.errorMessage ?? alarmsResult.errorCode ?? alarmsResult.status}`);
  } else {
    for (const alarm of extractListItems(extractSection(alarmsResult.body as string, 'MetricAlarms'), 'member')) {
      const name = field(alarm, 'AlarmName');
      if (!name) continue;
      out.push({
        resourceTypeKey: 'cloudwatch_alarm', resourceId: field(alarm, 'AlarmArn') ?? name, region: ctx.region, resourceName: name,
        state: field(alarm, 'StateValue') ?? undefined,
        metadata: {
          metricName: field(alarm, 'MetricName'), namespace: field(alarm, 'Namespace'),
          comparisonOperator: field(alarm, 'ComparisonOperator'), threshold: field(alarm, 'Threshold'),
        },
      });
    }
  }

  const dashboardsResult = await callQueryApi(ctx.creds, { service: 'monitoring', region: ctx.region, host: alarmsEndpoint, action: 'ListDashboards', version: ALARMS_VERSION });
  if (!dashboardsResult.ok) {
    console.error(`CloudWatch ListDashboards failed in ${ctx.region} (continuing without it): ${dashboardsResult.errorMessage ?? dashboardsResult.errorCode ?? dashboardsResult.status}`);
  } else {
    for (const d of extractListItems(extractSection(dashboardsResult.body as string, 'DashboardEntries'), 'member')) {
      const name = field(d, 'DashboardName');
      if (!name) continue;
      out.push({
        resourceTypeKey: 'cloudwatch_dashboard', resourceId: field(d, 'DashboardArn') ?? name, region: ctx.region, resourceName: name,
        metadata: { lastModified: field(d, 'LastModified'), sizeBytes: field(d, 'Size') },
      });
    }
  }

  const metricStreamsResult = await callQueryApi(ctx.creds, { service: 'monitoring', region: ctx.region, host: alarmsEndpoint, action: 'ListMetricStreams', version: ALARMS_VERSION });
  if (!metricStreamsResult.ok) {
    console.error(`CloudWatch ListMetricStreams failed in ${ctx.region} (continuing without it): ${metricStreamsResult.errorMessage ?? metricStreamsResult.errorCode ?? metricStreamsResult.status}`);
  } else {
    for (const m of extractListItems(extractSection(metricStreamsResult.body as string, 'Entries'), 'member')) {
      const name = field(m, 'Name');
      if (!name) continue;
      out.push({
        resourceTypeKey: 'cloudwatch_metric_stream', resourceId: field(m, 'Arn') ?? name, region: ctx.region, resourceName: name,
        state: field(m, 'State') ?? undefined,
        metadata: { creationDate: field(m, 'CreationDate'), lastUpdateDate: field(m, 'LastUpdateDate'), outputFormat: field(m, 'OutputFormat') },
      });
    }
  }

  const logsEndpoint = `logs.${ctx.region}.amazonaws.com`;
  const logsResult = await callJsonApi(ctx.creds, { service: 'logs', region: ctx.region, host: logsEndpoint, target: 'Logs_20140328.DescribeLogGroups', body: {} });
  if (!logsResult.ok) {
    console.error(`CloudWatch Logs DescribeLogGroups failed in ${ctx.region} (continuing without it): ${logsResult.errorMessage ?? logsResult.errorCode ?? logsResult.status}`);
  } else {
    const groups = (logsResult.body as { logGroups?: LogGroup[] }).logGroups ?? [];
    for (const g of groups) {
      out.push({
        resourceTypeKey: 'cloudwatch_log_group', resourceId: g.arn ?? g.logGroupName, region: ctx.region, resourceName: g.logGroupName,
        metadata: { createdAt: g.creationTime, storedBytes: g.storedBytes, retentionInDays: g.retentionInDays },
      });
    }
  }

  return out;
}
