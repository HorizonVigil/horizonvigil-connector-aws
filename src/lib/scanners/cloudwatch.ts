import { paginateQueryApi, detectQueryTruncation, incompleteSink } from '../pagination';
import { extractSection, extractListItems, field, boolField } from '../xmlList';
import { reportWalk, toIso, walkJsonRpc } from './restJson';
import { memberTexts, withoutSections } from './xmlShape';
import type { ScannedResource, ScannerContext } from './types';

const ALARMS_VERSION = '2010-08-01';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CLOUDWATCH_RESOURCE_TYPES = ['cloudwatch_alarm', 'cloudwatch_log_group', 'cloudwatch_dashboard', 'cloudwatch_metric_stream'] as const;

/** Metric filters kept per log group (patterns can be long). */
const MAX_FILTERS_PER_GROUP = 20;

interface LogGroup {
  logGroupName: string; arn?: string; logGroupArn?: string; creationTime?: number; storedBytes?: number; retentionInDays?: number;
  kmsKeyId?: string; dataProtectionStatus?: string; logGroupClass?: string; deletionProtectionEnabled?: boolean;
}
interface MetricFilter {
  filterName?: string; filterPattern?: string; logGroupName?: string;
  metricTransformations?: { metricName?: string; metricNamespace?: string }[];
}

/** Nested lists in a MetricAlarm whose children reuse top-level names (MetricName, Namespace…). */
const ALARM_NESTED = ['Metrics', 'Dimensions', 'OKActions', 'AlarmActions', 'InsufficientDataActions'];

/** Evidence for one metric alarm, read from the alarm's own top level. */
export function alarmEvidence(alarm: string) {
  const top = withoutSections(alarm, ALARM_NESTED);
  const dimensions = extractListItems(extractSection(alarm, 'Dimensions'), 'member')
    .map((d) => ({ name: field(d, 'Name'), value: field(d, 'Value') }))
    .filter((d) => d.name);
  const alarmActions = memberTexts(alarm, 'AlarmActions');
  return {
    // Kept exactly as before (extractMonitoringAlarmRows reads these).
    metricName: field(top, 'MetricName'),
    namespace: field(top, 'Namespace'),
    comparisonOperator: field(top, 'ComparisonOperator'),
    threshold: field(top, 'Threshold'),
    // An alarm with actions disabled, or with no action, alerts nobody
    // (CIS 4.x: each metric-filter alarm must notify an SNS topic).
    actionsEnabled: boolField(top, 'ActionsEnabled') ?? null,
    alarmActions,
    hasAlarmActions: alarmActions.length > 0,
    statistic: field(top, 'Statistic'),
    period: field(top, 'Period'),
    evaluationPeriods: field(top, 'EvaluationPeriods'),
    treatMissingData: field(top, 'TreatMissingData'),
    dimensions,
    isMetricMath: extractSection(alarm, 'Metrics') !== null,
  };
}

/**
 * CloudWatch alarms, dashboards and metric streams (Query protocol, signing
 * service "monitoring") and CloudWatch Logs log groups (JSON-RPC, "logs").
 *
 * What changed, and why:
 *  - EVERY list paginates. DescribeLogGroups returns 50 groups per page, so
 *    any account with more than 50 log groups lost the rest to tombstoning;
 *    alarms (100/page), dashboards and metric streams likewise.
 *  - Alarm fields are read from the alarm's top level. A metric-math alarm
 *    has no top-level MetricName, and the regex reader used to return one
 *    from inside its nested Metrics list instead.
 *  - Evidence for the CIS 4.x monitoring chain: each log group carries its
 *    metric filters (pattern → metric), and each alarm its actions, so
 *    posture can follow CloudTrail log group → filter → metric → alarm →
 *    SNS topic. Log groups also carry KMS encryption, retention (null =
 *    never expire) and data-protection status.
 *
 * Note: `storedBytes` changes continuously, so log-group rows change on most
 * scans. It is kept because existing consumers read it.
 */
export async function scanCloudWatch(ctx: ScannerContext): Promise<ScannedResource[]> {
  const out: ScannedResource[] = [];
  const monitoringHost = `monitoring.${ctx.region}.amazonaws.com`;
  const logsHost = `logs.${ctx.region}.amazonaws.com`;
  const onIncomplete = incompleteSink(ctx.creds);
  const queryWalk = (action: string, section: string, params?: Record<string, string>) => paginateQueryApi<string, string>(
    ctx.creds,
    { service: 'monitoring', region: ctx.region, host: monitoringHost, action, version: ALARMS_VERSION, params },
    (page) => extractListItems(extractSection(page, section), 'member'),
    (page) => detectQueryTruncation(page),
    { onIncomplete },
  );

  const [alarms, dashboards, streams, logGroups, metricFilters] = await Promise.all([
    queryWalk('DescribeAlarms', 'MetricAlarms', { MaxRecords: '100' }),
    queryWalk('ListDashboards', 'DashboardEntries'),
    queryWalk('ListMetricStreams', 'Entries', { MaxResults: '500' }),
    walkJsonRpc<LogGroup>(ctx, { service: 'logs', host: logsHost, target: 'Logs_20140328.DescribeLogGroups', body: { limit: 50 } }, 'logGroups', { tokenIn: 'nextToken', tokenOut: 'nextToken', maxPages: 200 }),
    walkJsonRpc<MetricFilter>(ctx, { service: 'logs', host: logsHost, target: 'Logs_20140328.DescribeMetricFilters', body: { limit: 50 } }, 'metricFilters', { tokenIn: 'nextToken', tokenOut: 'nextToken', maxPages: 20 }),
  ]);
  for (const [action, w] of [['DescribeAlarms', alarms], ['ListDashboards', dashboards], ['ListMetricStreams', streams]] as const) {
    if (w.termination !== 'complete') console.error(`CloudWatch ${action} in ${ctx.region} ended '${w.termination}' after ${w.pages} page(s); continuing with what was read.`);
  }
  reportWalk(ctx, logGroups, 'logs', 'DescribeLogGroups');
  const filtersComplete = metricFilters.complete;
  if (!filtersComplete) console.error(`CloudWatch Logs DescribeMetricFilters in ${ctx.region} is partial; metric-filter evidence marked incomplete.`);

  for (const alarm of alarms.items) {
    const name = field(alarm, 'AlarmName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'cloudwatch_alarm', resourceId: field(alarm, 'AlarmArn') ?? name, region: ctx.region, resourceName: name,
      state: field(alarm, 'StateValue') ?? undefined,
      metadata: alarmEvidence(alarm),
      relationships: { snsTopicArns: memberTexts(alarm, 'AlarmActions').filter((a) => a.startsWith('arn:aws:sns:')) },
    });
  }

  for (const d of dashboards.items) {
    const name = field(d, 'DashboardName');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'cloudwatch_dashboard', resourceId: field(d, 'DashboardArn') ?? name, region: ctx.region, resourceName: name,
      metadata: { lastModified: field(d, 'LastModified'), sizeBytes: field(d, 'Size') },
    });
  }

  for (const m of streams.items) {
    const name = field(m, 'Name');
    if (!name) continue;
    out.push({
      resourceTypeKey: 'cloudwatch_metric_stream', resourceId: field(m, 'Arn') ?? name, region: ctx.region, resourceName: name,
      state: field(m, 'State') ?? undefined,
      metadata: { creationDate: field(m, 'CreationDate'), lastUpdateDate: field(m, 'LastUpdateDate'), outputFormat: field(m, 'OutputFormat') },
      relationships: { firehoseArn: field(m, 'FirehoseArn') },
    });
  }

  const filtersByGroup = new Map<string, MetricFilter[]>();
  for (const f of metricFilters.items) {
    if (!f?.logGroupName) continue;
    const list = filtersByGroup.get(f.logGroupName) ?? [];
    list.push(f);
    filtersByGroup.set(f.logGroupName, list);
  }

  for (const g of logGroups.items) {
    if (!g?.logGroupName) continue;
    const filters = (filtersByGroup.get(g.logGroupName) ?? []).slice(0, MAX_FILTERS_PER_GROUP);
    out.push({
      // `arn` ends in ":*"; kept as the identity existing rows use.
      resourceTypeKey: 'cloudwatch_log_group', resourceId: g.arn ?? g.logGroupName, region: ctx.region, resourceName: g.logGroupName,
      metadata: {
        createdAt: g.creationTime, createdAtIso: toIso(typeof g.creationTime === 'number' ? g.creationTime / 1000 : g.creationTime),
        storedBytes: g.storedBytes, retentionInDays: g.retentionInDays,
        neverExpires: g.retentionInDays === undefined || g.retentionInDays === null,
        // FSBP CloudWatch: log groups encrypted with a KMS key.
        kmsKeyId: g.kmsKeyId ?? null,
        encryptedWithKms: !!g.kmsKeyId,
        dataProtectionStatus: g.dataProtectionStatus ?? null,
        logGroupClass: g.logGroupClass ?? null,
        deletionProtectionEnabled: g.deletionProtectionEnabled ?? null,
        metricFiltersCollected: filtersComplete,
        metricFilters: filters.map((f) => ({
          name: f.filterName ?? null,
          pattern: f.filterPattern ?? '',
          metrics: (f.metricTransformations ?? []).map((t) => ({ name: t.metricName ?? null, namespace: t.metricNamespace ?? null })),
        })),
      },
      relationships: { kmsKeyId: g.kmsKeyId ?? null },
    });
  }

  return out;
}

export interface MonitoringAlarmRow {
  connection_id: string; resource_id: null; alarm_name: string; metric_name: string;
  namespace: string; region: string; state: string; threshold: number | null; comparison_operator: string | null;
}

/**
 * Derives monitoring_alarms rows from scanCloudWatch's own output -- a pure
 * filter+map, no second DescribeAlarms call. resource_id stays null: nothing
 * structurally links an alarm to the resource it monitors (dimensions are
 * now recorded on the alarm, which is what a future link would use).
 */
export function extractMonitoringAlarmRows(scanned: ScannedResource[], connectionId: string): MonitoringAlarmRow[] {
  return scanned
    .filter((r): r is ScannedResource & { resourceName: string; region: string } => r.resourceTypeKey === 'cloudwatch_alarm' && !!r.resourceName && !!r.region)
    .map((r) => {
      const threshold = r.metadata?.threshold != null ? Number(r.metadata.threshold) : null;
      return {
        connection_id: connectionId, resource_id: null, alarm_name: r.resourceName,
        metric_name: (r.metadata?.metricName as string) ?? '', namespace: (r.metadata?.namespace as string) ?? '',
        region: r.region, state: r.state ?? 'INSUFFICIENT_DATA',
        threshold: threshold !== null && Number.isFinite(threshold) ? threshold : null,
        comparison_operator: (r.metadata?.comparisonOperator as string) ?? null,
      };
    });
}