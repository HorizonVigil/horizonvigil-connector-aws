import { callQueryApi, type AwsCreds } from '../awsApi';
import { extractSection, extractListItems, field } from '../xmlList';
import type { ScannedMetric } from './metricTypes';
import { mapWithConcurrency } from './scannerSupport';
import { memberTexts, withoutSections } from './xmlShape';

const CLOUDWATCH_VERSION = '2010-08-01';
const LOOKBACK_DAYS = 14;
const PERIOD_SECONDS = 86400; // daily datapoints: 14 per instance, not 14*24 hourly ones, to keep this cheap
/** GetMetricData accepts up to 500 queries per call; two per instance (Average + Maximum). */
const INSTANCES_PER_BATCH = 250;
/** NextToken pages per batch (14 daily points x 2 stats never needs more than one in practice). */
const MAX_PAGES = 5;
const FALLBACK_CONCURRENCY = 4;
const DAY_MS = 24 * 60 * 60 * 1000;

export interface Ec2InstanceRef {
  /** cloud_resources.id: the FK resource_metrics rows need. */
  dbId: string;
  /** The AWS instance id (i-...), what CloudWatch's dimension actually keys on. */
  awsInstanceId: string;
}

type Stat = 'Average' | 'Maximum';
const METRIC_NAME: Record<Stat, string> = { Average: 'CPUUtilization', Maximum: 'CPUUtilizationMaximum' };

/**
 * The query window. The start is floored to UTC midnight so each daily
 * datapoint covers one whole calendar day and its timestamp is identical
 * across runs; the previous version started at "now minus 14 days", so every
 * run produced a fresh set of timestamps and duplicated rows.
 */
export function metricWindow(now = new Date()): { start: Date; end: Date } {
  const midnight = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return { start: new Date(midnight - LOOKBACK_DAYS * DAY_MS), end: now };
}

/** GetMetricData query parameters for one batch of instances (ids a<i> / m<i>). */
export function metricDataParams(instances: Ec2InstanceRef[], start: Date, end: Date): Record<string, string> {
  const params: Record<string, string> = {
    StartTime: start.toISOString(), EndTime: end.toISOString(), ScanBy: 'TimestampAscending',
  };
  let n = 0;
  instances.forEach((inst, i) => {
    for (const [prefix, stat] of [['a', 'Average'], ['m', 'Maximum']] as const) {
      n += 1;
      const q = `MetricDataQueries.member.${n}`;
      params[`${q}.Id`] = `${prefix}${i}`;
      params[`${q}.ReturnData`] = 'true';
      params[`${q}.MetricStat.Metric.Namespace`] = 'AWS/EC2';
      params[`${q}.MetricStat.Metric.MetricName`] = 'CPUUtilization';
      params[`${q}.MetricStat.Metric.Dimensions.member.1.Name`] = 'InstanceId';
      params[`${q}.MetricStat.Metric.Dimensions.member.1.Value`] = inst.awsInstanceId;
      params[`${q}.MetricStat.Period`] = String(PERIOD_SECONDS);
      params[`${q}.MetricStat.Stat`] = stat;
      params[`${q}.MetricStat.Unit`] = 'Percent';
    }
  });
  return params;
}

export interface MetricDataSeries { id: string; statusCode: string | null; points: { ts: string; value: number }[] }

/** Parses GetMetricData's MetricDataResults (parallel Timestamps / Values lists). */
export function parseMetricDataResults(xml: string): { series: MetricDataSeries[]; nextToken: string | null } {
  const results = extractSection(xml, 'MetricDataResults');
  const series = extractListItems(results, 'member').map((m) => {
    const top = withoutSections(m, ['Timestamps', 'Values', 'Messages']);
    const timestamps = memberTexts(m, 'Timestamps');
    const values = memberTexts(m, 'Values');
    const points: { ts: string; value: number }[] = [];
    const n = Math.min(timestamps.length, values.length);
    for (let i = 0; i < n; i++) {
      const value = Number(values[i]);
      if (timestamps[i] && Number.isFinite(value)) points.push({ ts: timestamps[i], value });
    }
    return { id: field(top, 'Id') ?? '', statusCode: field(top, 'StatusCode'), points };
  });
  const outside = withoutSections(xml, ['MetricDataResults', 'Messages']);
  return { series, nextToken: field(outside, 'NextToken') || null };
}

/**
 * Daily Average and Maximum CPUUtilization for the last 14 days, per
 * already-discovered EC2 instance (CloudWatch, Query protocol).
 *
 * What changed, and why:
 *  - One GetMetricData call now covers up to 250 instances (500 queries),
 *    paginated on NextToken, instead of one GetMetricStatistics call per
 *    instance run strictly one after another. A 200-instance region went from
 *    200 sequential subrequests to 1.
 *  - The window starts at UTC midnight, so daily timestamps are stable run to
 *    run (the old rolling start produced new timestamps every run).
 *  - A failed or partial batch falls back to per-instance
 *    GetMetricStatistics (bounded concurrency), so one bad batch does not
 *    lose every instance's data. Failures are logged per instance, as before.
 *
 * Output shape is unchanged: ScannedMetric rows named CPUUtilization and
 * CPUUtilizationMaximum. ExtendedStatistics (p95/p99) are still deliberately
 * not requested; Average is a standard rightsizing signal on its own.
 *
 * Capped to whatever instance list the caller passes in; discovery.ts limits
 * that to a subrequest-budget-safe batch per step.
 */
export async function scanEc2CpuMetrics(creds: AwsCreds, region: string, instances: Ec2InstanceRef[]): Promise<ScannedMetric[]> {
  const host = `monitoring.${region}.amazonaws.com`;
  const { start, end } = metricWindow();
  const unique = [...new Map(instances.filter((i) => !!i?.awsInstanceId && !!i.dbId).map((i) => [i.awsInstanceId, i])).values()];

  const out: ScannedMetric[] = [];
  const emit = (instance: Ec2InstanceRef, stat: Stat, ts: string, value: number, unit = 'Percent') => {
    out.push({ resourceDbId: instance.dbId, resourceTypeKey: 'ec2_instance', metricName: METRIC_NAME[stat], namespace: 'AWS/EC2', unit, region, ts, value });
  };

  const fallback: Ec2InstanceRef[] = [];
  for (let b = 0; b < unique.length; b += INSTANCES_PER_BATCH) {
    const batch = unique.slice(b, b + INSTANCES_PER_BATCH);
    const baseParams = metricDataParams(batch, start, end);
    const collected = new Map<string, { ts: string; value: number }[]>();
    const partial = new Set<string>();
    let token: string | null = null;
    let failed = false;
    let pages = 0;
    do {
      const result = await callQueryApi(creds, {
        service: 'monitoring', region, host, action: 'GetMetricData', version: CLOUDWATCH_VERSION,
        params: token ? { ...baseParams, NextToken: token } : baseParams,
      });
      pages += 1;
      if (!result.ok) {
        console.error(`CloudWatch GetMetricData failed for ${batch.length} instances in ${region} (falling back to GetMetricStatistics): ${result.errorMessage ?? result.errorCode ?? result.status}`);
        failed = true;
        break;
      }
      const parsed = parseMetricDataResults(result.body as string);
      for (const s of parsed.series) {
        const list = collected.get(s.id) ?? [];
        list.push(...s.points);
        collected.set(s.id, list);
        if (s.statusCode && s.statusCode !== 'Complete' && s.statusCode !== 'PartialData') partial.add(s.id);
        else if (s.statusCode === 'Complete') partial.delete(s.id);
      }
      token = parsed.nextToken;
    } while (token && pages < MAX_PAGES);
    if (token) failed = true; // page cap hit with data still pending

    if (failed) {
      fallback.push(...batch);
      continue;
    }
    batch.forEach((inst, i) => {
      if (partial.has(`a${i}`) || partial.has(`m${i}`)) { fallback.push(inst); return; }
      for (const p of collected.get(`a${i}`) ?? []) emit(inst, 'Average', p.ts, p.value);
      for (const p of collected.get(`m${i}`) ?? []) emit(inst, 'Maximum', p.ts, p.value);
    });
  }

  await mapWithConcurrency(fallback, FALLBACK_CONCURRENCY, async (instance) => {
    const result = await callQueryApi(creds, {
      service: 'monitoring', region, host, action: 'GetMetricStatistics', version: CLOUDWATCH_VERSION,
      params: {
        Namespace: 'AWS/EC2', MetricName: 'CPUUtilization',
        'Dimensions.member.1.Name': 'InstanceId', 'Dimensions.member.1.Value': instance.awsInstanceId,
        StartTime: start.toISOString(), EndTime: end.toISOString(), Period: String(PERIOD_SECONDS),
        'Statistics.member.1': 'Average', 'Statistics.member.2': 'Maximum',
      },
    });
    if (!result.ok) {
      console.error(`CloudWatch GetMetricStatistics failed for ${instance.awsInstanceId} in ${region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return;
    }
    for (const dp of extractListItems(extractSection(result.body as string, 'Datapoints'), 'member')) {
      const ts = field(dp, 'Timestamp');
      if (!ts) continue;
      const unit = field(dp, 'Unit') ?? 'Percent';
      for (const stat of ['Average', 'Maximum'] as const) {
        const raw = field(dp, stat);
        const value = raw === null ? NaN : Number(raw);
        if (Number.isFinite(value)) emit(instance, stat, ts, value, unit);
      }
    }
  });

  return out;
}
