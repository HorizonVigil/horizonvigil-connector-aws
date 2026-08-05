import { callQueryApi, type AwsCreds } from '../awsApi';
import { extractSection, extractListItems, field } from '../xmlList';
import type { ScannedMetric } from './metricTypes';

const CLOUDWATCH_VERSION = '2010-08-01';
const LOOKBACK_DAYS = 14;
const PERIOD_SECONDS = 86400; // daily datapoints — 14 of them per instance, not 14*24 hourly ones, to keep this cheap

export interface Ec2InstanceRef {
  /** cloud_resources.id — the FK resource_metrics rows need. */
  dbId: string;
  /** The AWS instance id (i-...), what CloudWatch's dimension actually keys on. */
  awsInstanceId: string;
}

/**
 * Real CloudWatch GetMetricStatistics calls (Query-protocol, same
 * "monitoring" service/host as cloudwatch.ts's DescribeAlarms) — Average and
 * Maximum CPUUtilization, daily period, last 14 days, per already-discovered
 * EC2 instance. Deliberately skips ExtendedStatistics (p99/p95): CloudWatch
 * returns those as a <ExtendedStatistics><entry><key>/<value></entry></...>
 * map, a shape this codebase's list-based XML helpers (built for repeated
 * sibling elements, not key/value maps) aren't set up to parse correctly,
 * and guessing at that parsing without a live response to verify against
 * would risk silently-wrong data rather than an honest gap. Average is a
 * real, standard rightsizing signal on its own (see
 * generateRecommendations.ts's rightsizing detection) — just a different,
 * simpler methodology than a P99-based one, not a fabricated substitute.
 *
 * Capped to whatever instance list the caller passes in — discovery.ts
 * limits that to a subrequest-budget-safe batch per step, same reasoning as
 * every other high-cardinality scanner this session.
 */
export async function scanEc2CpuMetrics(creds: AwsCreds, region: string, instances: Ec2InstanceRef[]): Promise<ScannedMetric[]> {
  const endpoint = `monitoring.${region}.amazonaws.com`;
  const endTime = new Date();
  const startTime = new Date(endTime.getTime() - LOOKBACK_DAYS * 24 * 60 * 60 * 1000);

  const out: ScannedMetric[] = [];
  for (const instance of instances) {
    const result = await callQueryApi(creds, {
      service: 'monitoring', region, host: endpoint, action: 'GetMetricStatistics', version: CLOUDWATCH_VERSION,
      params: {
        Namespace: 'AWS/EC2', MetricName: 'CPUUtilization',
        'Dimensions.member.1.Name': 'InstanceId', 'Dimensions.member.1.Value': instance.awsInstanceId,
        StartTime: startTime.toISOString(), EndTime: endTime.toISOString(), Period: String(PERIOD_SECONDS),
        'Statistics.member.1': 'Average', 'Statistics.member.2': 'Maximum',
      },
    });
    if (!result.ok) {
      console.error(`CloudWatch GetMetricStatistics failed for ${instance.awsInstanceId} in ${region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      continue;
    }

    const datapoints = extractListItems(extractSection(result.body as string, 'Datapoints'), 'member');
    for (const dp of datapoints) {
      const ts = field(dp, 'Timestamp');
      const unit = field(dp, 'Unit') ?? 'Percent';
      if (!ts) continue;
      const average = field(dp, 'Average');
      if (average !== null) {
        out.push({ resourceDbId: instance.dbId, resourceTypeKey: 'ec2_instance', metricName: 'CPUUtilization', namespace: 'AWS/EC2', unit, region, ts, value: Number(average) });
      }
      const max = field(dp, 'Maximum');
      if (max !== null) {
        out.push({ resourceDbId: instance.dbId, resourceTypeKey: 'ec2_instance', metricName: 'CPUUtilizationMaximum', namespace: 'AWS/EC2', unit, region, ts, value: Number(max) });
      }
    }
  }
  return out;
}
