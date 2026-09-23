import { callJsonApi } from '../awsApi';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const CLOUDTRAIL_RESOURCE_TYPES = ['cloudtrail_trail'] as const;

const TARGET_PREFIX = 'CloudTrail_20131101';

/** Per-trail follow-ups (status + selectors). A region holds at most a handful of trails. */
const TRAIL_CONCURRENCY = 4;

interface Trail {
  Name: string;
  S3BucketName?: string;
  S3KeyPrefix?: string;
  SnsTopicARN?: string;
  TrailARN?: string;
  IsMultiRegionTrail?: boolean;
  IsOrganizationTrail?: boolean;
  IncludeGlobalServiceEvents?: boolean;
  LogFileValidationEnabled?: boolean;
  HomeRegion?: string;
  KmsKeyId?: string;
  CloudWatchLogsLogGroupArn?: string;
  CloudWatchLogsRoleArn?: string;
  HasCustomEventSelectors?: boolean;
  HasInsightSelectors?: boolean;
}

/** CloudTrail's JSON protocol returns timestamps as epoch SECONDS; tests and older callers pass ISO strings. */
type AwsTimestamp = string | number;

interface TrailStatus {
  IsLogging?: boolean;
  LatestDeliveryTime?: AwsTimestamp;
  LatestNotificationTime?: AwsTimestamp;
  LatestDeliveryError?: string;
  LatestNotificationError?: string;
  LatestDigestDeliveryTime?: AwsTimestamp;
  LatestDigestDeliveryError?: string;
  LatestCloudWatchLogsDeliveryTime?: AwsTimestamp;
  LatestCloudWatchLogsDeliveryError?: string;
  StartLoggingTime?: AwsTimestamp;
  StopLoggingTime?: AwsTimestamp;
}

interface EventSelector {
  ReadWriteType?: 'ReadOnly' | 'WriteOnly' | 'All';
  IncludeManagementEvents?: boolean;
  DataResources?: { Type?: string; Values?: string[] }[];
  ExcludeManagementEventSources?: string[];
}

interface AdvancedFieldSelector {
  Field?: string;
  Equals?: string[];
  NotEquals?: string[];
  StartsWith?: string[];
  NotStartsWith?: string[];
  EndsWith?: string[];
  NotEndsWith?: string[];
}

interface AdvancedEventSelector { Name?: string; FieldSelectors?: AdvancedFieldSelector[] }

export interface EventSelectorsResponse {
  EventSelectors?: EventSelector[];
  AdvancedEventSelectors?: AdvancedEventSelector[];
}

/**
 * What the trail actually RECORDS, which is the question CIS 3.1 / FSBP
 * CloudTrail.1 ask ("multi-region trail capturing read AND write management
 * events"). A trail that is logging but has management events turned off,
 * or restricted to WriteOnly, is not an audit trail.
 *
 * `collected: false` means GetEventSelectors was unavailable -- NOT that the
 * trail records nothing. Posture must treat it as NOT_ASSESSED.
 */
export interface EventSelectorSummary {
  collected: boolean;
  mode: 'basic' | 'advanced' | null;
  managementEvents: boolean | null;
  managementReadWriteType: 'All' | 'ReadOnly' | 'WriteOnly' | null;
  excludedManagementEventSources: string[];
  dataEventsConfigured: boolean | null;
  selectorCount: number;
}

const NOT_COLLECTED: EventSelectorSummary = {
  collected: false,
  mode: null,
  managementEvents: null,
  managementReadWriteType: null,
  excludedManagementEventSources: [],
  dataEventsConfigured: null,
  selectorCount: 0,
};

function combineReadWrite(types: ('All' | 'ReadOnly' | 'WriteOnly')[]): 'All' | 'ReadOnly' | 'WriteOnly' | null {
  if (types.length === 0) return null;
  if (types.includes('All')) return 'All';
  const hasRead = types.includes('ReadOnly');
  const hasWrite = types.includes('WriteOnly');
  if (hasRead && hasWrite) return 'All';
  return hasRead ? 'ReadOnly' : 'WriteOnly';
}

export function summarizeEventSelectors(res: EventSelectorsResponse | null): EventSelectorSummary {
  if (res === null) return { ...NOT_COLLECTED };

  const advanced = res.AdvancedEventSelectors ?? [];
  if (advanced.length > 0) {
    const categoryOf = (s: AdvancedEventSelector) =>
      s.FieldSelectors?.find((f) => f.Field === 'eventCategory')?.Equals ?? [];
    const management = advanced.filter((s) => categoryOf(s).includes('Management'));
    const readWrite = management.map((s): 'All' | 'ReadOnly' | 'WriteOnly' => {
      const readOnly = s.FieldSelectors?.find((f) => f.Field === 'readOnly');
      if (readOnly?.Equals?.length === 1) return readOnly.Equals[0] === 'true' ? 'ReadOnly' : 'WriteOnly';
      return 'All';
    });
    const excluded = new Set<string>();
    for (const s of management) {
      for (const f of s.FieldSelectors ?? []) {
        if (f.Field === 'eventSource') for (const v of f.NotEquals ?? []) excluded.add(v);
      }
    }
    return {
      collected: true,
      mode: 'advanced',
      managementEvents: management.length > 0,
      managementReadWriteType: combineReadWrite(readWrite),
      excludedManagementEventSources: [...excluded].sort(),
      dataEventsConfigured: advanced.some((s) => categoryOf(s).includes('Data')),
      selectorCount: advanced.length,
    };
  }

  const basic = res.EventSelectors ?? [];
  // IncludeManagementEvents defaults to true when omitted.
  const management = basic.filter((s) => s.IncludeManagementEvents !== false);
  const excluded = new Set<string>();
  for (const s of management) for (const v of s.ExcludeManagementEventSources ?? []) excluded.add(v);
  return {
    collected: true,
    mode: basic.length > 0 ? 'basic' : null,
    managementEvents: management.length > 0,
    managementReadWriteType: combineReadWrite(management.map((s) => s.ReadWriteType ?? 'All')),
    excludedManagementEventSources: [...excluded].sort(),
    dataEventsConfigured: basic.some((s) => (s.DataResources?.length ?? 0) > 0),
    selectorCount: basic.length,
  };
}

/** Epoch seconds (JSON protocol) or ISO string → ISO string; anything else → null. */
export function toIsoTimestamp(value: AwsTimestamp | undefined | null): string | null {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return null;
    return new Date(value * 1000).toISOString();
  }
  return value;
}

/** Account ID segment of a trail ARN (arn:aws:cloudtrail:<region>:<account>:trail/<name>). */
export function accountIdFromArn(arn: string | undefined): string | null {
  const account = arn?.split(':')[4];
  return account && /^\d{12}$/.test(account) ? account : null;
}

export function trailMetadata(trail: Trail, status: TrailStatus | null, selectors: EventSelectorsResponse | null = null) {
  return {
    s3BucketName: trail.S3BucketName,
    s3KeyPrefix: trail.S3KeyPrefix ?? null,
    snsTopicArn: trail.SnsTopicARN ?? null,
    homeRegion: trail.HomeRegion ?? null,
    trailAccountId: accountIdFromArn(trail.TrailARN),
    isMultiRegionTrail: trail.IsMultiRegionTrail,
    isOrganizationTrail: trail.IsOrganizationTrail,
    includeGlobalServiceEvents: trail.IncludeGlobalServiceEvents ?? null,
    logFileValidationEnabled: trail.LogFileValidationEnabled,
    // Encryption at rest with a customer-managed key (CIS 3.5 / FSBP CloudTrail.2).
    kmsKeyId: trail.KmsKeyId ?? null,
    encryptedWithKms: Boolean(trail.KmsKeyId),
    // CloudWatch Logs integration (CIS 3.4 / FSBP CloudTrail.5).
    cloudWatchLogsLogGroupArn: trail.CloudWatchLogsLogGroupArn ?? null,
    cloudWatchLogsRoleArn: trail.CloudWatchLogsRoleArn ?? null,
    hasCustomEventSelectors: trail.HasCustomEventSelectors ?? null,
    hasInsightSelectors: trail.HasInsightSelectors ?? null,

    // Runtime status is kept separate from configuration: a trail whose
    // status could not be read is NOT a stopped trail.
    statusCollected: status !== null,
    isLogging: status?.IsLogging ?? null,
    latestDeliveryTime: toIsoTimestamp(status?.LatestDeliveryTime),
    latestNotificationTime: toIsoTimestamp(status?.LatestNotificationTime),
    latestDeliveryError: status?.LatestDeliveryError || null,
    latestDigestDeliveryTime: toIsoTimestamp(status?.LatestDigestDeliveryTime),
    latestDigestDeliveryError: status?.LatestDigestDeliveryError || null,
    latestCloudWatchLogsDeliveryTime: toIsoTimestamp(status?.LatestCloudWatchLogsDeliveryTime),
    latestCloudWatchLogsDeliveryError: status?.LatestCloudWatchLogsDeliveryError || null,
    startLoggingTime: toIsoTimestamp(status?.StartLoggingTime),
    stopLoggingTime: toIsoTimestamp(status?.StopLoggingTime),

    eventSelectors: summarizeEventSelectors(selectors),
  };
}

/**
 * DescribeTrails (JSON-RPC, same pattern as DynamoDB/ECS/KMS).
 *
 * includeShadowTrails is TRUE on purpose. With `false`, a MEMBER account of
 * an AWS Organization does not see the organization trail at all (to that
 * account it is a shadow trail), so every member account looked as if it had
 * no CloudTrail -- a false CRITICAL on the most basic audit control.
 *
 * With shadow trails included, a multi-region trail appears once per region;
 * keeping only rows whose HomeRegion matches ctx.region records each trail
 * exactly once (in its home region) and keeps GetTrailStatus /
 * GetEventSelectors pointed at the region that owns the trail.
 */
export async function scanCloudTrail(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `cloudtrail.${ctx.region}.amazonaws.com`;
  const call = (action: string, body: Record<string, unknown>) =>
    callJsonApi(ctx.creds, { service: 'cloudtrail', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.${action}`, body });

  const result = await call('DescribeTrails', { includeShadowTrails: true });
  if (!result.ok) {
    // callJsonApi's terminal-failure path reports this to onCallFailure, which
    // is what keeps the missing trails from being read as deleted.
    console.error(`CloudTrail DescribeTrails failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const trails = (result.body as { trailList?: Trail[] } | null)?.trailList ?? [];
  const seen = new Set<string>();
  const localTrails = trails.filter((t) => {
    if (!t?.Name) return false;
    if (t.HomeRegion && t.HomeRegion !== ctx.region) return false;
    const key = t.TrailARN ?? t.Name;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return mapWithConcurrency(localTrails, TRAIL_CONCURRENCY, async (t): Promise<ScannedResource> => {
    const trailRef = t.TrailARN ?? t.Name;
    const [statusResult, selectorsResult] = await Promise.all([
      call('GetTrailStatus', { Name: trailRef }),
      call('GetEventSelectors', { TrailName: trailRef }),
    ]);

    const status = statusResult.ok ? (statusResult.body as TrailStatus) ?? {} : null;
    if (!statusResult.ok) {
      console.error(`CloudTrail GetTrailStatus failed for ${t.Name} in ${ctx.region}; recording configuration with status unavailable.`);
    }
    const selectors = selectorsResult.ok ? (selectorsResult.body as EventSelectorsResponse) ?? {} : null;
    if (!selectorsResult.ok) {
      console.error(`CloudTrail GetEventSelectors failed for ${t.Name} in ${ctx.region}; recording event selectors as not collected.`);
    }

    return {
      resourceTypeKey: 'cloudtrail_trail',
      resourceId: trailRef,
      region: ctx.region,
      resourceName: t.Name,
      state: status?.IsLogging === true ? 'logging' : status?.IsLogging === false ? 'stopped' : undefined,
      metadata: trailMetadata(t, status, selectors),
      relationships: {
        s3BucketName: t.S3BucketName ?? null,
        kmsKeyId: t.KmsKeyId ?? null,
        cloudWatchLogsLogGroupArn: t.CloudWatchLogsLogGroupArn ?? null,
        snsTopicArn: t.SnsTopicARN ?? null,
      },
    };
  });
}