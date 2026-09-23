import { callJsonApi } from '../awsApi';
import { reportWalk, toIso, walkPages } from './restJson';
import { siblingArn } from './dynamodb';
import { mapWithConcurrency, reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'Firehose_20150804';
/** DescribeDeliveryStream follow-ups per region-step (Workers subrequest budget). */
const MAX_STREAM_DETAILS = 40;

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const FIREHOSE_RESOURCE_TYPES = ['kinesis_firehose'] as const;

interface EncryptionConfiguration { NoEncryptionConfig?: string; KMSEncryptionConfig?: { AWSKMSKeyARN?: string } }
interface LoggingOptions { Enabled?: boolean }
interface DestinationDescription {
  DestinationId?: string;
  S3DestinationDescription?: { BucketARN?: string; RoleARN?: string; EncryptionConfiguration?: EncryptionConfiguration; CloudWatchLoggingOptions?: LoggingOptions };
  ExtendedS3DestinationDescription?: { BucketARN?: string; RoleARN?: string; EncryptionConfiguration?: EncryptionConfiguration; CloudWatchLoggingOptions?: LoggingOptions };
  RedshiftDestinationDescription?: { ClusterJDBCURL?: string; RoleARN?: string; CloudWatchLoggingOptions?: LoggingOptions };
  AmazonopensearchserviceDestinationDescription?: { DomainARN?: string; RoleARN?: string; CloudWatchLoggingOptions?: LoggingOptions };
  ElasticsearchDestinationDescription?: { DomainARN?: string; RoleARN?: string; CloudWatchLoggingOptions?: LoggingOptions };
  SplunkDestinationDescription?: { HECEndpoint?: string; CloudWatchLoggingOptions?: LoggingOptions };
  HttpEndpointDestinationDescription?: { EndpointConfiguration?: { Url?: string; Name?: string }; RoleARN?: string; CloudWatchLoggingOptions?: LoggingOptions };
}
export interface DeliveryStreamDescription {
  DeliveryStreamName?: string; DeliveryStreamARN?: string; DeliveryStreamStatus?: string; DeliveryStreamType?: string;
  VersionId?: string; CreateTimestamp?: number; LastUpdateTimestamp?: number;
  Destinations?: DestinationDescription[];
  DeliveryStreamEncryptionConfiguration?: { Status?: string; KeyType?: string; KeyARN?: string };
  Source?: { KinesisStreamSourceDescription?: { KinesisStreamARN?: string }; MSKSourceDescription?: { MSKClusterARN?: string } };
}

/** Host only -- an HTTP endpoint URL can carry a token in its path or query. */
function hostOf(url: string | undefined): string | null {
  if (!url) return null;
  try { return new URL(url).host; } catch { return null; }
}

/** Data-flow + encryption evidence for one delivery stream (FSBP DataFirehose.1). */
export function streamEvidence(s: DeliveryStreamDescription | undefined) {
  if (!s) return { detailsCollected: false };
  const dests = s.Destinations ?? [];
  const kinds: string[] = [];
  const bucketArns: string[] = [];
  const roleArns: string[] = [];
  let s3Unencrypted = false;
  let loggingOff = false;
  const httpHosts: string[] = [];
  for (const d of dests) {
    const s3 = d.ExtendedS3DestinationDescription ?? d.S3DestinationDescription;
    if (s3) {
      kinds.push(d.ExtendedS3DestinationDescription ? 'extended_s3' : 's3');
      if (s3.BucketARN) bucketArns.push(s3.BucketARN);
      if (s3.RoleARN) roleArns.push(s3.RoleARN);
      if (!s3.EncryptionConfiguration?.KMSEncryptionConfig) s3Unencrypted = true;
    }
    if (d.RedshiftDestinationDescription) kinds.push('redshift');
    if (d.AmazonopensearchserviceDestinationDescription || d.ElasticsearchDestinationDescription) kinds.push('opensearch');
    if (d.SplunkDestinationDescription) { kinds.push('splunk'); const h = hostOf(d.SplunkDestinationDescription.HECEndpoint); if (h) httpHosts.push(h); }
    if (d.HttpEndpointDestinationDescription) { kinds.push('http_endpoint'); const h = hostOf(d.HttpEndpointDestinationDescription.EndpointConfiguration?.Url); if (h) httpHosts.push(h); }
    const logging = (s3 ?? d.RedshiftDestinationDescription ?? d.AmazonopensearchserviceDestinationDescription ?? d.ElasticsearchDestinationDescription
      ?? d.SplunkDestinationDescription ?? d.HttpEndpointDestinationDescription)?.CloudWatchLoggingOptions;
    if (logging && logging.Enabled === false) loggingOff = true;
  }
  const enc = s.DeliveryStreamEncryptionConfiguration;
  return {
    detailsCollected: true,
    deliveryStreamType: s.DeliveryStreamType,
    versionId: s.VersionId,
    createdAt: s.CreateTimestamp,
    lastUpdateTimestamp: s.LastUpdateTimestamp,
    createdAtIso: toIso(s.CreateTimestamp),
    destinationIds: dests.map((d) => d.DestinationId).filter((id): id is string => !!id),
    // Server-side encryption of data in the stream itself.
    streamEncryptionEnabled: enc?.Status === 'ENABLED',
    streamEncryptionKeyType: enc?.KeyType ?? null,
    destinationKinds: [...new Set(kinds)],
    s3DestinationUnencrypted: s3Unencrypted,
    destinationLoggingDisabled: loggingOff,
    // Data leaving AWS: third-party HTTP endpoints (host only).
    externalEndpointHosts: [...new Set(httpHosts)],
    roleArns: [...new Set(roleArns)],
    s3BucketArns: [...new Set(bucketArns)],
  };
}

/**
 * Amazon Data Firehose delivery streams (JSON-RPC, Firehose_20150804).
 *
 * What changed, and why:
 *  - The listing loop STOPPED once it had 45 names, so stream 46 onward was
 *    never listed and looked deleted. Every page is now read; only the
 *    DescribeDeliveryStream fan-out is bounded, and streams past it keep a
 *    stable ARN identity (a failed describe used to fall back to the NAME,
 *    flipping the row's identity between scans).
 *  - Failures are reported rather than logged and dropped.
 *  - Evidence: stream encryption, S3 destination encryption, destination
 *    logging, source, and external HTTP/Splunk endpoints (host only).
 */
export async function scanFirehose(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `firehose.${ctx.region}.amazonaws.com`;

  // ListDeliveryStreams signals "more" with HasMoreDeliveryStreams rather than
  // a token; the last name of a page is the next page's exclusive start.
  const walk = await walkPages<string>(
    async (start) => {
      const r = await callJsonApi(ctx.creds, {
        service: 'firehose', region: ctx.region, host, target: `${TARGET_PREFIX}.ListDeliveryStreams`,
        body: { Limit: 100, ...(start ? { ExclusiveStartDeliveryStreamName: start } : {}) },
      });
      return r.ok
        ? { ok: true, status: r.status, body: (r.body ?? {}) as Record<string, unknown> }
        : { ok: false, status: r.status, body: null, error: r.errorMessage ?? r.errorCode ?? `status ${r.status}` };
    },
    (b) => b.DeliveryStreamNames,
    (b) => {
      const page = (b.DeliveryStreamNames as string[] | undefined) ?? [];
      return b.HasMoreDeliveryStreams === true && page.length > 0 ? page[page.length - 1] : undefined;
    },
  );
  reportWalk(ctx, walk, 'firehose', 'ListDeliveryStreams');
  const names = [...new Set(walk.items.filter((n): n is string => typeof n === 'string' && n !== ''))];

  const described = new Map<string, DeliveryStreamDescription>();
  await mapWithConcurrency(names.slice(0, MAX_STREAM_DETAILS), 6, async (name) => {
    const r = await callJsonApi(ctx.creds, { service: 'firehose', region: ctx.region, host, target: `${TARGET_PREFIX}.DescribeDeliveryStream`, body: { DeliveryStreamName: name } });
    const d = r.ok ? (r.body as { DeliveryStreamDescription?: DeliveryStreamDescription } | null)?.DeliveryStreamDescription : undefined;
    if (d) described.set(name, d);
  });

  const sampleArn = [...described.values()].find((d) => d.DeliveryStreamARN)?.DeliveryStreamARN;
  const out: ScannedResource[] = [];
  let unidentifiable = 0;
  for (const name of names) {
    const d = described.get(name);
    const arn = d?.DeliveryStreamARN ?? siblingArn(sampleArn, ':deliverystream/', name);
    if (!arn) { unidentifiable++; continue; }
    const evidence = streamEvidence(d);
    out.push({
      resourceTypeKey: 'kinesis_firehose', resourceId: arn, region: ctx.region, resourceName: name,
      state: d?.DeliveryStreamStatus,
      metadata: evidence,
      relationships: {
        sourceKinesisStreamArn: d?.Source?.KinesisStreamSourceDescription?.KinesisStreamARN ?? null,
        sourceMskClusterArn: d?.Source?.MSKSourceDescription?.MSKClusterARN ?? null,
        s3BucketArns: 's3BucketArns' in evidence ? evidence.s3BucketArns : [],
        kmsKeyArn: d?.DeliveryStreamEncryptionConfiguration?.KeyARN ?? null,
      },
    });
  }
  if (unidentifiable > 0) {
    console.error(`Firehose ${ctx.region}: ${unidentifiable} stream(s) could not be identified by ARN this step; coverage degraded.`);
    reportListingFailure(ctx, { service: 'firehose', action: 'DescribeDeliveryStream', region: ctx.region });
  }
  return out;
}
