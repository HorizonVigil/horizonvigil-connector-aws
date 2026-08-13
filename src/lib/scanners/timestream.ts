import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const TIMESTREAM_RESOURCE_TYPES = ['timestream_database'] as const;

interface Endpoint { Address: string; CachePeriodInMinutes?: number }
interface DescribeEndpointsResponse { Endpoints?: Endpoint[] }
interface Database { DatabaseName: string; Arn?: string; TableCount?: number; KmsKeyId?: string }
interface ListDatabasesResponse { Databases?: Database[] }

/**
 * Amazon Timestream — unlike almost every other AWS service, direct REST
 * API calls can't use a static `timestream.{region}.amazonaws.com` host;
 * Timestream requires the "endpoint discovery pattern" (confirmed against
 * AWS's developer guide): call DescribeEndpoints against the fixed
 * `ingest.timestream.{region}.amazonaws.com` host first, then make the
 * real ListDatabases call against whatever address it returns. A prior
 * version of this scanner skipped that step and got a 404 on every call.
 */
export async function scanTimestream(ctx: ScannerContext): Promise<ScannedResource[]> {
  const discoveryHost = `ingest.timestream.${ctx.region}.amazonaws.com`;
  const discovery = await callJsonApi(ctx.creds, {
    service: 'timestream', region: ctx.region, host: discoveryHost,
    target: 'Timestream_20181101.DescribeEndpoints', body: {},
  });
  if (!discovery.ok) {
    console.error(`Timestream DescribeEndpoints failed in ${ctx.region} (continuing without it): ${discovery.errorMessage ?? discovery.errorCode ?? discovery.status}`);
    return [];
  }
  const endpointAddress = (discovery.body as DescribeEndpointsResponse).Endpoints?.[0]?.Address;
  if (!endpointAddress) {
    console.error(`Timestream DescribeEndpoints returned no endpoints in ${ctx.region} (continuing without it).`);
    return [];
  }

  const result = await callJsonApi(ctx.creds, {
    service: 'timestream', region: ctx.region, host: endpointAddress,
    target: 'Timestream_20181101.ListDatabases', body: {},
  });
  if (!result.ok) {
    console.error(`Timestream ListDatabases failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const databases = (result.body as ListDatabasesResponse).Databases ?? [];
  return databases.map((d) => ({
    resourceTypeKey: 'timestream_database', resourceId: d.Arn ?? d.DatabaseName, region: ctx.region, resourceName: d.DatabaseName,
    metadata: { tableCount: d.TableCount, kmsKeyId: d.KmsKeyId },
  }));
}
