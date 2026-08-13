import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const TIMESTREAM_RESOURCE_TYPES = ['timestream_database'] as const;

interface Database { DatabaseName: string; Arn?: string; TableCount?: number; KmsKeyId?: string }
interface ListDatabasesResponse { Databases?: Database[] }

/** Amazon Timestream — the write/management API (ListDatabases lives here, not the separate query.timestream.* endpoint used for running queries). */
export async function scanTimestream(ctx: ScannerContext): Promise<ScannedResource[]> {
  const result = await callJsonApi(ctx.creds, {
    service: 'timestream', region: ctx.region, host: `timestream.${ctx.region}.amazonaws.com`,
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
