import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const EFS_RESOURCE_TYPES = ['efs_file_system', 'efs_access_point'] as const;

interface EfsFileSystem {
  FileSystemId: string; Name?: string; CreationTime?: string; LifeCycleState?: string;
  SizeInBytes?: { Value?: number }; PerformanceMode?: string; ThroughputMode?: string; Encrypted?: boolean;
}
interface EfsAccessPoint {
  AccessPointId: string; AccessPointArn?: string; Name?: string; FileSystemId?: string; LifeCycleState?: string;
}

/** EFS is REST-JSON, like lambda.ts — one page (up to AWS's default max) of DescribeFileSystems, plus one account-wide DescribeAccessPoints call (no FileSystemId filter needed to get every access point in the region). */
export async function scanEfs(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'elasticfilesystem', ctx.region);
  const base = `https://elasticfilesystem.${ctx.region}.amazonaws.com`;
  const getJson = async (path: string): Promise<Record<string, unknown> | null> => {
    const res = await safeFetch(client, `${base}${path}`, { method: 'GET' });
    const text = await res.text();
    if (!res.ok) {
      console.error(`EFS GET ${path} failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };

  const out: ScannedResource[] = [];

  const fsBody = await getJson('/2015-02-01/file-systems');
  for (const fs of (fsBody?.FileSystems as EfsFileSystem[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'efs_file_system', resourceId: fs.FileSystemId, region: ctx.region, resourceName: fs.Name ?? fs.FileSystemId,
      state: fs.LifeCycleState,
      metadata: {
        createdAt: fs.CreationTime, sizeBytes: fs.SizeInBytes?.Value, performanceMode: fs.PerformanceMode,
        throughputMode: fs.ThroughputMode, encrypted: fs.Encrypted,
      },
    });
  }

  const apBody = await getJson('/2015-02-01/access-points');
  for (const ap of (apBody?.AccessPoints as EfsAccessPoint[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'efs_access_point', resourceId: ap.AccessPointArn ?? ap.AccessPointId, region: ctx.region, resourceName: ap.Name ?? ap.AccessPointId,
      state: ap.LifeCycleState, relationships: { fileSystemId: ap.FileSystemId },
    });
  }

  return out;
}
