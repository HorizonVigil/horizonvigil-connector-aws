import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const FSX_RESOURCE_TYPES = ['fsx_file_system', 'fsx_backup', 'file_cache'] as const;

interface FileSystem { FileSystemId: string; FileSystemType?: string; Lifecycle?: string; StorageCapacity?: number; VpcId?: string; DNSName?: string }
interface DescribeFileSystemsResponse { FileSystems?: FileSystem[] }
interface Backup { BackupId: string; Lifecycle?: string; Type?: string; FileSystem?: { FileSystemId?: string } }
interface DescribeBackupsResponse { Backups?: Backup[] }
interface FileCache { FileCacheId: string; FileCacheType?: string; Lifecycle?: string; StorageCapacity?: number }
interface DescribeFileCachesResponse { FileCaches?: FileCache[] }

/** Amazon FSx — target prefix (AWSSimbaAPIService_v20180301) matches FSx's known internal codename ("Simba"). */
export async function scanFsx(ctx: ScannerContext): Promise<ScannedResource[]> {
  const host = `fsx.${ctx.region}.amazonaws.com`;
  const call = async (target: string, body: Record<string, unknown> = {}) =>
    callJsonApi(ctx.creds, { service: 'fsx', region: ctx.region, host, target: `AWSSimbaAPIService_v20180301.${target}`, body });

  const out: ScannedResource[] = [];

  const fsResult = await call('DescribeFileSystems');
  if (!fsResult.ok) {
    console.error(`FSx DescribeFileSystems failed in ${ctx.region} (continuing without it): ${fsResult.errorMessage ?? fsResult.errorCode ?? fsResult.status}`);
    return out;
  }
  for (const fs of (fsResult.body as DescribeFileSystemsResponse).FileSystems ?? []) {
    out.push({
      resourceTypeKey: 'fsx_file_system', resourceId: fs.FileSystemId, region: ctx.region,
      state: fs.Lifecycle, metadata: { type: fs.FileSystemType, storageCapacity: fs.StorageCapacity, dnsName: fs.DNSName }, relationships: { vpcId: fs.VpcId },
    });
  }

  const backupsResult = await call('DescribeBackups');
  for (const b of (backupsResult.ok ? (backupsResult.body as DescribeBackupsResponse).Backups : []) ?? []) {
    out.push({ resourceTypeKey: 'fsx_backup', resourceId: b.BackupId, region: ctx.region, state: b.Lifecycle, metadata: { type: b.Type }, relationships: { fileSystemId: b.FileSystem?.FileSystemId } });
  }

  const cachesResult = await call('DescribeFileCaches');
  for (const c of (cachesResult.ok ? (cachesResult.body as DescribeFileCachesResponse).FileCaches : []) ?? []) {
    out.push({ resourceTypeKey: 'file_cache', resourceId: c.FileCacheId, region: ctx.region, state: c.Lifecycle, metadata: { type: c.FileCacheType, storageCapacity: c.StorageCapacity } });
  }

  return out;
}
