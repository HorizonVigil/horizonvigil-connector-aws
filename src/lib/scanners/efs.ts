import { createAwsClient } from '../awsApi';
import { accountIdFromArn, summarizePolicy } from './policyEvidence';
import { fetchJson, reportWalk, toIso, walkPages } from './restJson';
import { mapWithConcurrency } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const EFS_RESOURCE_TYPES = ['efs_file_system', 'efs_access_point'] as const;

/** Per-file-system policy + backup-policy lookups per region-step. */
const MAX_FS_DETAILS = 25;

interface EfsFileSystem {
  FileSystemId: string; FileSystemArn?: string; Name?: string; CreationTime?: number | string; LifeCycleState?: string;
  SizeInBytes?: { Value?: number }; PerformanceMode?: string; ThroughputMode?: string; Encrypted?: boolean; KmsKeyId?: string;
  NumberOfMountTargets?: number; AvailabilityZoneName?: string;
  FileSystemProtection?: { ReplicationOverwriteProtection?: string };
}
export interface EfsAccessPoint {
  AccessPointId: string; AccessPointArn?: string; Name?: string; FileSystemId?: string; LifeCycleState?: string;
  PosixUser?: { Uid?: number; Gid?: number };
  RootDirectory?: { Path?: string };
}

/** Access-point evidence (FSBP EFS.3 / EFS.4). */
export function accessPointEvidence(ap: EfsAccessPoint) {
  const path = ap.RootDirectory?.Path ?? '/';
  return {
    rootDirectoryPath: path,
    // EFS.3: an access point should confine clients to a sub-directory.
    enforcesRootDirectory: path !== '/',
    // EFS.4: an access point should enforce a non-root POSIX identity.
    enforcesUserIdentity: ap.PosixUser !== undefined,
    posixUid: ap.PosixUser?.Uid ?? null,
    posixUserIsRoot: ap.PosixUser?.Uid === 0,
  };
}

/**
 * Amazon EFS file systems and access points (REST-JSON, 2015-02-01).
 *
 * What changed, and why:
 *  - Both lists paginate: file systems on Marker/NextMarker, access points on
 *    NextToken. The previous version read one page of each.
 *  - Failures are reported rather than returned as nothing; bodies are
 *    parsed defensively.
 *  - Evidence: KMS key, backup policy (EFS.2), the file-system resource
 *    policy (anonymous/cross-account mount access), single-AZ (One Zone)
 *    storage, and access-point root-directory / POSIX-user enforcement.
 *
 * Note: SizeInBytes is refreshed by AWS roughly hourly, so file-system rows
 * change often by nature. Kept for existing consumers.
 */
export async function scanEfs(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'elasticfilesystem', ctx.region);
  const base = `https://elasticfilesystem.${ctx.region}.amazonaws.com/2015-02-01`;

  const [fsWalk, apWalk] = await Promise.all([
    walkPages<EfsFileSystem>(
      (marker) => fetchJson(client, `${base}/file-systems?MaxItems=100${marker ? `&Marker=${encodeURIComponent(marker)}` : ''}`),
      (b) => b.FileSystems,
      (b) => b.NextMarker,
    ),
    walkPages<EfsAccessPoint>(
      (token) => fetchJson(client, `${base}/access-points?MaxResults=100${token ? `&NextToken=${encodeURIComponent(token)}` : ''}`),
      (b) => b.AccessPoints,
      (b) => b.NextToken,
    ),
  ]);
  reportWalk(ctx, fsWalk, 'elasticfilesystem', 'DescribeFileSystems');
  reportWalk(ctx, apWalk, 'elasticfilesystem', 'DescribeAccessPoints');

  const fileSystems = fsWalk.items.filter((f) => !!f?.FileSystemId);
  const details = new Map<string, { backup: string | null; policy: ReturnType<typeof summarizePolicy> | 'none' | null }>();
  await mapWithConcurrency(fileSystems.slice(0, MAX_FS_DETAILS), 5, async (f) => {
    const [backup, policy] = await Promise.all([
      fetchJson(client, `${base}/file-systems/${encodeURIComponent(f.FileSystemId)}/backup-policy`),
      fetchJson(client, `${base}/file-systems/${encodeURIComponent(f.FileSystemId)}/policy`),
    ]);
    details.set(f.FileSystemId, {
      // 404 PolicyNotFound on backup-policy means automatic backups are off.
      backup: backup.ok ? (((backup.body?.BackupPolicy as { Status?: string } | undefined)?.Status) ?? null) : backup.status === 404 ? 'DISABLED' : null,
      policy: policy.ok ? summarizePolicy(policy.body?.Policy as string | undefined, accountIdFromArn(f.FileSystemArn)) : policy.status === 404 ? 'none' : null,
    });
  });

  const out: ScannedResource[] = [];
  for (const fs of fileSystems) {
    const d = details.get(fs.FileSystemId);
    out.push({
      resourceTypeKey: 'efs_file_system', resourceId: fs.FileSystemId, region: ctx.region, resourceName: fs.Name ?? fs.FileSystemId,
      state: fs.LifeCycleState,
      metadata: {
        createdAt: fs.CreationTime, sizeBytes: fs.SizeInBytes?.Value, performanceMode: fs.PerformanceMode,
        throughputMode: fs.ThroughputMode, encrypted: fs.Encrypted,
        createdAtIso: toIso(fs.CreationTime),
        kmsKeyId: fs.KmsKeyId ?? null,
        numberOfMountTargets: fs.NumberOfMountTargets ?? null,
        // One Zone storage lives in a single AZ.
        oneZoneAvailabilityZone: fs.AvailabilityZoneName ?? null,
        replicationOverwriteProtection: fs.FileSystemProtection?.ReplicationOverwriteProtection ?? null,
        detailsCollected: d !== undefined,
        // EFS.2: automatic backups via AWS Backup.
        automaticBackupsStatus: d?.backup ?? null,
        hasResourcePolicy: !d || d.policy === null ? null : d.policy !== 'none',
        resourcePolicy: d && d.policy && d.policy !== 'none' ? d.policy : null,
      },
      relationships: { kmsKeyId: fs.KmsKeyId ?? null },
    });
  }

  for (const ap of apWalk.items) {
    if (!ap?.AccessPointId) continue;
    out.push({
      resourceTypeKey: 'efs_access_point', resourceId: ap.AccessPointArn ?? ap.AccessPointId, region: ctx.region, resourceName: ap.Name ?? ap.AccessPointId,
      state: ap.LifeCycleState,
      metadata: accessPointEvidence(ap),
      relationships: { fileSystemId: ap.FileSystemId },
    });
  }
  return out;
}
