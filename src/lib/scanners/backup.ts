import { createAwsClient } from '../awsApi';
import { summarizePolicy, accountIdFromArn } from './policyEvidence';
import { fetchJson, reportWalk, toIso, walkPages, type PageWalk } from './restJson';
import { mapWithConcurrency, reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const BACKUP_RESOURCE_TYPES = ['backup_plan', 'backup_vault', 'backup_report_plan', 'backup_recovery_point'] as const;

/** Vaults whose recovery points are enumerated, and recovery points read per vault. */
const MAX_RECOVERY_POINT_VAULTS = 10;
const RECOVERY_POINT_PAGE_SIZE = 100;
const MAX_RECOVERY_POINT_PAGES = 2;
/** Vault access-policy lookups per region. */
const MAX_POLICY_LOOKUPS = 20;
const CONCURRENCY = 4;

interface BackupPlanEntry {
  BackupPlanId: string; BackupPlanArn?: string; BackupPlanName?: string; CreationDate?: number; VersionId?: string;
  LastExecutionDate?: number; DeletionDate?: number;
}
interface BackupVaultEntry {
  BackupVaultName: string; BackupVaultArn?: string; CreationDate?: number; NumberOfRecoveryPoints?: number; EncryptionKeyArn?: string;
  VaultType?: string; VaultState?: string; Locked?: boolean; MinRetentionDays?: number; MaxRetentionDays?: number; LockDate?: number;
}
interface ReportPlanEntry {
  ReportPlanArn?: string; ReportPlanName?: string; CreationTime?: number; LastAttemptedExecutionTime?: number; DeploymentStatus?: string;
}
interface RecoveryPointEntry {
  RecoveryPointArn: string; ResourceArn?: string; ResourceType?: string; Status?: string; CreationDate?: number; BackupSizeInBytes?: number;
  IsEncrypted?: boolean; EncryptionKeyArn?: string; CalculatedLifecycle?: { DeleteAt?: number; MoveToColdStorageAt?: number };
}

/**
 * AWS Backup (REST-JSON): plans, vaults and report plans are account-wide
 * list calls; recovery points are listed per vault.
 *
 * What changed, and why:
 *  - Every list paginates (nextToken/NextToken). Previously page one only.
 *  - Failed lists are reported, not returned as []; the recovery-point caps
 *    (vaults and points per vault) are now REPORTED as truncation. Before,
 *    points in vault 6+ and past the 20th in any vault were silently omitted
 *    and so tombstoned on every run.
 *  - A report plan with no ARN or name is recorded with an empty id (which
 *    admission quarantines with a reason) instead of `undefined!`.
 *  - Ransomware-resilience evidence per vault: Vault Lock state and retention
 *    bounds, and whether the vault access policy admits anyone or other
 *    accounts. Recovery points carry encryption state.
 *  - Epoch-second timestamps gain ISO twins (*Iso); originals are kept.
 */
export async function scanBackup(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'backup', ctx.region);
  const base = `https://backup.${ctx.region}.amazonaws.com`;
  const list = <T>(path: string, key: string, pageSize = 1000, maxPages?: number): Promise<PageWalk<T>> => walkPages<T>(
    (token) => fetchJson(client, `${base}${path}?maxResults=${pageSize}${token ? `&nextToken=${encodeURIComponent(token)}` : ''}`),
    (b) => b[key],
    (b) => b.NextToken ?? b.nextToken,
    maxPages,
  );

  const [plans, vaultsWalk, reportPlans] = await Promise.all([
    list<BackupPlanEntry>('/backup/plans/', 'BackupPlansList'),
    list<BackupVaultEntry>('/backup-vaults/', 'BackupVaultList'),
    list<ReportPlanEntry>('/audit/report-plans/', 'ReportPlans'),
  ]);
  reportWalk(ctx, plans, 'backup', 'ListBackupPlans');
  reportWalk(ctx, vaultsWalk, 'backup', 'ListBackupVaults');
  reportWalk(ctx, reportPlans, 'backup', 'ListReportPlans');

  const out: ScannedResource[] = [];

  for (const p of plans.items) {
    if (!p?.BackupPlanId && !p?.BackupPlanArn) continue;
    out.push({
      resourceTypeKey: 'backup_plan', resourceId: p.BackupPlanArn ?? p.BackupPlanId, region: ctx.region, resourceName: p.BackupPlanName,
      metadata: {
        createdAt: p.CreationDate, createdAtIso: toIso(p.CreationDate), versionId: p.VersionId,
        lastExecutionDateIso: toIso(p.LastExecutionDate),
      },
    });
  }

  const vaults = vaultsWalk.items.filter((v) => !!v?.BackupVaultName);
  const policies = new Map<string, ReturnType<typeof summarizePolicy> | 'none' | null>();
  await mapWithConcurrency(vaults.slice(0, MAX_POLICY_LOOKUPS), CONCURRENCY, async (v) => {
    const res = await fetchJson(client, `${base}/backup-vaults/${encodeURIComponent(v.BackupVaultName)}/access-policy`);
    if (res.ok) {
      policies.set(v.BackupVaultName, summarizePolicy(res.body?.Policy as string | undefined, accountIdFromArn(v.BackupVaultArn)));
    } else if (res.status === 404) {
      policies.set(v.BackupVaultName, 'none'); // no access policy: only IAM governs access
    } else {
      policies.set(v.BackupVaultName, null);
    }
  });

  for (const v of vaults) {
    const policy = policies.get(v.BackupVaultName);
    out.push({
      resourceTypeKey: 'backup_vault', resourceId: v.BackupVaultArn ?? v.BackupVaultName, region: ctx.region, resourceName: v.BackupVaultName,
      state: v.VaultState,
      metadata: {
        createdAt: v.CreationDate, createdAtIso: toIso(v.CreationDate),
        recoveryPointCount: v.NumberOfRecoveryPoints, encryptionKeyArn: v.EncryptionKeyArn,
        vaultType: v.VaultType ?? null,
        // Vault Lock: recovery points cannot be deleted early, even by an admin.
        locked: v.Locked ?? false,
        minRetentionDays: v.MinRetentionDays ?? null,
        maxRetentionDays: v.MaxRetentionDays ?? null,
        lockDateIso: toIso(v.LockDate),
        accessPolicyCollected: policy !== undefined && policy !== null,
        hasAccessPolicy: policy === undefined || policy === null ? null : policy !== 'none',
        accessPolicy: policy && policy !== 'none' ? policy : null,
      },
    });
  }

  for (const rp of reportPlans.items) {
    if (!rp) continue;
    out.push({
      resourceTypeKey: 'backup_report_plan', resourceId: rp.ReportPlanArn ?? rp.ReportPlanName ?? '', region: ctx.region, resourceName: rp.ReportPlanName,
      state: rp.DeploymentStatus,
      metadata: {
        createdAt: rp.CreationTime, createdAtIso: toIso(rp.CreationTime),
        lastAttemptedExecutionTime: rp.LastAttemptedExecutionTime, lastAttemptedExecutionIso: toIso(rp.LastAttemptedExecutionTime),
      },
    });
  }

  // Recovery points: per vault, bounded, and every bound is REPORTED.
  const rpVaults = vaults.slice(0, MAX_RECOVERY_POINT_VAULTS);
  let recoveryPointsComplete = vaultsWalk.complete && vaults.length <= MAX_RECOVERY_POINT_VAULTS;
  const perVault = await mapWithConcurrency(rpVaults, CONCURRENCY, async (v) => {
    const walk = await list<RecoveryPointEntry>(
      `/backup-vaults/${encodeURIComponent(v.BackupVaultName)}/recovery-points/`, 'RecoveryPoints',
      RECOVERY_POINT_PAGE_SIZE, MAX_RECOVERY_POINT_PAGES,
    );
    if (!walk.complete) recoveryPointsComplete = false;
    return { vault: v, points: walk.items };
  });
  if (!recoveryPointsComplete) {
    console.error(`Backup ${ctx.region}: recovery points were not fully enumerated (vault or per-vault cap, or a failed page); coverage degraded.`);
    reportListingFailure(ctx, { service: 'backup', action: 'ListRecoveryPointsByBackupVault', region: ctx.region, truncated: true });
  }

  for (const { vault, points } of perVault) {
    for (const rp of points) {
      if (!rp?.RecoveryPointArn) continue;
      out.push({
        resourceTypeKey: 'backup_recovery_point', resourceId: rp.RecoveryPointArn, region: ctx.region,
        state: rp.Status,
        metadata: {
          resourceType: rp.ResourceType, createdAt: rp.CreationDate, createdAtIso: toIso(rp.CreationDate), sizeBytes: rp.BackupSizeInBytes,
          isEncrypted: rp.IsEncrypted ?? null,
          encryptionKeyArn: rp.EncryptionKeyArn ?? null,
          deleteAtIso: toIso(rp.CalculatedLifecycle?.DeleteAt),
        },
        relationships: { backupVaultName: vault.BackupVaultName, resourceArn: rp.ResourceArn },
      });
    }
  }

  return out;
}