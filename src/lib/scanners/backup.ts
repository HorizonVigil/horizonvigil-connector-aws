import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const BACKUP_RESOURCE_TYPES = ['backup_plan', 'backup_vault', 'backup_report_plan', 'backup_recovery_point'] as const;

interface BackupPlanEntry {
  BackupPlanId: string; BackupPlanArn?: string; BackupPlanName?: string; CreationDate?: number; VersionId?: string;
}
interface BackupVaultEntry {
  BackupVaultName: string; BackupVaultArn?: string; CreationDate?: number; NumberOfRecoveryPoints?: number; EncryptionKeyArn?: string;
}
interface ReportPlanEntry {
  ReportPlanArn?: string; ReportPlanName?: string; CreationTime?: number; LastAttemptedExecutionTime?: number;
}
interface RecoveryPointEntry {
  RecoveryPointArn: string; ResourceArn?: string; ResourceType?: string; Status?: string; CreationDate?: number; BackupSizeInBytes?: number;
}

/** AWS Backup is REST-JSON, like lambda.ts/efs.ts — plans, vaults, and report plans are independent list calls; recovery points are listed per-vault (see the loop below). */
export async function scanBackup(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'backup', ctx.region);
  const base = `https://backup.${ctx.region}.amazonaws.com`;
  const getJson = async (path: string): Promise<Record<string, unknown> | null> => {
    const res = await safeFetch(client, `${base}${path}`, { method: 'GET' });
    const text = await res.text();
    if (!res.ok) {
      console.error(`Backup GET ${path} failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };

  const out: ScannedResource[] = [];

  const plans = await getJson('/backup/plans/');
  for (const p of (plans?.BackupPlansList as BackupPlanEntry[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'backup_plan', resourceId: p.BackupPlanArn ?? p.BackupPlanId, region: ctx.region, resourceName: p.BackupPlanName,
      metadata: { createdAt: p.CreationDate, versionId: p.VersionId },
    });
  }

  const vaultsBody = await getJson('/backup-vaults/');
  const vaults = (vaultsBody?.BackupVaultList as BackupVaultEntry[] | undefined) ?? [];
  for (const v of vaults) {
    out.push({
      resourceTypeKey: 'backup_vault', resourceId: v.BackupVaultArn ?? v.BackupVaultName, region: ctx.region, resourceName: v.BackupVaultName,
      metadata: { createdAt: v.CreationDate, recoveryPointCount: v.NumberOfRecoveryPoints, encryptionKeyArn: v.EncryptionKeyArn },
    });
  }

  const reportPlans = await getJson('/audit/report-plans/');
  for (const rp of (reportPlans?.ReportPlans as ReportPlanEntry[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'backup_report_plan', resourceId: rp.ReportPlanArn ?? rp.ReportPlanName!, region: ctx.region, resourceName: rp.ReportPlanName,
      metadata: { createdAt: rp.CreationTime, lastAttemptedExecutionTime: rp.LastAttemptedExecutionTime },
    });
  }

  // Recovery points are listed per-vault, not account-wide — capped to the
  // first 5 vaults and 20 recovery points each to stay well inside
  // Cloudflare's free-tier ~50-subrequest budget for one invocation (3 calls
  // already made, up to 5 more here).
  for (const v of vaults.slice(0, 5)) {
    const points = await getJson(`/backup-vaults/${encodeURIComponent(v.BackupVaultName)}/recovery-points/?maxResults=20`);
    for (const rp of (points?.RecoveryPoints as RecoveryPointEntry[] | undefined) ?? []) {
      out.push({
        resourceTypeKey: 'backup_recovery_point', resourceId: rp.RecoveryPointArn, region: ctx.region,
        state: rp.Status, metadata: { resourceType: rp.ResourceType, createdAt: rp.CreationDate, sizeBytes: rp.BackupSizeInBytes },
        relationships: { backupVaultName: v.BackupVaultName, resourceArn: rp.ResourceArn },
      });
    }
  }

  return out;
}
