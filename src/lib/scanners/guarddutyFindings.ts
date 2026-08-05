import { createAwsClient } from '../awsApi';
import type { ScannerContext } from './types';
import type { ScannedFinding } from './findingTypes';

interface GuardDutyResource {
  ResourceType?: string;
  InstanceDetails?: { InstanceId?: string };
  S3BucketDetails?: { Name?: string }[];
  AccessKeyDetails?: { AccessKeyId?: string; UserName?: string };
  EksClusterDetails?: { Name?: string };
  EcsClusterDetails?: { Name?: string };
  RdsDbInstanceDetails?: { DbInstanceIdentifier?: string };
  LambdaDetails?: { FunctionArn?: string };
}

interface GuardDutyFinding {
  Id: string;
  Type?: string;
  Severity?: number;
  Title?: string;
  Description?: string;
  CreatedAt?: string;
  Region?: string;
  Resource?: GuardDutyResource;
  Service?: { Archived?: boolean };
}

/** GuardDuty's severity is a 0.1-8.9 float, not a label — bucketed per AWS's own console thresholds (docs.aws.amazon.com/guardduty: Low 1.0-3.9, Medium 4.0-6.9, High 7.0-8.9). GuardDuty has no "critical"/"informational" tier of its own. */
function severityFromScore(score: number | undefined): ScannedFinding['severity'] {
  if (score === undefined) return 'informational';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/** Resource identity varies by type — best-effort single string for the resource_arn column (a display/debug field, not a real FK), never blocking ingestion when a shape isn't one of these common ones. */
function resourceArnFrom(resource: GuardDutyResource | undefined): string | undefined {
  if (!resource) return undefined;
  return (
    resource.InstanceDetails?.InstanceId ??
    resource.S3BucketDetails?.[0]?.Name ??
    resource.AccessKeyDetails?.AccessKeyId ??
    resource.EksClusterDetails?.Name ??
    resource.EcsClusterDetails?.Name ??
    resource.RdsDbInstanceDetails?.DbInstanceIdentifier ??
    resource.LambdaDetails?.FunctionArn ??
    undefined
  );
}

/**
 * GuardDuty findings are REST-JSON (path-based, like guardduty.ts's detector
 * scan) — ListFindings gets ids, GetFindings (up to 50 per call) fills in
 * detail. Capped at 2 pages / 100 ids so one step always fits Cloudflare's
 * free-tier subrequest budget regardless of how many findings an account
 * has; a large backlog is caught up over repeated scans (last_seen_at keeps
 * re-surfacing ones still active, so nothing is silently lost, just spread
 * across runs). Archived findings (Service.Archived — AWS's own >90-day
 * auto-archive) are skipped entirely, same reasoning as SecurityHub's
 * RecordState !== 'ACTIVE' filter below.
 */
export async function scanGuardDutyFindings(ctx: ScannerContext): Promise<ScannedFinding[]> {
  const client = createAwsClient(ctx.creds, 'guardduty', ctx.region);
  const base = `https://guardduty.${ctx.region}.amazonaws.com`;

  const getJson = async (path: string): Promise<Record<string, unknown> | null> => {
    const res = await client.fetch(`${base}${path}`, { method: 'GET' });
    const text = await res.text();
    if (!res.ok) {
      console.error(`GuardDuty GET ${path} failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };
  const postJson = async (path: string, body: unknown): Promise<Record<string, unknown> | null> => {
    const res = await client.fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const text = await res.text();
    if (!res.ok) {
      console.error(`GuardDuty POST ${path} failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };

  const detectorIds = ((await getJson('/detector')) as { DetectorIds?: string[] } | null)?.DetectorIds ?? [];

  const out: ScannedFinding[] = [];
  for (const detectorId of detectorIds) {
    let nextToken: string | undefined;
    let findingIds: string[] = [];
    for (let page = 0; page < 2; page++) {
      const list = await postJson(`/detector/${encodeURIComponent(detectorId)}/findings`, {
        maxResults: 50,
        nextToken,
        sortCriteria: { attributeName: 'updatedAt', orderBy: 'DESC' },
      });
      if (!list) break;
      findingIds = findingIds.concat((list.FindingIds as string[] | undefined) ?? []);
      nextToken = list.NextToken as string | undefined;
      if (!nextToken) break;
    }
    if (findingIds.length === 0) continue;

    for (let i = 0; i < findingIds.length; i += 50) {
      const batch = findingIds.slice(i, i + 50);
      const result = await postJson(`/detector/${encodeURIComponent(detectorId)}/findings/get`, { findingIds: batch });
      if (!result) continue;
      const findings = (result.Findings as GuardDutyFinding[] | undefined) ?? [];
      for (const f of findings) {
        if (f.Service?.Archived) continue;
        out.push({
          findingSource: 'guardduty',
          awsFindingId: f.Id,
          severity: severityFromScore(f.Severity),
          cvssScore: f.Severity,
          title: f.Title ?? f.Type ?? 'GuardDuty finding',
          description: f.Description,
          complianceFrameworks: [],
          discoveredAt: f.CreatedAt ?? new Date().toISOString(),
          region: f.Region ?? ctx.region,
          resourceArn: resourceArnFrom(f.Resource),
        });
      }
    }
  }
  return out;
}
