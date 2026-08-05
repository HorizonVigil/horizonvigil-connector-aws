import type { ScannerContext } from './types';

/**
 * Distinct from ScannedResource — a finding isn't a cloud resource (no
 * resourceTypeKey/catalog entry, no is_default/tags), it's a security
 * signal about one, so it gets its own shape and its own upsert target
 * (vulnerability_findings, not cloud_resources). `status` is deliberately
 * absent here: it's user/vanish-logic-owned after first insert (see
 * discovery.ts's finding upsert — new rows get the DB default 'open',
 * existing rows keep whatever status a user already set via PATCH
 * /findings/:id, since a finding scanner re-seeing something AWS still
 * considers active must never silently un-suppress it).
 */
export interface ScannedFinding {
  findingSource: string;
  awsFindingId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  cvssScore?: number;
  title: string;
  description?: string;
  complianceFrameworks?: string[];
  remediationLink?: string;
  discoveredAt: string;
  region: string | null;
  resourceArn?: string;
}

export type FindingScannerFn = (ctx: ScannerContext) => Promise<ScannedFinding[]>;
