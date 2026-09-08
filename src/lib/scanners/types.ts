import type { AwsCreds } from '../awsApi';

export interface ScannedResource {
  resourceTypeKey: string;
  resourceId: string;
  resourceName?: string;
  region: string | null; // null for global services
  state?: string;
  isDefault?: boolean;
  tags?: Record<string, string>;
  metadata?: Record<string, unknown>;
  relationships?: Record<string, unknown>;
}

/**
 * Reported by a scanner when an individual AWS call fails but the scanner
 * continues with partial data.
 *
 * These were previously invisible: a scanner logged to console and returned an
 * empty body, so the step still counted as a success and finalize treated the
 * missing resources as deleted. Anything reported here marks the affected
 * resource types as degraded for this run, which makes them ineligible for
 * vanished-resource deletion (see discoveryFinalize.ts).
 */
export interface ApiFailure {
  /** AWS service the call belonged to, e.g. 'ec2'. */
  service: string;
  /** The API action that failed, e.g. 'DescribeInstances'. */
  action: string;
  region: string;
  /** Normalized code from awsErrors.ts — never a raw AWS message. */
  normalizedCode: string;
  /** Resource types this failure leaves incomplete, so finalize can protect them. */
  affectedResourceTypes: readonly string[];
}

export type ApiFailureSink = (failure: ApiFailure) => void;

export interface ScannerContext {
  creds: AwsCreds;
  region: string;
  /**
   * Optional so all ~120 existing scanners keep compiling untouched; a
   * scanner that does not report simply gets the previous behaviour.
   */
  onApiFailure?: ApiFailureSink;
}

export type ScannerFn = (ctx: ScannerContext) => Promise<ScannedResource[]>;
