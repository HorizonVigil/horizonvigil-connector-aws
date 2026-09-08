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

export interface ScannerContext {
  creds: AwsCreds;
  region: string;
  /**
   * Failure reporting is NOT here: it hangs off `creds.onCallFailure`
   * (awsApi.ts), because creds are what every scanner threads into every AWS
   * call. That covers all 111 scanners without any of them being edited.
   */
}

export type ScannerFn = (ctx: ScannerContext) => Promise<ScannedResource[]>;
