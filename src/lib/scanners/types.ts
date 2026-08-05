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
}

export type ScannerFn = (ctx: ScannerContext) => Promise<ScannedResource[]>;
