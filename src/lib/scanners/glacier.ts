import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const GLACIER_RESOURCE_TYPES = ['glacier_vault'] as const;

interface VaultList { VaultARN: string; VaultName?: string; CreationDate?: string; NumberOfArchives?: number; SizeInBytes?: number }
interface ListVaultsResponse { VaultList?: VaultList[] }

/** Amazon S3 Glacier — REST-JSON. `-` in the path stands for "the caller's own account", the standard Glacier convention for account-scoped calls. Requires the x-amz-glacier-version header on every request; omitting it produced an HTTP 400 with a misleadingly empty-looking body in an earlier version of this scanner. */
export async function scanGlacier(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'glacier', ctx.region);
  const res = await safeFetch(client, `https://glacier.${ctx.region}.amazonaws.com/-/vaults`, { method: 'GET', headers: { 'x-amz-glacier-version': '2012-06-01' } });
  const text = await res.text();
  if (!res.ok) {
    console.error(`Glacier ListVaults failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
    return [];
  }

  const vaults = ((text ? JSON.parse(text) : {}) as ListVaultsResponse).VaultList ?? [];
  return vaults.map((v) => ({
    resourceTypeKey: 'glacier_vault', resourceId: v.VaultARN, region: ctx.region, resourceName: v.VaultName,
    metadata: { creationDate: v.CreationDate, numberOfArchives: v.NumberOfArchives, sizeInBytes: v.SizeInBytes },
  }));
}
