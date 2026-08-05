import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'secretsmanager';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SECRETSMANAGER_RESOURCE_TYPES = ['secretsmanager_secret'] as const;

interface SecretListEntry {
  ARN: string; Name: string; Description?: string; LastChangedDate?: number; LastAccessedDate?: number;
  RotationEnabled?: boolean; Tags?: { Key: string; Value: string }[];
}

/** ListSecrets — one JSON-RPC call, gives everything needed for inventory without a per-secret follow-up (and never touches the actual secret value). */
export async function scanSecretsManager(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `secretsmanager.${ctx.region}.amazonaws.com`;
  const result = await callJsonApi(ctx.creds, { service: 'secretsmanager', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.ListSecrets`, body: {} });
  if (!result.ok) {
    console.error(`Secrets Manager ListSecrets failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const secrets = (result.body as { SecretList?: SecretListEntry[] }).SecretList ?? [];
  return secrets.map((s) => ({
    resourceTypeKey: 'secretsmanager_secret', resourceId: s.ARN, region: ctx.region, resourceName: s.Name,
    tags: Object.fromEntries((s.Tags ?? []).map((t) => [t.Key, t.Value])),
    metadata: { description: s.Description, lastChangedDate: s.LastChangedDate, lastAccessedDate: s.LastAccessedDate, rotationEnabled: s.RotationEnabled },
  }));
}
