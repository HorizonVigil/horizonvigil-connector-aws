import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'TrentService';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const KMS_RESOURCE_TYPES = ['kms_key', 'kms_alias'] as const;

interface KeyMetadata {
  KeyId: string; Arn?: string; Enabled?: boolean; Description?: string; KeyState?: string;
  KeyUsage?: string; KeyManager?: string; Origin?: string; CreationDate?: number;
}

/**
 * Keys and their aliases — one JSON-RPC signer. ListKeys only gives bare
 * KeyIds, so DescribeKey fills in state/description, capped at 45 keys for
 * the same free-tier subrequest-budget reasoning as DynamoDB's
 * DescribeTable follow-ups. AWS-managed keys (KeyManager=AWS) are included
 * rather than filtered out here — unlike IAM's Scope=Local filter on
 * ListPolicies, KMS doesn't expose KeyManager until after DescribeKey, so
 * there's no cheap way to exclude them up front.
 */
export async function scanKms(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `kms.${ctx.region}.amazonaws.com`;
  const call = async (action: string, body: Record<string, unknown> = {}) => {
    const result = await callJsonApi(ctx.creds, { service: 'kms', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.${action}`, body });
    if (!result.ok) {
      console.error(`KMS ${action} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return null;
    }
    return result.body as Record<string, unknown>;
  };

  const out: ScannedResource[] = [];

  const listKeys = await call('ListKeys');
  const keyIds = ((listKeys?.Keys as { KeyId: string }[] | undefined) ?? []).map((k) => k.KeyId).slice(0, 45);
  const descriptions = await Promise.all(keyIds.map((id) => call('DescribeKey', { KeyId: id })));
  for (let i = 0; i < keyIds.length; i++) {
    const meta = descriptions[i]?.KeyMetadata as KeyMetadata | undefined;
    out.push({
      resourceTypeKey: 'kms_key', resourceId: meta?.Arn ?? keyIds[i], region: ctx.region, resourceName: keyIds[i],
      state: meta?.KeyState, metadata: {
        enabled: meta?.Enabled, description: meta?.Description, keyUsage: meta?.KeyUsage,
        keyManager: meta?.KeyManager, origin: meta?.Origin, createdAt: meta?.CreationDate,
      },
    });
  }

  const listAliases = await call('ListAliases');
  const aliases = (listAliases?.Aliases as { AliasName: string; AliasArn?: string; TargetKeyId?: string }[] | undefined) ?? [];
  for (const a of aliases) {
    out.push({
      resourceTypeKey: 'kms_alias', resourceId: a.AliasArn ?? a.AliasName, region: ctx.region, resourceName: a.AliasName,
      relationships: { targetKeyId: a.TargetKeyId },
    });
  }

  return out;
}
