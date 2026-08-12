import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SHIELD_RESOURCE_TYPES = ['shield_protection'] as const;

interface Protection { Id: string; Name?: string; ResourceArn?: string; ProtectionArn?: string }
interface ListProtectionsResponse { Protections?: Protection[] }

/**
 * AWS Shield — a global service, single endpoint in us-east-1 regardless of
 * ctx.region, same convention as cloudfront.ts/route53.ts. ListProtections
 * only returns results for accounts subscribed to Shield Advanced (the paid
 * tier); Shield Standard (free, automatic on every account) has no
 * enumerable "protections" via this API, so an unsubscribed account gets a
 * ResourceNotFoundException here — expected and common, not a real failure.
 */
export async function scanShield(ctx: ScannerContext): Promise<ScannedResource[]> {
  const result = await callJsonApi(ctx.creds, {
    service: 'shield', region: 'us-east-1', host: 'shield.us-east-1.amazonaws.com',
    target: 'AWSShield_20160616.ListProtections', body: {},
  });
  if (!result.ok) {
    console.error(`Shield ListProtections failed (continuing without it — likely no Shield Advanced subscription): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const protections = (result.body as ListProtectionsResponse).Protections ?? [];
  return protections.map((p) => ({
    resourceTypeKey: 'shield_protection', resourceId: p.ProtectionArn ?? p.Id, region: null, resourceName: p.Name,
    relationships: { resourceArn: p.ResourceArn },
  }));
}
