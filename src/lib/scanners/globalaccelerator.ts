import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const GLOBALACCELERATOR_RESOURCE_TYPES = ['global_accelerator'] as const;

interface Accelerator { AcceleratorArn: string; Name?: string; Status?: string; Enabled?: boolean; DnsName?: string; IpAddressType?: string }
interface ListAcceleratorsResponse { Accelerators?: Accelerator[] }

/**
 * AWS Global Accelerator — a global service with a single API endpoint
 * fixed to us-west-2 (confirmed against AWS's own CLI example, which shows
 * `--region us-west-2` regardless of the accelerator's actual traffic
 * regions), same fixed-region convention as cloudfront.ts/shield.ts.
 */
export async function scanGlobalAccelerator(ctx: ScannerContext): Promise<ScannedResource[]> {
  const result = await callJsonApi(ctx.creds, {
    service: 'globalaccelerator', region: 'us-west-2', host: 'globalaccelerator.us-west-2.amazonaws.com',
    target: 'GlobalAccelerator_V20180808.ListAccelerators', body: {},
  });
  if (!result.ok) {
    console.error(`Global Accelerator ListAccelerators failed (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const accelerators = (result.body as ListAcceleratorsResponse).Accelerators ?? [];
  return accelerators.map((a) => ({
    resourceTypeKey: 'global_accelerator', resourceId: a.AcceleratorArn, region: null, resourceName: a.Name,
    state: a.Status, isDefault: false, metadata: { enabled: a.Enabled, dnsName: a.DnsName, ipAddressType: a.IpAddressType },
  }));
}
