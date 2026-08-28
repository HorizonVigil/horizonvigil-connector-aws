import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'AWSLicenseManager';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const LICENSEMANAGER_RESOURCE_TYPES = ['license_manager_configuration'] as const;

interface LicenseConfiguration {
  LicenseConfigurationArn: string;
  LicenseConfigurationId?: string;
  Name?: string;
  Description?: string;
  LicenseCountingType?: string;
  LicenseCount?: number;
  LicenseCountHardLimit?: boolean;
  ConsumedLicenses?: number;
  Status?: string;
  OwnerAccountId?: string;
  LicenseRules?: string[];
}
interface ListLicenseConfigurationsResponse {
  LicenseConfigurations?: LicenseConfiguration[];
  NextToken?: string;
}

/**
 * AWS License Manager — account-level license configurations (the rules an
 * account defines for counting/enforcing licenses, e.g. per-vCPU or
 * per-socket limits for BYOL software), not the individual license grants
 * themselves. JSON-RPC 1.1, regional per license-manager.<region>.amazonaws.com
 * (confirmed via the AWS SDK for Go's service.go: TargetPrefix
 * "AWSLicenseManager", JSONVersion "1.1", EndpointsID/SigningName
 * "license-manager"), same request shape as athena.ts/ce.ts. Single
 * ListLicenseConfigurations call with MaxResults set high enough to cover a
 * first pass in one page — NextToken pagination is not followed yet, so an
 * account with more configurations than MAX_RESULTS in a single region will
 * be undercounted until that's added.
 *
 * UNVERIFIED against a real account's actual response shape until this runs
 * against a live connection and gets checked -- same disclosed-uncertainty
 * convention as inspector2.ts (no test account had any license
 * configurations set up when this was written).
 */
export async function scanLicenseManager(ctx: ScannerContext): Promise<ScannedResource[]> {
  const MAX_RESULTS = 100;
  const result = await callJsonApi(ctx.creds, {
    service: 'license-manager', region: ctx.region, host: `license-manager.${ctx.region}.amazonaws.com`,
    target: `${TARGET_PREFIX}.ListLicenseConfigurations`, body: { MaxResults: MAX_RESULTS },
  });
  if (!result.ok) {
    console.error(`License Manager ListLicenseConfigurations failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
    return [];
  }

  const configs = (result.body as ListLicenseConfigurationsResponse).LicenseConfigurations ?? [];
  return configs.map((c) => ({
    resourceTypeKey: 'license_manager_configuration', resourceId: c.LicenseConfigurationArn, region: ctx.region, resourceName: c.Name,
    state: c.Status,
    metadata: {
      description: c.Description,
      licenseConfigurationId: c.LicenseConfigurationId,
      licenseCountingType: c.LicenseCountingType,
      licenseCount: c.LicenseCount,
      licenseCountHardLimit: c.LicenseCountHardLimit,
      consumedLicenses: c.ConsumedLicenses,
      ownerAccountId: c.OwnerAccountId,
      licenseRules: c.LicenseRules,
    },
  }));
}
