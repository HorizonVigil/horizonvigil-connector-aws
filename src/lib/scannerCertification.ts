/**
 * Collectors that are implemented but have not been exercised against live
 * provider data for the required account/service state. Keeping this as code,
 * rather than comments spread across scanner files, prevents the product from
 * presenting implementation as production certification.
 */
export const UNVERIFIED_RESOURCE_SCANNERS = new Set([
  'imagebuilder',
  'inspector2',
  'lakeformation',
  'licensemanager',
  'macie',
  'memorydb',
  'mq',
  'outposts',
  'redshiftserverless',
  'savingsplans',
  'servicecatalog',
  'ses',
  'snowball',
  'trustedadvisorresource',
]);

export const UNVERIFIED_FINDING_SCANNERS = new Set([
  'inspector',
  'trustedadvisor',
]);

export interface ScannerCertificationSummary {
  state: 'implemented' | 'partially_verified';
  implementedResourceScanners: number;
  implementedFindingScanners: number;
  unverifiedResourceScanners: string[];
  unverifiedFindingScanners: string[];
}

export function scannerCertificationSummary(
  resourceScannerNames: readonly string[],
  findingScannerNames: readonly string[],
): ScannerCertificationSummary {
  const unverifiedResourceScanners = resourceScannerNames.filter((name) => UNVERIFIED_RESOURCE_SCANNERS.has(name)).sort();
  const unverifiedFindingScanners = findingScannerNames.filter((name) => UNVERIFIED_FINDING_SCANNERS.has(name)).sort();
  return {
    state: unverifiedResourceScanners.length || unverifiedFindingScanners.length ? 'partially_verified' : 'implemented',
    implementedResourceScanners: resourceScannerNames.length,
    implementedFindingScanners: findingScannerNames.length,
    unverifiedResourceScanners,
    unverifiedFindingScanners,
  };
}
