import { describe, expect, it } from 'vitest';
import { FINDING_SCANNERS, GLOBAL_SCANNERS, REGIONAL_SCANNERS } from '../routes/discovery';
import {
  scannerCertificationSummary,
  UNVERIFIED_FINDING_SCANNERS,
  UNVERIFIED_RESOURCE_SCANNERS,
} from './scannerCertification';

describe('AWS scanner production certification', () => {
  const resources = [...Object.keys(REGIONAL_SCANNERS), ...Object.keys(GLOBAL_SCANNERS)];
  const findings = Object.keys(FINDING_SCANNERS);

  it('does not silently drop a named unverified scanner from the live registry', () => {
    for (const scanner of UNVERIFIED_RESOURCE_SCANNERS) expect(resources, scanner).toContain(scanner);
    for (const scanner of UNVERIFIED_FINDING_SCANNERS) expect(findings, scanner).toContain(scanner);
  });

  it('reports the live implementation as partially verified while live-evidence gaps remain', () => {
    const result = scannerCertificationSummary(resources, findings);
    expect(result.state).toBe('partially_verified');
    expect(result.unverifiedResourceScanners).toContain('servicecatalog');
    expect(result.unverifiedFindingScanners).toContain('inspector');
    expect(result.implementedResourceScanners).toBe(resources.length);
    expect(result.implementedFindingScanners).toBe(findings.length);
  });
});
