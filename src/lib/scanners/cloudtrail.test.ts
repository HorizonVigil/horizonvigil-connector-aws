import { describe, expect, it } from 'vitest';
import { trailMetadata } from './cloudtrail';

describe('CloudTrail status evidence', () => {
  const trail = { Name: 'org-trail', TrailARN: 'arn:aws:cloudtrail:us-east-1:111122223333:trail/org-trail', IsMultiRegionTrail: true, IsOrganizationTrail: true, LogFileValidationEnabled: true };

  it('keeps runtime logging status separate from configuration', () => {
    expect(trailMetadata(trail, { IsLogging: true, LatestDeliveryTime: '2026-09-23T00:00:00Z' }))
      .toMatchObject({ isMultiRegionTrail: true, logFileValidationEnabled: true, statusCollected: true, isLogging: true });
  });

  it('does not call a trail stopped when GetTrailStatus was unavailable', () => {
    expect(trailMetadata(trail, null)).toMatchObject({ statusCollected: false, isLogging: null });
  });
});
