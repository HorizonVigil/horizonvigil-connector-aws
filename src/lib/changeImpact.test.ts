import { describe, expect, it } from 'vitest';
import { classifyChangeImpact } from './changeImpact';

describe('classifyChangeImpact', () => {
  it('prioritizes exposure over a generic policy update', () => {
    const result = classifyChangeImpact('PutBucketPolicy');
    expect(result).toMatchObject({ severity: 'critical', securityImpact: 'exposure', requiresReview: true });
    expect(result.categories).toContain('compliance');
  });

  it('marks new billable capacity as a possible cost increase', () => {
    expect(classifyChangeImpact('RunInstances')).toMatchObject({ severity: 'high', costImpact: 'possible_increase' });
  });

  it('does not claim an impact for an unclassified event', () => {
    expect(classifyChangeImpact('FutureAwsOperation')).toMatchObject({ severity: 'unknown', costImpact: 'unknown', securityImpact: 'unknown' });
  });

  it('does not treat a rejected request as a completed change', () => {
    expect(classifyChangeImpact('PutBucketPolicy', 'AccessDenied')).toMatchObject({ severity: 'low', costImpact: 'none_expected', requiresReview: false });
  });
});
