import { describe, expect, it } from 'vitest';
import { accountPublicAccessBlockResource } from './s3control';

describe('S3 account public access evidence', () => {
  it('retains all four account-level guardrails', () => {
    const row = accountPublicAccessBlockResource('111122223333', `
      <PublicAccessBlockConfiguration>
        <BlockPublicAcls>true</BlockPublicAcls>
        <IgnorePublicAcls>true</IgnorePublicAcls>
        <BlockPublicPolicy>false</BlockPublicPolicy>
        <RestrictPublicBuckets>true</RestrictPublicBuckets>
      </PublicAccessBlockConfiguration>`);
    expect(row.resourceTypeKey).toBe('s3_account_public_access_block');
    expect(row.metadata).toMatchObject({ configured: true, blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: false, restrictPublicBuckets: true });
  });

  it('records a missing configuration as an explicit unsafe state', () => {
    expect(accountPublicAccessBlockResource('111122223333', '', false).metadata)
      .toEqual({ configured: false, blockPublicAcls: false, ignorePublicAcls: false, blockPublicPolicy: false, restrictPublicBuckets: false });
  });
});
