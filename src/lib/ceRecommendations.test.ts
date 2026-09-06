import { describe, it, expect } from 'vitest';
import {
  mapReservationRecommendation, mapRightsizingRecommendation, mapSavingsPlanRecommendation,
  type RIRecommendation, type RightsizingRecommendation,
} from './ceRecommendations';

describe('mapReservationRecommendation', () => {
  it('maps a real EC2 recommendation, copying dollar figures verbatim', () => {
    const rec: RIRecommendation = { TermInYears: 'ONE_YEAR', PaymentOption: 'NO_UPFRONT' };
    const detail = {
      AccountId: '111111111111',
      InstanceDetails: { EC2InstanceDetails: { InstanceType: 'm5.large', Region: 'us-east-1' } },
      RecommendedNumberOfInstancesToPurchase: '3',
      EstimatedMonthlySavingsAmount: '42.50',
      EstimatedMonthlyOnDemandCost: '120.00',
      UpfrontCost: '0',
    };
    const row = mapReservationRecommendation(rec, detail, 'AmazonEC2', 'conn-1');
    expect(row).not.toBeNull();
    expect(row!.potential_monthly_savings).toBe(42.5);
    expect(row!.category).toBe('reserved_instance');
    expect(row!.source).toBe('aws_ce_reservation');
    expect(row!.resource_id).toBeNull();
    expect(row!.external_key).toBe('ri:AmazonEC2:ONE_YEAR:NO_UPFRONT:111111111111');
    expect(row!.issue).toContain('m5.large');
    expect(row!.issue).toContain('3 Reserved Instance');
  });

  it('returns null rather than a fabricated zero-savings row', () => {
    const rec: RIRecommendation = {};
    const detail = { EstimatedMonthlySavingsAmount: '0' };
    expect(mapReservationRecommendation(rec, detail, 'AmazonEC2', 'conn-1')).toBeNull();
  });
});

describe('mapRightsizingRecommendation', () => {
  it('maps a real Modify recommendation with a resolved resource row', () => {
    const rec: RightsizingRecommendation = {
      CurrentInstance: { ResourceId: 'i-0abc123', InstanceType: 'm5.2xlarge', Region: 'us-west-2' },
      RightsizingType: 'Modify',
      ModifyRecommendationDetail: { TargetInstances: [{ EstimatedMonthlySavings: '80.00', ResourceDetails: { EC2ResourceDetails: { InstanceType: 'm5.xlarge' } } }] },
    };
    const row = mapRightsizingRecommendation(rec, 'conn-1', 'resource-row-uuid');
    expect(row).not.toBeNull();
    expect(row!.resource_id).toBe('resource-row-uuid');
    expect(row!.potential_monthly_savings).toBe(80);
    expect(row!.source).toBe('aws_ce_rightsizing');
    expect(row!.external_key).toBe('ce-rightsizing:i-0abc123');
    expect(row!.issue).toContain('m5.xlarge');
  });

  it('maps a real Terminate recommendation', () => {
    const rec: RightsizingRecommendation = {
      CurrentInstance: { ResourceId: 'i-0def456', InstanceType: 't3.large', Region: 'eu-west-1' },
      RightsizingType: 'Terminate',
      TerminateRecommendationDetail: { EstimatedMonthlySavings: '15.00' },
    };
    const row = mapRightsizingRecommendation(rec, 'conn-1', null);
    expect(row).not.toBeNull();
    expect(row!.resource_id).toBeNull();
    expect(row!.recommended_action).toMatch(/[Tt]erminate/);
  });

  it('returns null when AWS reports no real savings', () => {
    const rec: RightsizingRecommendation = {
      CurrentInstance: { ResourceId: 'i-0xyz' }, RightsizingType: 'Modify',
      ModifyRecommendationDetail: { TargetInstances: [{ EstimatedMonthlySavings: '0' }] },
    };
    expect(mapRightsizingRecommendation(rec, 'conn-1', null)).toBeNull();
  });

  it('returns null without a ResourceId to key off of', () => {
    const rec: RightsizingRecommendation = { RightsizingType: 'Terminate', TerminateRecommendationDetail: { EstimatedMonthlySavings: '10' } };
    expect(mapRightsizingRecommendation(rec, 'conn-1', null)).toBeNull();
  });
});

describe('mapSavingsPlanRecommendation', () => {
  it('maps a real Compute Savings Plan recommendation', () => {
    const detail = { AccountId: '222222222222', HourlyCommitmentToPurchase: '2.50', EstimatedMonthlySavingsAmount: '300.00', EstimatedSavingsPercentage: '18.3' };
    const row = mapSavingsPlanRecommendation(detail, 'COMPUTE_SP', 'ONE_YEAR', 'NO_UPFRONT', 'conn-1');
    expect(row).not.toBeNull();
    expect(row!.category).toBe('savings_plan');
    expect(row!.potential_monthly_savings).toBe(300);
    expect(row!.external_key).toBe('sp:COMPUTE_SP:ONE_YEAR:NO_UPFRONT:222222222222');
    expect(row!.issue).toContain('18.3%');
  });

  it('returns null with no real savings', () => {
    expect(mapSavingsPlanRecommendation({ EstimatedMonthlySavingsAmount: '0' }, 'COMPUTE_SP', 'ONE_YEAR', 'NO_UPFRONT', 'conn-1')).toBeNull();
  });
});
