import { describe, it, expect } from 'vitest';
import { checkCachedEligibility, type CachedResourceRow } from './remediationEligibility';

function resource(overrides: Partial<CachedResourceRow>): CachedResourceRow {
  return {
    id: 'res-1', connection_id: 'conn-1', resource_type_key: 'ec2_instance', resource_id: 'i-0abc',
    region: 'us-east-1', state: null, relationships: {},
    ...overrides,
  };
}

describe('checkCachedEligibility', () => {
  describe('stop_instance', () => {
    it('eligible when running', () => {
      expect(checkCachedEligibility('stop_instance', resource({ state: 'running' })).eligible).toBe(true);
    });
    it('not eligible when already stopped', () => {
      const result = checkCachedEligibility('stop_instance', resource({ state: 'stopped' }));
      expect(result.eligible).toBe(false);
      expect(result.reason).toMatch(/stopped/);
    });
  });

  describe('start_instance', () => {
    it('eligible when stopped', () => {
      expect(checkCachedEligibility('start_instance', resource({ state: 'stopped' })).eligible).toBe(true);
    });
    it('not eligible when already running', () => {
      expect(checkCachedEligibility('start_instance', resource({ state: 'running' })).eligible).toBe(false);
    });
  });

  describe('release_eip', () => {
    it('eligible when unassociated', () => {
      expect(checkCachedEligibility('release_eip', resource({ relationships: {} })).eligible).toBe(true);
    });
    it('not eligible when associated with an instance', () => {
      const result = checkCachedEligibility('release_eip', resource({ relationships: { instanceId: 'i-0abc' } }));
      expect(result.eligible).toBe(false);
    });
    it('not eligible when associated with a network interface only', () => {
      const result = checkCachedEligibility('release_eip', resource({ relationships: { networkInterfaceId: 'eni-0abc' } }));
      expect(result.eligible).toBe(false);
    });
  });

  describe('delete_volume', () => {
    it('eligible when unattached', () => {
      expect(checkCachedEligibility('delete_volume', resource({ relationships: { attachedInstanceIds: [] } })).eligible).toBe(true);
    });
    it('eligible when attachedInstanceIds is missing entirely', () => {
      expect(checkCachedEligibility('delete_volume', resource({ relationships: {} })).eligible).toBe(true);
    });
    it('not eligible when attached to an instance', () => {
      const result = checkCachedEligibility('delete_volume', resource({ relationships: { attachedInstanceIds: ['i-0abc'] } }));
      expect(result.eligible).toBe(false);
    });
    it('ignores null entries in attachedInstanceIds (treats as unattached)', () => {
      expect(checkCachedEligibility('delete_volume', resource({ relationships: { attachedInstanceIds: [null] } })).eligible).toBe(true);
    });
  });

  describe('delete_snapshot', () => {
    it('eligible when completed', () => {
      expect(checkCachedEligibility('delete_snapshot', resource({ state: 'completed' })).eligible).toBe(true);
    });
    it('not eligible while still pending', () => {
      const result = checkCachedEligibility('delete_snapshot', resource({ state: 'pending' }));
      expect(result.eligible).toBe(false);
      expect(result.reason).toMatch(/pending/);
    });
  });

  describe('resize_instance', () => {
    it('eligible when running', () => {
      expect(checkCachedEligibility('resize_instance', resource({ state: 'running' })).eligible).toBe(true);
    });
    it('eligible when stopped', () => {
      expect(checkCachedEligibility('resize_instance', resource({ state: 'stopped' })).eligible).toBe(true);
    });
    it('not eligible while pending', () => {
      const result = checkCachedEligibility('resize_instance', resource({ state: 'pending' }));
      expect(result.eligible).toBe(false);
      expect(result.reason).toMatch(/pending/);
    });
  });

  describe('deregister_ami', () => {
    it('eligible when available', () => {
      expect(checkCachedEligibility('deregister_ami', resource({ state: 'available' })).eligible).toBe(true);
    });
    it('not eligible while still pending', () => {
      const result = checkCachedEligibility('deregister_ami', resource({ state: 'pending' }));
      expect(result.eligible).toBe(false);
      expect(result.reason).toMatch(/pending/);
    });
  });
});
