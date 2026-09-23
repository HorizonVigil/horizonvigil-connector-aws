import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { classifyRecord } from '../admission';
import type { ScannedResource } from './types';

/**
 * A resource identity must never be asserted non-null off a provider payload.
 *
 * `field()` returns `string | null`. Writing `field(x, 'Id')!` tells the
 * compiler a value is present that AWS is under no obligation to send, and
 * `resourceId` is one quarter of the identity
 * `(connection_id, resource_type_key, resource_id, generation)`.
 *
 * WHAT THE AUDIT GOT WRONG
 *
 * The audit said this let "a malformed provider response become a malformed
 * database row rather than a rejected record". That was overstated: admission
 * already quarantines a missing identity as MISSING_REQUIRED_IDENTITY, so the
 * row never reached the table. The assertion was a type-level lie whose
 * runtime consequence was caught downstream.
 *
 * That is why the fix is `?? ''` rather than `continue`. Skipping would make
 * the record vanish with no quarantine row and no reason code — trading a
 * caught problem for a silent one. An empty id still fails admission's
 * `trim() === ''` check, so the record stays observable with a typed reason
 * and a redacted payload.
 */
const DIR = __dirname;

/** The catalog is authoritative for known types, so the fixture must declare one. */
const CTX = {
  orgId: '00000000-0000-0000-0000-000000000001',
  connectionId: '00000000-0000-0000-0000-000000000002',
  accountNativeId: '111111111111',
  knownResourceTypes: new Set(['rds_instance']),
} as const;

describe('resource identity is never asserted non-null', () => {
  it('no scanner asserts a field() result as non-null', () => {
    const offenders: string[] = [];
    for (const f of readdirSync(DIR)) {
      if (!f.endsWith('.ts') || f.endsWith('.test.ts')) continue;
      const src = readFileSync(join(DIR, f), 'utf8');
      for (const m of src.matchAll(/field\([^)]*\)!/g)) offenders.push(`${f}: ${m[0]}`);
    }
    expect(offenders, `non-null assertion on provider data:\n${offenders.join('\n')}`).toEqual([]);
  });

  /**
   * The behaviour the fix relies on. If admission ever stopped quarantining an
   * empty identity, `?? ''` would become the very defect the audit described,
   * so this pins the downstream guarantee rather than trusting it.
   */
  it('admission quarantines an empty identity instead of storing it', async () => {
    const record = {
      resourceTypeKey: 'rds_instance',
      resourceId: '',
      region: 'us-east-1',
      metadata: {},
    } as unknown as ScannedResource;

    const outcome = await classifyRecord(record, CTX);

    expect(outcome.kind).toBe('quarantined');
    if (outcome.kind === 'quarantined') {
      expect(outcome.reasonCode).toBe('MISSING_REQUIRED_IDENTITY');
    }
  });

  /** A real id must still pass, or the guard above would be vacuous. */
  it('admits a record that carries a real identity', async () => {
    const record = {
      resourceTypeKey: 'rds_instance',
      resourceId: 'db-prod-1',
      region: 'us-east-1',
      metadata: {},
    } as unknown as ScannedResource;

    const outcome = await classifyRecord(record, CTX);

    expect(outcome.kind, 'a well-formed record must not be quarantined').toBe('accepted');
  });
});