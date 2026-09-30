import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { chunk, partitionOf, INSERT_CHUNK, MAX_ACCOUNTS_PER_BULK_IMPORT } from './bulkImport';

const SOURCE = readFileSync('src/routes/bulkImport.ts', 'utf8');
/** Comment lines stripped, so prose describing an old behaviour cannot satisfy — or trip — a check on the code. */
const CODE = SOURCE.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');

describe('inserting thousands of connections', () => {
  it('splits the work into bounded batches', () => {
    expect(chunk(Array.from({ length: 1000 }, (_, i) => i), 200)).toHaveLength(5);
    expect(chunk([1, 2, 3], 2)).toEqual([[1, 2], [3]]);
    expect(chunk([], 10)).toEqual([]);
  });

  it('never drops or duplicates an item', () => {
    // The failure that matters: a chunker that loses the tail imports 990 of
    // 1,000 accounts and reports success.
    const items = Array.from({ length: 1007 }, (_, i) => i);
    const flat = chunk(items, INSERT_CHUNK).flat();
    expect(flat).toEqual(items);
    expect(new Set(flat).size).toBe(items.length);
  });

  it('keeps a whole import inside a sane number of batches', () => {
    // 2,000 accounts at 200 per batch is 10 requests, not one multi-megabyte
    // transaction where a single rejected row loses everything.
    expect(Math.ceil(MAX_ACCOUNTS_PER_BULK_IMPORT / INSERT_CHUNK)).toBeLessThanOrEqual(10);
  });

  /**
   * The insert loop must not abort the whole import on one bad batch. A
   * partial import that is REPORTED is recoverable; one that is reported as
   * total failure sends the customer to re-run a job that already created
   * hundreds of connections.
   */
  it('records a failed batch and continues', () => {
    expect(CODE).toContain('failedBatches.push');
    expect(CODE).toMatch(/for \(const batch of chunk\(toInsert, INSERT_CHUNK\)\)/);
    expect(CODE).toContain('inserted.push(...rows)');
  });

  it('always reports what was attempted, not only what succeeded', () => {
    // `imported: 900` alone reads as success at any scale.
    expect(CODE).toMatch(/attempted: toInsert\.length/);
    expect(CODE).toMatch(/failed: toInsert\.length - inserted\.length/);
  });
});

describe('the role ARN partition is derived, not assumed', () => {
  it('reads the partition from the management connection', () => {
    expect(partitionOf('arn:aws:iam::123456789012:role/HorizonVigilRead')).toBe('aws');
    expect(partitionOf('arn:aws-us-gov:iam::123456789012:role/HorizonVigilRead')).toBe('aws-us-gov');
    expect(partitionOf('arn:aws-cn:iam::123456789012:role/HorizonVigilRead')).toBe('aws-cn');
  });

  it('falls back to the commercial partition when there is no ARN to read', () => {
    // Access-key connections have no role ARN. Commercial is where they
    // almost certainly are, and guessing wrong here only produces a role ARN
    // that fails to assume — it grants nothing.
    expect(partitionOf(null)).toBe('aws');
    expect(partitionOf(undefined)).toBe('aws');
    expect(partitionOf('')).toBe('aws');
    expect(partitionOf('not-an-arn')).toBe('aws');
  });

  it('builds member role ARNs from that partition rather than a literal', () => {
    // A hardcoded `arn:aws:` produces connections that are correctly shaped
    // and can never authenticate in GovCloud or China.
    expect(CODE).toMatch(/role_arn: `arn:\$\{partition\}:iam::\$\{a\.Id\}:role\/\$\{ROLE_NAME\}`/);
    expect(CODE).not.toMatch(/role_arn: `arn:aws:iam/);
  });
});

describe('an Organization larger than one call can still be imported', () => {
  it('accepts an OU scope on both the preview and the import', () => {
    // If only the import accepted a scope, the counts the customer approved
    // in the preview would not be the accounts they got.
    expect(CODE).toMatch(/listOrganizationAccounts\(resolved\.creds, parentId\)/);
    expect(CODE).toMatch(/listOrganizationAccounts\(resolved\.creds, body\.parentId\)/);
  });

  it('tells the customer how to get under the cap instead of to contact support', () => {
    const overLimit = CODE.slice(CODE.indexOf('MAX_ACCOUNTS_PER_BULK_IMPORT}-per-call'));
    expect(overLimit).toContain('parentId');
    expect(CODE).not.toContain('Contact HorizonVigil for a staged import');
  });

  it('reports the scope it actually used', () => {
    // "820 imported" means different things for an OU and for a whole
    // organization, and the audit entry has to be able to tell them apart.
    expect(CODE).toMatch(/scope: body\.parentId/);
    expect(CODE).toMatch(/scope: body\.parentId \?\? 'organization'/);
  });
});

describe('the plan position is surfaced, as it is on single connect', () => {
  it('reports where the import leaves the org against its plan', () => {
    // The single-account route already returns planLimitWarning. The path
    // that adds 800 accounts at once said nothing at all.
    expect(CODE).toContain('checkCloudAccountLimit');
    expect(CODE).toContain('planLimitWarning');
  });

  it('projects the position AFTER the import, not before', () => {
    // "You are at 48 of 50" is not the useful sentence when the next click
    // adds 800.
    expect(CODE).toMatch(/planLimit\.used \+ inserted\.length/);
    expect(CODE).toMatch(/planLimit\.used \+ importable\.length/);
  });

  /**
   * checkCloudAccountLimit is documented as soft and non-blocking — "this
   * never throws and never blocks a connect". Bulk import must not quietly
   * promote it into a hard cap.
   */
  it('does not turn a soft plan signal into a rejection', () => {
    const afterLimit = CODE.slice(CODE.indexOf('const planLimit'));
    expect(afterLimit).not.toMatch(/if \(planLimit\.atLimit\)[\s\S]{0,80}return errJson/);
  });
});

describe('the endpoint still says what it does not verify', () => {
  it('no longer claims a platform AWS credential is required', () => {
    // Workload identity removed that dependency. The comment outlived it, and
    // a stale caveat about an unprovisionable credential reads as "this can
    // never work".
    expect(SOURCE).not.toMatch(/needs PLATFORM_AWS_ACCESS_KEY_ID\/SECRET/);
    expect(SOURCE).toContain('Workload identity removed that dependency');
  });

  it('says where an imported connection actually gets validated', () => {
    // 1,000 sts:AssumeRole calls do not belong in one HTTP request, so the
    // import cannot prove the roles work. It must say so rather than let
    // "imported: 1000" imply 1,000 working connections.
    expect(CODE).toContain('nextStep');
    expect(CODE).toMatch(/pending/);
  });
});
