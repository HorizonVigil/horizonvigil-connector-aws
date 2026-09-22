import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { buildScanHealth, groupFailures, parseStepId, type StepRow } from './scanHealth';

/**
 * The scenario this module exists for, measured in production 2026-09-15:
 *
 *   kamal-k8s — 430 resources, `errors: 0`, run PARTIALLY_SUCCEEDED,
 *   regional:ec2 failed in all 17 regions.
 *
 * The page showed "430 resources" beside a zero error count. EC2 — instances,
 * volumes, VPCs, subnets, security groups — had returned nothing anywhere,
 * and those rows were stale. A count without its coverage is a claim the data
 * does not support.
 */
const step = (id: string, status: StepRow['status'], over: Partial<StepRow> = {}): StepRow =>
  ({ step_id: id, status, normalized_code: null, error_message: null, ...over });

const REGIONS = ['us-east-1', 'us-east-2', 'us-west-1', 'eu-west-1'];
const ec2Failures = REGIONS.map((r) =>
  step(`regional:ec2:${r}`, 'failed', { normalized_code: 'UNSUPPORTED_CAPABILITY', error_message: 'EC2 DescribeElasticGpus failed' }));

describe('parseStepId', () => {
  it('splits kind, scanner and scope', () => {
    expect(parseStepId('regional:ec2:us-east-1')).toEqual({ kind: 'regional', scanner: 'ec2', scope: 'us-east-1' });
  });

  it('treats a scopeless step as global', () => {
    expect(parseStepId('global:iam')).toEqual({ kind: 'global', scanner: 'iam', scope: 'global' });
  });
});

describe('groupFailures', () => {
  /**
   * Seventeen rows reading `regional:ec2:<region> failed` is noise; "ec2
   * failed in 17 regions" is the finding. A scanner failing everywhere is a
   * different problem from one failing in a single region, and a flat list
   * hides which it is.
   */
  it('groups by scanner and reports the scopes', () => {
    const [f] = groupFailures(ec2Failures);
    expect(f.scanner).toBe('ec2');
    expect(f.scopes).toEqual(['eu-west-1', 'us-east-1', 'us-east-2', 'us-west-1']);
    expect(f.normalizedCode).toBe('UNSUPPORTED_CAPABILITY');
  });

  /** One shared cause is actionable; several is not, and naming one of them would send someone to fix the wrong thing. */
  it('reports no single cause when the causes differ', () => {
    const mixed = [
      step('regional:s3:us-east-1', 'failed', { normalized_code: 'PERMISSION_DENIED' }),
      step('regional:s3:eu-west-1', 'failed', { normalized_code: 'THROTTLED' }),
    ];
    expect(groupFailures(mixed)[0].normalizedCode).toBeNull();
  });

  it('ranks the widest failure first', () => {
    const f = groupFailures([...ec2Failures, step('regional:s3:us-east-1', 'failed')]);
    expect(f.map((x) => x.scanner)).toEqual(['ec2', 's3']);
  });

  it('ignores succeeded, skipped and info steps', () => {
    expect(groupFailures([
      step('regional:ec2:us-east-1', 'succeeded'),
      step('regional:macie:us-east-1', 'info'),
      step('regional:s3:us-east-1', 'skipped'),
    ])).toEqual([]);
  });

  it('deduplicates a scope that failed more than once', () => {
    const f = groupFailures([step('regional:ec2:us-east-1', 'failed'), step('regional:ec2:us-east-1', 'failed')]);
    expect(f[0].scopes).toEqual(['us-east-1']);
  });
});

describe('buildScanHealth', () => {
  const run = (over: Partial<Parameters<typeof buildScanHealth>[0] & object> = {}) =>
    ({ status: 'SUCCEEDED', totalSteps: 100, completedSteps: 100, failedSteps: 0, degradedResourceTypes: [], ...over });

  it('a clean run is the only state whose count may be presented as a total', () => {
    const h = buildScanHealth(run(), [step('regional:ec2:us-east-1', 'succeeded')]);
    expect(h.completeness).toBe('COMPLETE');
    expect(h.countIsAuthoritative).toBe(true);
  });

  /** The production case. */
  it('a partial run says the estate is not whole and names the widest failure', () => {
    const h = buildScanHealth(
      run({ status: 'PARTIALLY_SUCCEEDED', failedSteps: 4 }),
      [...ec2Failures, step('regional:s3:us-east-1', 'succeeded')],
    );
    expect(h.completeness).toBe('PARTIAL');
    expect(h.countIsAuthoritative).toBe(false);
    expect(h.summary).toContain('ec2 failed in 4 regions');
    expect(h.summary).toContain('not the whole estate');
  });

  /**
   * A run can report SUCCEEDED while individual steps failed, depending on
   * how the terminal status was derived. The step rows are the evidence, so
   * a failed step downgrades the verdict regardless of the run's own label.
   */
  it('downgrades to PARTIAL on failed steps even if the run says SUCCEEDED', () => {
    const h = buildScanHealth(run({ status: 'SUCCEEDED' }), ec2Failures);
    expect(h.completeness).toBe('PARTIAL');
    expect(h.countIsAuthoritative).toBe(false);
  });

  /**
   * AWS-H4, and the exact production blind spot that hid C3 for 12 days.
   *
   * 1,628 steps succeeded, nothing was degraded, and 4 S3 buckets were read
   * from AWS and discarded by admission on every run -- while this function
   * answered "All 1628 collection steps succeeded" with an authoritative
   * count. A record that was READ and then refused breaks no step and degrades
   * no type, so it was invisible by construction.
   */
  it('a run that discarded records is NOT complete, however well its steps went', () => {
    const h = buildScanHealth(
      run(),
      [step('global:s3', 'succeeded')],
      { succeededSteps: 100, failedSteps: 0 },
      { total: 4, byReason: [{ reasonCode: 'INVALID_REGION', count: 4 }] },
    );

    expect(h.completeness).toBe('PARTIAL');
    expect(h.countIsAuthoritative).toBe(false);
    expect(h.quarantinedRecords).toBe(4);
    expect(h.summary).toContain('refused admission');
    expect(h.summary).toContain('INVALID_REGION');
    expect(h.summary).toContain('floor, not a total');
  });

  it('names the most common reason and says how many others there are', () => {
    const h = buildScanHealth(
      run(), [], { succeededSteps: 100, failedSteps: 0 },
      {
        total: 9,
        byReason: [
          { reasonCode: 'UNKNOWN_RESOURCE_TYPE', count: 2 },
          { reasonCode: 'INVALID_REGION', count: 6 },
          { reasonCode: 'ACCOUNT_MISMATCH', count: 1 },
        ],
      },
    );

    // Sorted by frequency, not by the order the caller happened to build them.
    expect(h.quarantineReasons[0]).toEqual({ reasonCode: 'INVALID_REGION', count: 6 });
    expect(h.summary).toContain('INVALID_REGION');
    expect(h.summary).toContain('2 other reason(s)');
  });

  it('reports a failed step ahead of quarantine when both happened', () => {
    // Both make the count non-authoritative; the failure is the more
    // actionable headline, and the quarantine count is still on the object.
    const h = buildScanHealth(
      run({ status: 'PARTIALLY_SUCCEEDED', failedSteps: 4 }),
      ec2Failures,
      { succeededSteps: 96, failedSteps: 4 },
      { total: 3, byReason: [{ reasonCode: 'INVALID_REGION', count: 3 }] },
    );

    expect(h.summary).toContain('ec2 failed in 4 regions');
    expect(h.quarantinedRecords).toBe(3);
    expect(h.countIsAuthoritative).toBe(false);
  });

  it('a clean run with zero quarantine still reports COMPLETE', () => {
    // The guard must not make every run permanently partial.
    const h = buildScanHealth(run(), [], { succeededSteps: 100, failedSteps: 0 }, { total: 0, byReason: [] });
    expect(h.completeness).toBe('COMPLETE');
    expect(h.countIsAuthoritative).toBe(true);
    expect(h.quarantinedRecords).toBe(0);
  });

  /**
   * The argument is optional so the older two- and three-argument call shapes
   * still compile, and absent is treated as zero.
   *
   * That is a deliberate soft spot: "nobody measured" and "measured and found
   * none" produce the same COMPLETE verdict here. It is acceptable only
   * because there is exactly ONE production caller and it always measures --
   * which is asserted below, against the route's source, rather than assumed.
   * If a second caller ever appears without passing these facts, that
   * assertion is what should be made to fail.
   */
  it('absent quarantine facts are treated as zero — see the wiring assertion below', () => {
    const h = buildScanHealth(run(), []);
    expect(h.completeness).toBe('COMPLETE');
    expect(h.quarantinedRecords).toBe(0);
    expect(h.quarantineReasons).toEqual([]);
  });

  it('a failed run reports the inventory as stale, not current', () => {
    const h = buildScanHealth(run({ status: 'FAILED' }), []);
    expect(h.completeness).toBe('FAILED');
    expect(h.countIsAuthoritative).toBe(false);
    expect(h.summary).toContain('stale');
  });

  it('an in-flight run never vouches for the count', () => {
    const h = buildScanHealth(run({ status: 'RUNNING', completedSteps: 40 }), []);
    expect(h.completeness).toBe('RUNNING');
    expect(h.countIsAuthoritative).toBe(false);
    expect(h.summary).toContain('40 of 100');
  });

  /**
   * Never-run is distinct from zero. "This account has no resources" and
   * "nobody has looked yet" are different statements and only the first is an
   * answer.
   */
  it('never-run is distinct from an empty estate', () => {
    const h = buildScanHealth(null, []);
    expect(h.completeness).toBe('NEVER_RUN');
    expect(h.countIsAuthoritative).toBe(false);
    expect(h.summary).toContain('has not been established');
  });

  it('carries degraded resource types through so the UI can name what is stale', () => {
    const h = buildScanHealth(run({ status: 'PARTIALLY_SUCCEEDED', degradedResourceTypes: ['ec2_instance', 'vpc'] }), ec2Failures);
    expect(h.degradedResourceTypes).toEqual(['ec2_instance', 'vpc']);
  });

  /** Only COMPLETE may vouch for the number — asserted across every state. */
  it('no state other than COMPLETE vouches for the count', () => {
    const states = ['PARTIALLY_SUCCEEDED', 'FAILED', 'CANCELED', 'RUNNING', 'QUEUED', 'WAITING_RETRY', 'PAUSED'];
    for (const status of states) {
      expect(buildScanHealth(run({ status }), []).countIsAuthoritative, status).toBe(false);
    }
    expect(buildScanHealth(null, []).countIsAuthoritative).toBe(false);
  });
});

/**
 * The truncation defect this module exists to expose, reproduced inside it.
 *
 * The first version counted statuses from the step rows it was handed. But the
 * route selected them with `limit: 5000`, and PostgREST caps a response at
 * ~1000 rows server-side. Measured on a real 1,628-step run: the endpoint
 * reported `succeededSteps: 1000`.
 *
 * The count being wrong was the harmless half. The dangerous half is that a
 * failure sitting beyond row 1000 was invisible, so this would have answered
 * COMPLETE with `countIsAuthoritative: true` over a scan that had failed.
 */
describe('counts never come from a capped page', () => {
  const run = { status: 'SUCCEEDED', totalSteps: 1628, completedSteps: 1628, failedSteps: 0, degradedResourceTypes: [] };

  it('uses the exact counts it is given, not the rows it can see', () => {
    // What the route now passes: no success rows at all, just the number.
    const h = buildScanHealth(run, [], { succeededSteps: 1628, failedSteps: 0 });
    expect(h.succeededSteps).toBe(1628);
    expect(h.completeness).toBe('COMPLETE');
  });

  /**
   * The load-bearing case. Failures are fetched as their own filtered query,
   * so a failure that would have fallen past row 1000 of a mixed page is still
   * counted and still downgrades the verdict.
   */
  it('reports PARTIAL from an exact failed count even when no rows were paged in', () => {
    const h = buildScanHealth(
      { ...run, status: 'SUCCEEDED' },
      [step('regional:ec2:us-east-1', 'failed')],
      { succeededSteps: 1611, failedSteps: 17 },
    );
    expect(h.failedSteps).toBe(17);
    expect(h.completeness).toBe('PARTIAL');
    expect(h.countIsAuthoritative).toBe(false);
  });

  /** Without counts it still works, so existing callers are unaffected. */
  it('falls back to counting rows when no exact counts are supplied', () => {
    const h = buildScanHealth(run, [step('a:b:c', 'succeeded'), step('d:e:f', 'succeeded')]);
    expect(h.succeededSteps).toBe(2);
  });
});

/**
 * A truncated read SUCCEEDS.
 *
 * The guard in awsApi.ts catches truncation and excludes the scanner's
 * resource types from tombstoning, which prevents data loss. But the STEP
 * still reports `succeeded` — so a run where 83 scanners silently stopped at
 * page one reported COMPLETE with countIsAuthoritative: true, and the banner
 * rendered nothing at all.
 *
 * Measured 2026-09-16: 83 of 111 scanner files are structurally single-page.
 * On a large customer account that is most of the estate.
 */
describe('degraded coverage downgrades the verdict', () => {
  const clean = { status: 'SUCCEEDED', totalSteps: 100, completedSteps: 100, failedSteps: 0, degradedResourceTypes: [] };

  it('a run with degraded types is PARTIAL even when every step succeeded', () => {
    const h = buildScanHealth({ ...clean, degradedResourceTypes: ['ec2_instance', 'vpc', 'subnet', 's3_bucket'] }, [],
      { succeededSteps: 100, failedSteps: 0 });
    expect(h.completeness).toBe('PARTIAL');
    expect(h.countIsAuthoritative).toBe(false);
    expect(h.summary).toContain('4 resource type(s) were not fully read');
    expect(h.summary).toContain('floor, not a total');
  });

  /** Naming the types is what makes it actionable rather than alarming. */
  it('names the degraded types, bounded, with a count for the rest', () => {
    const h = buildScanHealth({ ...clean, degradedResourceTypes: ['a', 'b', 'c', 'd', 'e'] }, [],
      { succeededSteps: 100, failedSteps: 0 });
    expect(h.summary).toContain('a, b, c and 2 more');
  });

  /** Reassuring and true: degraded coverage suppresses deletion, not causes it. */
  it('says the resources were kept rather than deleted', () => {
    const h = buildScanHealth({ ...clean, degradedResourceTypes: ['ec2_instance'] }, [],
      { succeededSteps: 100, failedSteps: 0 });
    expect(h.summary).toContain('kept rather than marked deleted');
  });

  /** A failed step is more actionable than a degraded type, so it wins. */
  it('reports the failure when a run has both', () => {
    const h = buildScanHealth(
      { ...clean, status: 'PARTIALLY_SUCCEEDED', failedSteps: 2, degradedResourceTypes: ['ec2_instance'] },
      [step('regional:ec2:us-east-1', 'failed')],
      { succeededSteps: 98, failedSteps: 2 },
    );
    expect(h.completeness).toBe('PARTIAL');
    expect(h.summary).toContain('ec2 failed in');
  });

  /** A genuinely complete run still says so — this must not flag everything. */
  it('still reports COMPLETE when nothing was degraded', () => {
    const h = buildScanHealth(clean, [], { succeededSteps: 100, failedSteps: 0 });
    expect(h.completeness).toBe('COMPLETE');
    expect(h.countIsAuthoritative).toBe(true);
  });
});

/**
 * AWS-H4 wiring. A correct verdict the route never feeds is worth nothing --
 * the lesson from the capability verdict and the region ledger, both of which
 * passed their own tests while the route kept the broken behaviour.
 *
 * These assertions are what makes the optional fourth argument safe: they
 * fail the moment the one production caller stops measuring.
 */
describe('the scan-health route measures quarantine', () => {
  const ROUTE = readFileSync('src/routes/collectionRuns.ts', 'utf8');

  it('reads quarantine records for the connection', () => {
    expect(ROUTE).toContain("selectWithCount<{ reason_code: string }[]>('quarantine_records'");
  });

  it('passes them into buildScanHealth', () => {
    expect(ROUTE).toContain('total: quarantineTotal');
    expect(ROUTE).toContain('byReason:');
  });

  it('uses the exact count, not the length of a possibly-capped page', () => {
    // The same PostgREST trap this endpoint already documents for step rows:
    // a page capped at 1,000 read as a total is how an under-count hides.
    expect(ROUTE).not.toMatch(/total:\s*quarantineRows\.length/);
  });

  it('bounds the window by the run rather than reporting all history', () => {
    expect(ROUTE).toMatch(/quarantined_at: `gte\.\$\{since\}`/);
  });
});
