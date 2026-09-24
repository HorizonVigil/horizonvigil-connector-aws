import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

import { provenFindingSources } from './findingCoverage';

const SCANNERS = ['guardduty', 'securityhub', 'accessanalyzer', 'inspector', 'awsconfig', 'trustedadvisor'];
const SOURCES = {
  guardduty: ['guardduty'],
  securityhub: ['security_hub'],
  accessanalyzer: ['iam_access_analyzer', 'iam_access_analyzer_unused'],
  inspector: ['inspector'],
  awsconfig: ['aws_config'],
  trustedadvisor: ['trusted_advisor'],
};

const plan = (regions: string[]) => regions.flatMap((r) => SCANNERS.map((n) => `finding:${n}:${r}`));

const run = (opts: {
  regions: string[];
  planned?: string[];
  succeeded: string[];
}) => provenFindingSources({
  scanners: SCANNERS,
  regions: opts.regions,
  plannedSteps: opts.planned ?? plan(opts.regions),
  succeededStepIds: new Set(opts.succeeded),
  sourcesByScanner: SOURCES,
});

describe('provenFindingSources', () => {
  it('proves a source when every planned region step succeeded', () => {
    const regions = ['us-east-1', 'eu-west-1'];
    expect(run({ regions, succeeded: plan(regions) })).toEqual([
      'guardduty', 'security_hub', 'iam_access_analyzer', 'iam_access_analyzer_unused',
      'inspector', 'aws_config', 'trusted_advisor',
    ]);
  });

  /**
   * The defect, in one assertion. finalize resolved findings from a hardcoded
   * six-source list on EVERY run, so a run that never executed a single
   * finding step still closed every open finding.
   */
  it('proves NOTHING when no finding step ran', () => {
    expect(run({ regions: ['us-east-1'], succeeded: [] })).toEqual([]);
  });

  it('proves nothing for a scanner the run did not plan', () => {
    const regions = ['us-east-1'];
    const planned = plan(regions).filter((s) => !s.startsWith('finding:guardduty:'));

    const proven = run({ regions, planned, succeeded: planned });

    expect(proven).not.toContain('guardduty');
    expect(proven).toContain('inspector');
  });

  /**
   * One region is enough. A finding lives in a region; a scanner denied in
   * eu-west-1 and clean in us-east-1 has not shown that the eu-west-1 finding
   * is gone, however well it did elsewhere.
   */
  it('one unsucceeded region withholds the whole source', () => {
    const regions = ['us-east-1', 'eu-west-1'];
    const succeeded = plan(regions).filter((s) => s !== 'finding:guardduty:eu-west-1');

    const proven = run({ regions, succeeded });

    expect(proven).not.toContain('guardduty');
    expect(proven).toContain('security_hub');
  });

  /**
   * 'info' is the status runFindingStep commits when an AWS call inside the
   * step failed. The step is not a failure -- the run still succeeded -- but
   * it read part of the picture, so it cannot prove the rest is gone.
   * Excluding only 'failed' would let a throttled read close real findings.
   */
  it('a committed-but-incomplete step does not count, only succeeded does', () => {
    const regions = ['us-east-1'];
    // Everything committed; guardduty committed as 'info', so it is absent
    // from the succeeded set.
    const succeeded = plan(regions).filter((s) => s !== 'finding:guardduty:us-east-1');

    expect(run({ regions, succeeded })).not.toContain('guardduty');
  });

  it('a scanner with no mapped source contributes nothing rather than its own name', () => {
    const proven = provenFindingSources({
      scanners: ['newscanner'],
      regions: ['us-east-1'],
      plannedSteps: ['finding:newscanner:us-east-1'],
      succeededStepIds: new Set(['finding:newscanner:us-east-1']),
      sourcesByScanner: SOURCES,
    });
    // Guessing a finding_source would resolve either the wrong rows or none,
    // and the wrong rows are security findings.
    expect(proven).toEqual([]);
  });

  it('a connection with no regions proves nothing', () => {
    // `[].every(...)` is true, so without the explicit guard an empty region
    // list would prove EVERY source while reading nothing at all.
    expect(run({ regions: [], planned: [], succeeded: [] })).toEqual([]);
  });

  it('does not repeat a source claimed by two scanners', () => {
    const proven = provenFindingSources({
      scanners: ['a', 'b'],
      regions: ['us-east-1'],
      plannedSteps: ['finding:a:us-east-1', 'finding:b:us-east-1'],
      succeededStepIds: new Set(['finding:a:us-east-1', 'finding:b:us-east-1']),
      sourcesByScanner: { a: ['shared'], b: ['shared'] },
    });
    expect(proven).toEqual(['shared']);
  });
});

/**
 * The wiring. A correct rule the worker does not call changes nothing -- the
 * lesson from the capability verdict and the region ledger, both of which
 * passed their own tests while the route kept the broken behaviour.
 */
describe('finalize consumes the proof rather than a hardcoded list', () => {
  const DISCOVERY = readFileSync('src/routes/discovery.ts', 'utf8');
  const RUNS = readFileSync('src/routes/collectionRuns.ts', 'utf8');

  it('the hardcoded source literal is gone from finalize', () => {
    expect(DISCOVERY).not.toContain("finding_source: 'in.(guardduty,security_hub,iam_access_analyzer,inspector,aws_config,trusted_advisor)'");
  });

  it('finalize filters on the proven set', () => {
    expect(DISCOVERY).toContain('finding_source: inFilter([...coveredFindingSources])');
  });

  it('an empty proven set resolves nothing at all', () => {
    // Not merely an empty in.() -- that is a query we should never issue.
    expect(DISCOVERY).toContain('coveredFindingSources.length === 0 ? []');
  });

  it('the parameter defaults to proving nothing, not to every source', () => {
    expect(DISCOVERY).toMatch(/coveredFindingSources: readonly string\[\] = \[\]/);
  });

  it('the worker computes it from committed step rows and passes it', () => {
    expect(RUNS).toContain('provenFindingSources({');
    expect(RUNS).toContain("s.status === 'succeeded'");
    expect(RUNS).toContain('provenScopes, coveredFindingSources,');
  });

  it('finding scanners report their failed calls at all', () => {
    // They were called with bare credentials, so a denied or throttled call
    // left no trace anywhere in the system.
    expect(DISCOVERY).toContain('scanner({ creds: { ...resolved.creds, onCallFailure }, region })');
  });

  it('a finding step that read partially is committed as incomplete', () => {
    expect(DISCOVERY).toMatch(/errorSeverity: 'info' as const/);
    expect(DISCOVERY).toContain('return { stepId, resourceCount: rows.length, created, ...incomplete };');
  });
});
