import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { CUR_COLUMNS } from './curSchema';

/**
 * The templates in templates/ are the only artifact a customer actually
 * deploys, and until now nothing tested them.
 *
 * That is not a theoretical gap. AC-12 (2026-09-09) audited all 177 actions in
 * the collection role and removed four credential-producing ones and narrowed
 * two wildcards. That hardening was applied to the published policy JSON and
 * to the policy the connect wizard displays -- and NOT to
 * horizonvigil-scan-role-stackset.yaml. So every role created from the
 * template still granted `redshift:GetClusterCredentials`,
 * `ec2:GetConsoleOutput`, `iam:GenerateServiceLastAccessedDetails`,
 * `logs:Get*`, `codebuild:BatchGet*` and `apigateway:GET` on `"*"`, while the
 * audit recorded them as removed. Same class as every other defect this
 * session found: the fix landed in one representation and not in the one that
 * ships.
 */
const ROLE_TEMPLATE = readFileSync('templates/horizonvigil-scan-role-stackset.yaml', 'utf8');
const CUR_TEMPLATE = readFileSync('templates/horizonvigil-cur-setup.yaml', 'utf8');
const CUR_INGEST = readFileSync('src/lib/curIngest.ts', 'utf8');

/** YAML comment lines stripped, so prose naming an action cannot satisfy — or trip — a check on the policy itself. */
const code = (src: string) =>
  src.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');

const ROLE_CODE = code(ROLE_TEMPLATE);
const CUR_CODE = code(CUR_TEMPLATE);

/**
 * One IAM statement, sliced from `- Sid: <name>` to the next `- Sid:`.
 * Statement-level, because "is this action granted" and "what is it granted
 * ON" are different questions and only the second one caught the apigateway
 * problem.
 */
function statement(src: string, sid: string): string {
  const start = src.indexOf(`- Sid: ${sid}`);
  if (start === -1) return '';
  const next = src.indexOf('- Sid: ', start + 1);
  return src.slice(start, next === -1 ? undefined : next);
}

describe('the deployed template grants no credential-producing permission (AC-12)', () => {
  /** Each removed for a stated reason; the reason is the test's real content. */
  const FORBIDDEN: [action: string, why: string][] = [
    ['redshift:GetClusterCredentials', 'mints temporary database credentials'],
    ['ec2:GetConsoleOutput', 'boot logs routinely carry secrets'],
    ['iam:GenerateServiceLastAccessedDetails', 'a job-producing write, and nothing calls it'],
    ['logs:Get*', 'GetLogEvents returns raw log lines'],
    ['codebuild:BatchGet*', 'also matches BatchGetBuilds -- build logs and env vars'],
  ];

  for (const [action, why] of FORBIDDEN) {
    it(`does not grant ${action} — ${why}`, () => {
      expect(ROLE_CODE).not.toContain(`'${action}'`);
    });
  }

  /**
   * The narrowed replacements must still be present, or "no wildcard" would
   * be satisfiable by deleting the capability instead of scoping it.
   */
  it('keeps the narrowed replacement for codebuild', () => {
    expect(ROLE_CODE).toContain("'codebuild:BatchGetProjects'");
  });

  /**
   * Two credential-adjacent actions were deliberately KEPT with a stated
   * rationale: IAM returns no credential report until one is generated (it is
   * MFA/key-age metadata), and FilterLogEvents backs the per-resource
   * on-demand log viewer. Pinned so a later sweep does not remove them as
   * collateral and quietly drop a working feature.
   */
  it('keeps the two deliberate exceptions', () => {
    expect(ROLE_CODE).toContain("'iam:GenerateCredentialReport'");
    expect(ROLE_CODE).toContain("'logs:FilterLogEvents'");
  });
});

describe('apigateway:GET is scoped, because on "*" it returns API key values', () => {
  it('is granted only inside its own scoped statement', () => {
    const scoped = statement(ROLE_CODE, 'ApiGatewayInventoryOnly');
    expect(scoped).toContain("'apigateway:GET'");
    // Exactly one grant in the whole template, and it is that one.
    expect(ROLE_CODE.match(/'apigateway:GET'/g)).toHaveLength(1);
  });

  it('names real resource ARNs instead of a wildcard', () => {
    const scoped = statement(ROLE_CODE, 'ApiGatewayInventoryOnly');
    expect(scoped).toMatch(/apigateway:\*::\/restapis/);
    expect(scoped).toMatch(/apigateway:\*::\/apis/);
    // `GET /apikeys` is what the wildcard would have included.
    expect(scoped).not.toMatch(/Resource: '\*'/);
    expect(scoped).not.toContain('apikeys');
  });
});

describe('the role can read object CONTENTS in exactly one place', () => {
  /**
   * Every other S3 grant in this role reads bucket METADATA -- policy,
   * encryption, lifecycle, public-access settings -- which is what a posture
   * scanner needs. Object contents are customer data. A collection role that
   * can read any object is a categorically larger promise, so the one
   * exception is pinned here rather than left to review.
   */
  it('grants s3:GetObject exactly once', () => {
    expect(ROLE_CODE.match(/'s3:GetObject'/g)).toHaveLength(1);
  });

  it('never grants a broad s3:Get* or s3:GetObject on "*"', () => {
    expect(ROLE_CODE).not.toContain("'s3:Get*'");
    const cur = statement(ROLE_CODE, 'CostAndUsageReportObjectRead');
    expect(cur).toContain("'s3:GetObject'");
    expect(cur).not.toMatch(/Resource: '\*'/);
  });

  it('scopes it to the CUR bucket and nothing else', () => {
    const cur = statement(ROLE_CODE, 'CostAndUsageReportObjectRead');
    expect(cur).toMatch(/s3:::horizonvigil-cur-\$\{AWS::AccountId\}/);
  });

  it('can discover the report without the customer typing a bucket name', () => {
    const discovery = statement(ROLE_CODE, 'CostAndUsageReportDiscovery');
    expect(discovery).toContain("'cur:DescribeReportDefinitions'");
    expect(discovery).toContain("'bcm-data-exports:ListExports'");
    expect(discovery).toContain("'bcm-data-exports:GetExport'");
  });
});

/**
 * The cross-file invariant, and the reason the bucket name is derived rather
 * than configurable: one stack creates the bucket, a DIFFERENT stack grants
 * read on it, and they never reference each other. If the two names drift the
 * grant points at a bucket that does not exist, CUR ingestion fails with
 * AccessDenied, and nothing anywhere reports a misconfiguration.
 */
describe('the two templates agree on where the CUR lives', () => {
  it('the bucket the CUR stack creates is the bucket the role may read', () => {
    expect(CUR_CODE).toMatch(/BucketName: !Sub 'horizonvigil-cur-\$\{AWS::AccountId\}'/);
    const cur = statement(ROLE_CODE, 'CostAndUsageReportObjectRead');
    expect(cur).toMatch(/s3:::horizonvigil-cur-\$\{AWS::AccountId\}'/);
    expect(cur).toMatch(/s3:::horizonvigil-cur-\$\{AWS::AccountId\}\/\*'/);
  });

  it('CUR creation is NOT in the org-wide StackSet', () => {
    // Billing is consolidated at the payer, so one CUR covers every member
    // account. In the StackSet this would create one bucket and one export per
    // member account -- N times the storage for one useful report.
    expect(ROLE_CODE).not.toContain('AWS::S3::Bucket');
    expect(ROLE_CODE).not.toContain('bcm-data-exports:CreateExport');
  });
});

describe('the CUR export is delivered in a form the ingester can read', () => {
  it('is CSV + GZIP, not Parquet', () => {
    // curIngest streams gzip and parses CSV rows. Parquet is smaller and is
    // what a competitor ships, but reading it needs a decoder the connector
    // does not have.
    expect(CUR_CODE).toContain("'Format': 'TEXT_OR_CSV'");
    expect(CUR_CODE).toContain("'Compression': 'GZIP'");
    expect(CUR_CODE).not.toContain("'Format': 'PARQUET'");
    expect(CUR_INGEST).toContain("DecompressionStream('gzip')");
  });

  it('includes resource IDs, which is the entire reason to ingest CUR', () => {
    // Without them cost cannot be attributed to a resource, and Cost Explorer
    // would already have answered the aggregate question.
    expect(CUR_CODE).toContain("'INCLUDE_RESOURCES': 'TRUE'");
  });

  it('overwrites each billing period instead of keeping every refresh', () => {
    expect(CUR_CODE).toContain("'Overwrite': 'OVERWRITE_REPORT'");
  });

  /**
   * The export query is narrow on purpose, which makes "did we select the
   * columns the parser requires" a real question rather than a formality.
   *
   * curIngest still reads CUR 1.0 column names; the export emits CUR 2.0
   * names. The mapping is pinned here so the rename in the ingester has a
   * specification to satisfy, and so a column cannot be dropped from the
   * export without this failing.
   */
  /**
   * Now asserted against the ingester's real column table rather than a
   * hand-copied list, so adding a column the parser depends on without
   * selecting it in the export fails here instead of at the first ingest.
   *
   * Every column in CUR_COLUMNS.v2 must appear, not only the three that are
   * strictly required: the optional ones (service, region) are what turn a
   * cost row into an attributable one, and an export that omits them
   * produces rows labelled "unknown" rather than an error.
   */
  it('selects every CUR 2.0 column the ingester reads', () => {
    for (const column of Object.values(CUR_COLUMNS.v2)) {
      expect(CUR_CODE, `${column} is read by the ingester but not selected by the export`).toContain(`'${column}'`);
    }
  });

  it('the ingester can read both generations, so a pre-existing report still works', () => {
    // The export this template creates is v2, but a customer who already had
    // a legacy CUR must not be broken by that.
    expect(Object.keys(CUR_COLUMNS).sort()).toEqual(['v1', 'v2']);
    expect(CUR_INGEST).toContain('resolveCurColumns');
  });

  it('carries the usage account id, so a payer CUR can be attributed', () => {
    // A CUR created in the management account contains every member account's
    // rows. Without this column all of that cost belongs to the payer.
    expect(CUR_CODE).toContain("'line_item_usage_account_id'");
  });
});

describe('the CUR bucket is not writable by the wrong billing service', () => {
  it('constrains the billing service principals to this account', () => {
    // Without these the confused-deputy case is real: another account's
    // billing service can be induced to write into this bucket.
    expect(CUR_CODE).toContain("'aws:SourceAccount': !Ref 'AWS::AccountId'");
    expect(CUR_CODE).toMatch(/aws:SourceArn/);
  });

  it('blocks public access and plaintext transport', () => {
    expect(CUR_CODE).toContain('BlockPublicAcls: true');
    expect(CUR_CODE).toContain('RestrictPublicBuckets: true');
    expect(CUR_CODE).toContain("'aws:SecureTransport': false");
  });

  it('retains the bucket when the stack is deleted', () => {
    // Billing history cannot be regenerated once the retention window passes.
    expect(CUR_CODE).toContain('DeletionPolicy: Retain');
  });
});
