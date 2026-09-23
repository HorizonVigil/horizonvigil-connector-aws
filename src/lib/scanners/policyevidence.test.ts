import { describe, expect, it } from 'vitest';
import { accountIdFromArn, attr, decodePolicyText, parseAttributeEntries, summarizePolicy } from './policyEvidence';

const OWN = '111122223333';
const doc = (...statements: unknown[]) => JSON.stringify({ Version: '2012-10-17', Statement: statements });

describe('summarizePolicy', () => {
  it('distinguishes "no policy" from "unreadable policy"', () => {
    expect(summarizePolicy(null, OWN)).toMatchObject({ parsed: false, present: false });
    expect(summarizePolicy('{not json', OWN)).toMatchObject({ parsed: false, present: true });
  });

  it('flags an unconditioned "*" principal as anonymous access', () => {
    const s = summarizePolicy(doc({ Effect: 'Allow', Principal: '*', Action: 'sns:Publish' }), OWN);
    expect(s).toMatchObject({ parsed: true, allowsAnonymous: true, allowsAnyPrincipalWithCondition: false });
  });

  it('treats {"AWS":"*"} the same as "*"', () => {
    expect(summarizePolicy(doc({ Effect: 'Allow', Principal: { AWS: '*' } }), OWN).allowsAnonymous).toBe(true);
  });

  it('keeps a conditioned "*" separate from anonymous access', () => {
    const s = summarizePolicy(doc({ Effect: 'Allow', Principal: '*', Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:s3:::b' } } }), OWN);
    expect(s).toMatchObject({ allowsAnonymous: false, allowsAnyPrincipalWithCondition: true, conditionKeys: ['aws:sourcearn'] });
  });

  it('ignores Deny statements when collecting grants', () => {
    const s = summarizePolicy(doc({ Effect: 'Deny', Principal: '*', Action: '*' }), OWN);
    expect(s).toMatchObject({ allowsAnonymous: false, allowStatementCount: 0 });
  });

  it('lists external accounts but not the owning account', () => {
    const s = summarizePolicy(doc({
      Effect: 'Allow',
      Principal: { AWS: [`arn:aws:iam::${OWN}:root`, 'arn:aws:iam::444455556666:role/x', '777788889999'] },
    }), OWN);
    expect(s.externalAccountIds).toEqual(['444455556666', '777788889999']);
  });

  it('collects service and federated principals and trust conditions', () => {
    const s = summarizePolicy(doc(
      { Effect: 'Allow', Principal: { Service: 'ec2.amazonaws.com' }, Action: 'sts:AssumeRole' },
      { Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::444455556666:root' }, Condition: { StringEquals: { 'sts:ExternalId': 'x' } } },
      { Effect: 'Allow', Principal: { Federated: 'arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com' } },
    ), OWN);
    expect(s.principals.service).toEqual(['ec2.amazonaws.com']);
    expect(s.principals.federated).toHaveLength(1);
    expect(s.conditionKeys).toContain('sts:externalid');
  });

  it('decodes URL-encoded IAM documents and entity-escaped SNS/SQS attributes', () => {
    const json = doc({ Effect: 'Allow', Principal: '*' });
    expect(summarizePolicy(encodeURIComponent(json), OWN).allowsAnonymous).toBe(true);
    expect(summarizePolicy(json.replace(/"/g, '&quot;'), OWN).allowsAnonymous).toBe(true);
    expect(decodePolicyText('  ')).toBeNull();
  });

  it('flags Allow + NotPrincipal for review', () => {
    expect(summarizePolicy(doc({ Effect: 'Allow', NotPrincipal: { AWS: 'arn:aws:iam::1:root' } }), OWN).usesNotPrincipalAllow).toBe(true);
  });
});

describe('attribute parsing', () => {
  it('reads SNS entry/key/value and SQS Attribute/Name/Value shapes', () => {
    const sns = parseAttributeEntries('<Attributes><entry><key>KmsMasterKeyId</key><value>alias/aws/sns</value></entry></Attributes>', 'sns');
    expect(attr(sns, 'KmsMasterKeyId')).toBe('alias/aws/sns');
    const sqs = parseAttributeEntries('<Attribute><Name>FifoQueue</Name><Value>true</Value></Attribute>', 'sqs');
    expect(attr(sqs, 'FifoQueue')).toBe('true');
    expect(attr(sqs, 'Missing')).toBeNull();
  });

  it('reads the account out of an ARN', () => {
    expect(accountIdFromArn('arn:aws:sqs:us-east-1:111122223333:q')).toBe('111122223333');
    expect(accountIdFromArn('not-an-arn')).toBeNull();
  });
});