import { describe, expect, it } from 'vitest';

import { classifyProvenance, describeProvenance, type ProvenanceInput } from './changeProvenance';

const classify = (over: ProvenanceInput = {}) => classifyProvenance(over);

/** Real user-agent strings AWS emits, not invented ones. */
const AGENTS = {
  consoleCoral: 'Coral/Jakarta',
  consoleSignin: 'signin.amazonaws.com',
  awsInternal: 'AWS Internal',
  cli2: 'aws-cli/2.15.0 Python/3.11.6 Linux/5.10 exe/x86_64.amzn.2',
  terraform: 'APN/1.0 HashiCorp/1.0 Terraform/1.5.7 (+https://www.terraform.io)',
  opentofu: 'APN/1.0 HashiCorp/1.0 OpenTofu/1.6.0',
  cdk: 'aws-cdk/2.100.0 aws-sdk-js/2.1450.0',
  pulumi: 'Pulumi/3.90.0 aws-sdk-go/1.44.0',
  cloudformation: 'cloudformation.amazonaws.com',
  boto: 'Boto3/1.28.0 Python/3.11 botocore/1.31.0',
  sdkGo: 'aws-sdk-go/1.44.300 (go1.20.5; linux; amd64)',
  amazonQ: 'AmazonQ/1.0 aws-sdk-js/2.1450.0',
  unknown: 'SomeInternalTool/4.2',
};

describe('AWS service-initiated changes', () => {
  /**
   * `invokedBy` is the only place CloudTrail names the service that acted. It
   * was previously parsed and discarded, which made a change nobody made
   * indistinguishable from a change nobody can be found for.
   */
  it('attributes an auto-scaling replacement to Auto Scaling, not to a person', () => {
    const p = classify({ invokedBy: 'autoscaling.amazonaws.com', userIdentityType: 'AssumedRole' });

    expect(p.actorClass).toBe('aws_service');
    expect(p.actorLabel).toBe('AWS Auto Scaling');
    expect(p.basis).toBe('invoked_by');
  });

  it('outranks the identity type and the user agent', () => {
    // An AssumedRole with a console-looking agent is still Auto Scaling if
    // AWS says the service invoked it.
    const p = classify({
      invokedBy: 'cloudformation.amazonaws.com',
      userIdentityType: 'AssumedRole',
      userAgent: AGENTS.consoleCoral,
    });
    expect(p.actorClass).toBe('aws_service');
    expect(p.actorLabel).toBe('AWS CloudFormation');
  });

  it('keeps an unlisted service principal rather than calling it unknown', () => {
    // Presence of invokedBy is what proves it, not membership of our list.
    const p = classify({ invokedBy: 'some-new-service.amazonaws.com' });
    expect(p.actorClass).toBe('aws_service');
    expect(p.actorLabel).toBe('some-new-service.amazonaws.com');
  });

  it('recognises an AWSService identity even with no invokedBy', () => {
    const p = classify({ userIdentityType: 'AWSService', eventSource: 'backup.amazonaws.com' });
    expect(p.actorClass).toBe('aws_service');
    expect(p.actorLabel).toBe('AWS Backup');
    expect(p.basis).toBe('identity_type');
  });
});

describe('infrastructure as code', () => {
  it('recognises Terraform', () => {
    const p = classify({ userAgent: AGENTS.terraform, userIdentityType: 'AssumedRole' });
    expect(p).toMatchObject({ actorClass: 'automation', actorKind: 'terraform', actorLabel: 'Terraform', basis: 'user_agent' });
  });

  it('recognises OpenTofu as the same kind of change', () => {
    expect(classify({ userAgent: AGENTS.opentofu }).actorKind).toBe('terraform');
  });

  /**
   * Order is load-bearing: CDK and Pulumi embed an AWS SDK string in their
   * agent, so a bare `aws-sdk` match placed first would file every IaC change
   * as a generic SDK call and lose the tool entirely.
   */
  it('does not mistake CDK for a generic SDK call', () => {
    expect(classify({ userAgent: AGENTS.cdk }).actorKind).toBe('cdk');
  });

  it('does not mistake Pulumi for a generic SDK call', () => {
    expect(classify({ userAgent: AGENTS.pulumi }).actorKind).toBe('pulumi');
  });

  it('recognises CloudFormation from its agent', () => {
    expect(classify({ userAgent: AGENTS.cloudformation }).actorKind).toBe('cloudformation');
  });
});

describe('AI assistants', () => {
  /**
   * These act with a developer's own credentials, so identity alone cannot
   * distinguish them from that developer typing. The agent string is the only
   * signal that can — which is exactly why classifying it is worth doing.
   */
  it('separates an Amazon Q change from a human one', () => {
    const p = classify({ userAgent: AGENTS.amazonQ, userIdentityType: 'IAMUser' });
    expect(p.actorClass).toBe('automation');
    expect(p.actorKind).toBe('ai_assistant');
    expect(p.actorLabel).toBe('Amazon Q');
  });

  it('is checked before the SDK rule its agent also matches', () => {
    // AmazonQ/1.0 aws-sdk-js/2.x contains `aws-sdk`.
    expect(classify({ userAgent: AGENTS.amazonQ }).actorKind).not.toBe('sdk');
  });
});

describe('human console changes', () => {
  for (const [name, agent] of [['Coral', AGENTS.consoleCoral], ['signin', AGENTS.consoleSignin], ['AWS Internal', AGENTS.awsInternal]] as const) {
    it(`recognises the console via ${name}`, () => {
      const p = classify({ userAgent: agent, userIdentityType: 'IAMUser' });
      expect(p.actorClass).toBe('human');
      expect(p.actorKind).toBe('console');
    });
  }
});

/**
 * The honesty core. A misattributed change is worse than an unattributed one:
 * it sends the reviewer to the wrong person.
 */
describe('what it refuses to claim', () => {
  it('does not call a CLI change human OR automated', () => {
    // The same binary is a person at a terminal and a CI job, and CloudTrail
    // does not record which. The KIND is provable; the CLASS is not.
    const p = classify({ userAgent: AGENTS.cli2, userIdentityType: 'IAMUser' });

    expect(p.actorKind).toBe('cli');
    expect(p.actorClass).toBe('unknown');
    expect(p.ambiguityReason).toMatch(/both by people .* and by automation/i);
  });

  it('does not call an unrecognised client human', () => {
    const p = classify({ userAgent: AGENTS.unknown, userIdentityType: 'IAMUser' });
    expect(p.actorClass).toBe('unknown');
    expect(p.actorKind).toBe('unknown');
    expect(p.ambiguityReason).toMatch(/not recognised/i);
  });

  it('says so when CloudTrail recorded no client at all', () => {
    const p = classify({ userIdentityType: 'AssumedRole' });
    expect(p.actorClass).toBe('unknown');
    expect(p.basis).toBe('none');
    expect(p.ambiguityReason).toMatch(/no client/i);
  });

  it('never claims a class without a basis', () => {
    // A verdict with `basis: 'none'` must not assert anything about who acted.
    for (const input of [{}, { userIdentityType: 'IAMUser' }, { userIdentityType: 'AssumedRole' }]) {
      const p = classify(input);
      if (p.basis === 'none') expect(p.actorClass).toBe('unknown');
    }
  });

  it('always explains an unknown class', () => {
    for (const input of [{}, { userAgent: AGENTS.unknown }, { userAgent: AGENTS.cli2 }, { userIdentityType: 'Root' }]) {
      const p = classify(input);
      if (p.actorClass === 'unknown') {
        expect(p.ambiguityReason, JSON.stringify(input)).toBeTruthy();
        expect(p.ambiguityReason!.length).toBeGreaterThan(20);
      }
    }
  });

  it('treats an empty or whitespace agent as absent, not as a client', () => {
    for (const userAgent of ['', '   ', null, undefined]) {
      expect(classify({ userAgent }).actorKind).toBe('unknown');
    }
  });
});

describe('root', () => {
  /**
   * Root does NOT short-circuit the agent: a root account acting through
   * Terraform is still a Terraform change, and the reviewer needs the tool as
   * much as the principal.
   */
  it('still reports the tool when root used one', () => {
    const p = classify({ userIdentityType: 'Root', userAgent: AGENTS.terraform });
    expect(p.actorKind).toBe('terraform');
  });

  it('names root when nothing else is provable, without claiming a person', () => {
    const p = classify({ userIdentityType: 'Root' });
    expect(p.actorLabel).toBe('Root account');
    expect(p.actorClass).toBe('unknown');
  });
});

describe('describeProvenance', () => {
  it('gives a reviewer one readable sentence per class', () => {
    expect(describeProvenance(classify({ invokedBy: 'autoscaling.amazonaws.com' }))).toMatch(/automatically/i);
    expect(describeProvenance(classify({ userAgent: AGENTS.terraform }))).toMatch(/Terraform/);
    expect(describeProvenance(classify({ userAgent: AGENTS.consoleCoral }))).toMatch(/by a person/i);
  });

  it('passes the ambiguity through rather than inventing certainty', () => {
    const p = classify({ userAgent: AGENTS.cli2 });
    expect(describeProvenance(p)).toBe(p.ambiguityReason);
  });

  it('leaks no credential material into the sentence', () => {
    const p = classify({ userAgent: 'aws-cli/2.0 AKIAIOSFODNN7EXAMPLE', userIdentityType: 'IAMUser' });
    expect(describeProvenance(p)).not.toMatch(/AKIA|ASIA/);
  });
});
