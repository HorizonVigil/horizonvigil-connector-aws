/**
 * AWS-22.1 — WHO changed this, and was it a person?
 *
 * THE GAP THIS CLOSES
 *
 * The change feed already collected every signal needed to answer that
 * question — `userAgent`, `userIdentity.type`, `userIdentity.arn`,
 * `eventSource`, `sourceIPAddress` — and then handed the raw strings to the
 * customer unclassified. A reviewer scanning a week of changes had to know
 * that `APN/1.0 HashiCorp/1.0 Terraform/1.5.7` means the change came from
 * infrastructure-as-code and `Coral/Jakarta` means somebody clicked a button
 * in the console.
 *
 * It also parsed `invokedBy` and threw it away. That is the single strongest
 * signal in a CloudTrail record: when an AWS service itself made the call —
 * Auto Scaling replacing an instance, CloudFormation rolling a stack — it is
 * named there and nowhere else. Without it, a change nobody made looks
 * identical to a change nobody can be found for.
 *
 * WHY THIS MATTERS NOW
 *
 * Most infrastructure changes are no longer made by a person typing. They are
 * made by pipelines, IaC, auto-scaling, remediation jobs, and increasingly by
 * AI coding assistants acting with a developer's credentials. "An IAM role
 * changed a security group" is not an answer a reviewer can act on. "Terraform
 * changed it from a CI pipeline" and "someone clicked it in the console at
 * 02:00" demand completely different responses.
 *
 * THE RULE THIS FOLLOWS
 *
 * Classify only what a signal proves, and say so. Every result carries the
 * `basis` that produced it, and anything unproven is `unknown` with a stated
 * reason rather than a confident guess. A misattributed change is worse than
 * an unattributed one: it sends the reviewer to the wrong person.
 *
 * The clearest case is the AWS CLI. `aws-cli/2.15.0` is used by a person at a
 * terminal AND by half the CI pipelines in the world, and CloudTrail does not
 * distinguish them. So the KIND is `cli` — which is provable — while the
 * CLASS stays `unknown`, with the ambiguity named. Guessing "human" there
 * would put a name on an automated change.
 */

/** Was a person at the keyboard? */
export type ActorClass =
  /** A person acting interactively. */
  | 'human'
  /** Software acting on a person's or a pipeline's behalf. */
  | 'automation'
  /** An AWS service acting on its own (auto-scaling, stack rollback, ...). */
  | 'aws_service'
  /** The signals present do not settle it. Never a placeholder for "probably human". */
  | 'unknown';

/** What did the acting, specifically. Provable from the user agent or invokedBy. */
export type ActorKind =
  | 'console'
  | 'cli'
  | 'sdk'
  | 'terraform'
  | 'cloudformation'
  | 'cdk'
  | 'pulumi'
  | 'ansible'
  | 'ai_assistant'
  | 'aws_service'
  | 'unknown';

/** Which signal produced the verdict. Stored so a classification can be argued with. */
export type ProvenanceBasis = 'invoked_by' | 'identity_type' | 'user_agent' | 'none';

export interface ChangeProvenance {
  actorClass: ActorClass;
  actorKind: ActorKind;
  basis: ProvenanceBasis;
  /** Display name, e.g. "Terraform" or "AWS Auto Scaling". Null when unknown. */
  actorLabel: string | null;
  /** Present whenever the class is `unknown`, explaining what was missing or ambiguous. */
  ambiguityReason: string | null;
}

export interface ProvenanceInput {
  /** `userIdentity.type`: Root, IAMUser, AssumedRole, AWSService, FederatedUser, ... */
  userIdentityType?: string | null;
  /** `userIdentity.invokedBy`: the AWS service that made the call, when one did. */
  invokedBy?: string | null;
  userAgent?: string | null;
  eventSource?: string | null;
}

/**
 * AWS service principals seen in `invokedBy`, mapped to names a reviewer
 * recognises. An unlisted one is still `aws_service` — the presence of
 * `invokedBy` at all is what proves it, not membership of this list.
 */
const AWS_SERVICE_LABELS: Record<string, string> = {
  'autoscaling.amazonaws.com': 'AWS Auto Scaling',
  'application-autoscaling.amazonaws.com': 'AWS Application Auto Scaling',
  'cloudformation.amazonaws.com': 'AWS CloudFormation',
  'ec2.amazonaws.com': 'Amazon EC2',
  'ecs.amazonaws.com': 'Amazon ECS',
  'eks.amazonaws.com': 'Amazon EKS',
  'lambda.amazonaws.com': 'AWS Lambda',
  'rds.amazonaws.com': 'Amazon RDS',
  'ssm.amazonaws.com': 'AWS Systems Manager',
  'elasticbeanstalk.amazonaws.com': 'AWS Elastic Beanstalk',
  'backup.amazonaws.com': 'AWS Backup',
  'config.amazonaws.com': 'AWS Config',
  'securityhub.amazonaws.com': 'AWS Security Hub',
  'guardduty.amazonaws.com': 'Amazon GuardDuty',
  'organizations.amazonaws.com': 'AWS Organizations',
  'codepipeline.amazonaws.com': 'AWS CodePipeline',
  'codebuild.amazonaws.com': 'AWS CodeBuild',
};

/**
 * User-agent matchers, most specific first.
 *
 * Order is load-bearing: the CDK and Terraform both embed an AWS SDK string
 * in their agent, so a bare `aws-sdk` match has to come last or every IaC
 * change is filed as a generic SDK call. Likewise the AWS CLI's agent
 * contains `botocore`, so the CLI must be tested before the Python SDK.
 */
const USER_AGENT_RULES: readonly {
  pattern: RegExp;
  kind: ActorKind;
  actorClass: ActorClass;
  label: string;
  ambiguityReason?: string;
}[] = [
  /*
   * AI coding assistants. These act with a developer's own credentials, so
   * identity alone cannot distinguish them from that developer typing -- the
   * agent string is the only thing that can, which is exactly why it is worth
   * classifying.
   */
  { pattern: /\b(amazonq|amazon-q|q-developer|codewhisperer)\b/i, kind: 'ai_assistant', actorClass: 'automation', label: 'Amazon Q' },
  { pattern: /\b(copilot|cursor|claude-code|openai|anthropic)\b/i, kind: 'ai_assistant', actorClass: 'automation', label: 'AI coding assistant' },

  // Infrastructure as code.
  { pattern: /\bterraform\b/i, kind: 'terraform', actorClass: 'automation', label: 'Terraform' },
  { pattern: /\bopentofu\b/i, kind: 'terraform', actorClass: 'automation', label: 'OpenTofu' },
  { pattern: /\bpulumi\b/i, kind: 'pulumi', actorClass: 'automation', label: 'Pulumi' },
  { pattern: /\baws-cdk\b/i, kind: 'cdk', actorClass: 'automation', label: 'AWS CDK' },
  { pattern: /\bansible\b/i, kind: 'ansible', actorClass: 'automation', label: 'Ansible' },
  { pattern: /cloudformation\.amazonaws\.com/i, kind: 'cloudformation', actorClass: 'aws_service', label: 'AWS CloudFormation' },

  /*
   * The console. `Coral/` is the console's own backend framework and appears
   * on console-originated calls that do not carry the friendlier agent.
   */
  { pattern: /(console|signin)\.amazonaws\.com/i, kind: 'console', actorClass: 'human', label: 'AWS Console' },
  { pattern: /^AWS Internal$/i, kind: 'console', actorClass: 'human', label: 'AWS Console' },
  { pattern: /\bCoral\//i, kind: 'console', actorClass: 'human', label: 'AWS Console' },

  /*
   * The CLI. Kind is provable; CLASS is not -- the same binary is a person at
   * a terminal and a CI job, and CloudTrail cannot tell them apart. Naming the
   * ambiguity is the honest answer; guessing "human" would put a person's name
   * on an automated change.
   */
  {
    pattern: /\baws-cli\//i,
    kind: 'cli',
    actorClass: 'unknown',
    label: 'AWS CLI',
    ambiguityReason: 'The AWS CLI is used both by people at a terminal and by automation, and CloudTrail does not record which.',
  },

  // Generic SDKs. Last, because IaC tools embed these strings too.
  {
    pattern: /\b(aws-sdk|botocore|boto3|aws_sdk)\b/i,
    kind: 'sdk',
    actorClass: 'automation',
    label: 'AWS SDK',
  },
];

/**
 * Classifies one change event.
 *
 * Signals are consulted in order of how much they prove:
 *   1. `invokedBy`  — AWS itself naming the calling service. Unambiguous.
 *   2. identity type `AWSService` — same conclusion by a weaker route.
 *   3. `userAgent`  — what software made the call.
 *   4. nothing      — `unknown`, said plainly.
 *
 * Root is deliberately NOT short-circuited above the user agent: a root
 * account acting through Terraform is still a Terraform change, and the
 * reviewer needs the tool as much as the principal. Root only decides the
 * outcome when the agent proves nothing.
 */
export function classifyProvenance(input: ProvenanceInput): ChangeProvenance {
  const invokedBy = input.invokedBy?.trim();

  if (invokedBy) {
    return {
      actorClass: 'aws_service',
      actorKind: 'aws_service',
      basis: 'invoked_by',
      actorLabel: AWS_SERVICE_LABELS[invokedBy.toLowerCase()] ?? invokedBy,
      ambiguityReason: null,
    };
  }

  const identityType = input.userIdentityType?.trim();

  if (identityType === 'AWSService') {
    const source = input.eventSource?.trim().toLowerCase();
    return {
      actorClass: 'aws_service',
      actorKind: 'aws_service',
      basis: 'identity_type',
      actorLabel: (source && AWS_SERVICE_LABELS[source]) ?? source ?? 'An AWS service',
      ambiguityReason: null,
    };
  }

  const agent = input.userAgent?.trim();

  if (agent) {
    for (const rule of USER_AGENT_RULES) {
      if (!rule.pattern.test(agent)) continue;
      return {
        actorClass: rule.actorClass,
        actorKind: rule.kind,
        basis: 'user_agent',
        actorLabel: rule.label,
        ambiguityReason: rule.ambiguityReason ?? null,
      };
    }
  }

  /*
   * Nothing proved a tool. The identity type still says whether a PRINCIPAL
   * was involved, which is weaker but not nothing -- and it must not be
   * inflated into a class. An IAM user's credentials are used by people and by
   * long-lived scripts alike.
   */
  if (identityType === 'Root') {
    return {
      actorClass: 'unknown',
      actorKind: 'unknown',
      basis: 'identity_type',
      actorLabel: 'Root account',
      ambiguityReason: agent
        ? 'The root account made this change with an unrecognised client, so whether a person was involved is not recorded.'
        : 'The root account made this change and no client was recorded.',
    };
  }

  return {
    actorClass: 'unknown',
    actorKind: 'unknown',
    basis: agent ? 'user_agent' : 'none',
    actorLabel: null,
    ambiguityReason: agent
      ? 'The client that made this change was not recognised, so whether a person was involved is not recorded.'
      : 'CloudTrail recorded no client for this change, so whether a person was involved is not recorded.',
  };
}

/** One sentence a reviewer can read in a feed, without re-deriving the fields. */
export function describeProvenance(p: ChangeProvenance): string {
  switch (p.actorClass) {
    case 'aws_service':
      return `${p.actorLabel ?? 'An AWS service'} made this change automatically.`;
    case 'automation':
      return `Made through ${p.actorLabel ?? 'automation'}, not by hand.`;
    case 'human':
      return `Made by a person in ${p.actorLabel ?? 'the console'}.`;
    case 'unknown':
      return p.ambiguityReason ?? 'Who made this change is not recorded.';
  }
}
