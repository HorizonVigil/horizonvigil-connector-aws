export type ImpactLevel = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface ChangeImpact {
  severity: ImpactLevel;
  categories: Array<'security' | 'cost' | 'availability' | 'compliance' | 'identity' | 'data'>;
  summary: string;
  costImpact: 'possible_increase' | 'possible_decrease' | 'none_expected' | 'unknown';
  securityImpact: 'exposure' | 'identity' | 'encryption' | 'logging' | 'policy' | 'unknown';
  recommendedActions: string[];
  requiresReview: boolean;
}

interface Rule {
  pattern: RegExp;
  severity: Exclude<ImpactLevel, 'unknown'>;
  categories: ChangeImpact['categories'];
  securityImpact?: Exclude<ChangeImpact['securityImpact'], 'unknown'>;
  costImpact?: Exclude<ChangeImpact['costImpact'], 'unknown'>;
  summary: string;
  actions: string[];
}

// Specific, high-consequence actions precede generic create/delete/modify
// rules. This is classification, not proof of harm: the stored CloudTrail
// payload remains the evidence and the Advisor states the limitation.
const RULES: readonly Rule[] = [
  {
    pattern: /(PutBucketPolicy|PutBucketAcl|AuthorizeSecurityGroupIngress|CreateNetworkAclEntry|ModifyPublicAccessBlock|UpdateAssumeRolePolicy)/i,
    severity: 'critical', categories: ['security', 'compliance'], securityImpact: 'exposure',
    summary: 'A network or resource access boundary changed.',
    actions: ['Verify the intended principals and CIDR ranges.', 'Check public exposure and effective policy.', 'Revert or narrow access if the change is not approved.'],
  },
  {
    pattern: /(CreateAccessKey|PutUserPolicy|PutRolePolicy|Attach.*Policy|Detach.*Policy|UpdateLoginProfile|CreatePolicyVersion|SetDefaultPolicyVersion|DeleteRole|DeleteUser)/i,
    severity: 'critical', categories: ['security', 'identity', 'compliance'], securityImpact: 'identity',
    summary: 'An identity, credential, or authorization policy changed.',
    actions: ['Review the effective permissions and principal activity.', 'Confirm the change owner and approval.', 'Rotate or revoke credentials if attribution is unexpected.'],
  },
  {
    pattern: /(StopLogging|DeleteTrail|UpdateTrail|DeleteConfigurationRecorder|StopConfigurationRecorder|DeleteDetector|DisableSecurityHub|DeleteFlowLogs)/i,
    severity: 'critical', categories: ['security', 'compliance'], securityImpact: 'logging',
    summary: 'A security, audit, or configuration evidence source changed.',
    actions: ['Restore evidence collection if the interruption is unintended.', 'Confirm retention and audit continuity.', 'Escalate any unapproved monitoring gap.'],
  },
  {
    pattern: /(DisableKey|ScheduleKeyDeletion|PutBucketEncryption|DeleteBucketEncryption|ModifyDBInstance.*StorageEncrypted|CreateGrant|RevokeGrant)/i,
    severity: 'critical', categories: ['security', 'data', 'compliance'], securityImpact: 'encryption',
    summary: 'Encryption or key access changed.',
    actions: ['Validate key availability and affected data.', 'Confirm encryption remains enforced.', 'Review grants and recovery windows before approval.'],
  },
  {
    pattern: /(RunInstances|CreateDBInstance|CreateCluster|CreateFunction|CreateNatGateway|CreateLoadBalancer|CreateDomain|CreateFileSystem|Purchase|Reserve|ModifyInstanceAttribute|ModifyDBInstance)/i,
    severity: 'high', categories: ['cost', 'availability'], costImpact: 'possible_increase',
    summary: 'Capacity or a billable AWS service changed.',
    actions: ['Validate demand, size, region, and lifecycle.', 'Compare projected monthly cost with budget.', 'Confirm monitoring and rollback readiness.'],
  },
  {
    pattern: /(TerminateInstances|DeleteDBInstance|DeleteCluster|DeleteFunction|DeleteVolume|DeleteSnapshot|DeleteBucket|DeleteTable|DeleteFileSystem|ReleaseAddress)/i,
    severity: 'high', categories: ['availability', 'data', 'cost'], costImpact: 'possible_decrease',
    summary: 'A resource or retained data may have been removed.',
    actions: ['Confirm the deletion was approved.', 'Verify backups, dependencies, and recovery point.', 'Check for service impact and validate realized savings.'],
  },
  {
    pattern: /(Update|Modify|Put|Create|Delete|Attach|Detach|Associate|Disassociate|Authorize|Revoke|Enable|Disable|Start|Stop|Terminate)/i,
    severity: 'medium', categories: ['availability'],
    summary: 'AWS configuration changed.',
    actions: ['Review the before/after parameters and affected resources.', 'Confirm the actor and intended owner.', 'Check related alarms, findings, and cost movement.'],
  },
];

export function classifyChangeImpact(eventName: string, errorCode?: string | null): ChangeImpact {
  if (errorCode) {
    return {
      severity: 'low', categories: [], summary: 'AWS rejected the attempted change.',
      costImpact: 'none_expected', securityImpact: 'unknown', requiresReview: false,
      recommendedActions: ['Review the failed request only if it was unexpected or repeatedly attempted.'],
    };
  }
  const rule = RULES.find(candidate => candidate.pattern.test(eventName));
  if (!rule) {
    return {
      severity: 'unknown', categories: [], summary: 'The impact of this AWS event is not classified.',
      costImpact: 'unknown', securityImpact: 'unknown', requiresReview: true,
      recommendedActions: ['Inspect the request parameters, affected resources, and related telemetry before deciding.'],
    };
  }
  return {
    severity: rule.severity,
    categories: rule.categories,
    summary: rule.summary,
    costImpact: rule.costImpact ?? 'unknown',
    securityImpact: rule.securityImpact ?? 'unknown',
    recommendedActions: rule.actions,
    requiresReview: rule.severity === 'critical' || rule.severity === 'high' || rule.severity === 'medium',
  };
}
