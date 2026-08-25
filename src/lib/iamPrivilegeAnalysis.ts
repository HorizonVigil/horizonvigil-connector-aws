/**
 * Real IAM policy-document analysis — the "is this identity over-privileged"
 * leg of a toxic-combination correlation, which nothing in this codebase
 * has ever computed before (confirmed: no ListAttachedRolePolicies/
 * ListRolePolicies/GetPolicyVersion call existed anywhere prior to this).
 *
 * Deliberately conservative about API call volume: this runs once per
 * account (IAM is a global-service scan, not per-region), but a large
 * account can have hundreds of roles, each with several attached + inline
 * policies, and each policy potentially needing its own GetPolicyVersion
 * call — left unbounded this could be thousands of subrequests in one
 * scan step. ROLE_ANALYSIS_CAP and the per-role policy caps below bound the
 * worst case the same way EC2_METRICS_INSTANCE_CAP and every finding
 * scanner's `.slice(0, N)` already do in this codebase: analyze the first N,
 * leave the rest with no privilege data rather than risk the step failing
 * for everyone.
 */

export type PrivilegeLevel = 'scoped' | 'broad' | 'admin_equivalent';

export interface PrivilegeAnalysisResult {
  privilegeLevel: PrivilegeLevel;
  privilegeReasons: string[];
  /** The full inventory of policies actually examined (capped the same way as the analysis itself) -- distinct from privilegeReasons, which only explains *why* a level was assigned. A scoped principal still has a real, non-empty policy list worth showing; privilegeReasons alone would render as one generic "no wildcard grants" line. */
  attachedPolicyNames: string[];
  inlinePolicyNames: string[];
}

export const ROLE_ANALYSIS_CAP = 100;
const MAX_ATTACHED_POLICIES_PER_PRINCIPAL = 10;
const MAX_INLINE_POLICIES_PER_PRINCIPAL = 5;

/** AWS-managed policies whose name alone (no document fetch needed) implies broad or admin-equivalent access — the well-known, bounded set a real AWS practitioner would recognize on sight. */
const ADMIN_EQUIVALENT_MANAGED_POLICY_NAMES = new Set(['AdministratorAccess', 'IAMFullAccess']);
const BROAD_MANAGED_POLICY_NAME_SUFFIXES = ['FullAccess'];
const BROAD_MANAGED_POLICY_NAMES = new Set(['PowerUserAccess']);

interface PolicyStatement {
  Effect?: string;
  Action?: string | string[];
  Resource?: string | string[];
}
interface PolicyDocument {
  Statement?: PolicyStatement | PolicyStatement[];
}

/** Evaluates one already-parsed policy document's statements for wildcard grants. Never throws on malformed input — a policy this codebase can't parse just contributes no reasons, same "degrade honestly" convention as every AWS response parser here. */
export function evaluatePolicyDocument(doc: PolicyDocument, sourceLabel: string): { isAdminEquivalent: boolean; isBroad: boolean; reasons: string[] } {
  const statements = Array.isArray(doc.Statement) ? doc.Statement : doc.Statement ? [doc.Statement] : [];
  let isAdminEquivalent = false;
  let isBroad = false;
  const reasons: string[] = [];

  for (const stmt of statements) {
    if (stmt.Effect !== 'Allow') continue;
    const actions = toArray(stmt.Action);
    const resources = toArray(stmt.Resource);
    const hasWildcardResource = resources.includes('*');
    const hasFullWildcardAction = actions.includes('*');
    if (hasFullWildcardAction && hasWildcardResource) {
      isAdminEquivalent = true;
      reasons.push(`${sourceLabel}: Action "*" on Resource "*"`);
      continue;
    }
    const serviceWildcards = actions.filter((a) => /^[a-zA-Z0-9-]+:\*$/.test(a));
    if (serviceWildcards.length > 0 && hasWildcardResource) {
      isBroad = true;
      reasons.push(`${sourceLabel}: ${serviceWildcards.join(', ')} on Resource "*"`);
    }
  }
  return { isAdminEquivalent, isBroad, reasons };
}

function toArray(v: string | string[] | undefined): string[] {
  if (v === undefined) return [];
  return Array.isArray(v) ? v : [v];
}

/** `arn:aws:iam::aws:policy/AdministratorAccess` -> `AdministratorAccess`. */
function managedPolicyName(policyArn: string): string {
  return policyArn.split('/').pop() ?? policyArn;
}

export function classifyAttachedManagedPolicy(policyArn: string): { isAdminEquivalent: boolean; isBroad: boolean; reason: string } | null {
  // Only AWS-managed policies (arn:aws:iam::aws:policy/...) are classified by name alone — a customer-managed policy's name is arbitrary and tells us nothing, so those go through evaluatePolicyDocument via a real GetPolicyVersion call instead (see analyzePrincipalPolicies below).
  if (!policyArn.startsWith('arn:aws:iam::aws:policy/')) return null;
  const name = managedPolicyName(policyArn);
  if (ADMIN_EQUIVALENT_MANAGED_POLICY_NAMES.has(name)) return { isAdminEquivalent: true, isBroad: false, reason: `AWS managed policy ${name}` };
  if (BROAD_MANAGED_POLICY_NAMES.has(name) || BROAD_MANAGED_POLICY_NAME_SUFFIXES.some((suf) => name.endsWith(suf))) {
    return { isAdminEquivalent: false, isBroad: true, reason: `AWS managed policy ${name}` };
  }
  return null;
}

export interface PrincipalPolicyFetcher {
  listAttachedPolicies(): Promise<{ policyArn: string }[]>;
  listInlinePolicyNames(): Promise<string[]>;
  getInlinePolicyDocument(policyName: string): Promise<PolicyDocument | null>;
  getManagedPolicyDocument(policyArn: string): Promise<PolicyDocument | null>;
}

/**
 * Combines the AWS-managed-name shortcut (no extra calls) with real
 * document fetches for customer-managed + inline policies, capped per
 * principal so one role with dozens of attached policies can't blow the
 * step's subrequest budget on its own.
 */
export async function analyzePrincipalPolicies(fetcher: PrincipalPolicyFetcher, principalLabel: string): Promise<PrivilegeAnalysisResult> {
  let isAdminEquivalent = false;
  let isBroad = false;
  const reasons: string[] = [];
  const attachedPolicyNames: string[] = [];

  const attached = (await fetcher.listAttachedPolicies()).slice(0, MAX_ATTACHED_POLICIES_PER_PRINCIPAL);
  for (const { policyArn } of attached) {
    attachedPolicyNames.push(managedPolicyName(policyArn));
    const managedResult = classifyAttachedManagedPolicy(policyArn);
    if (managedResult) {
      isAdminEquivalent = isAdminEquivalent || managedResult.isAdminEquivalent;
      isBroad = isBroad || managedResult.isBroad;
      reasons.push(managedResult.reason);
      continue;
    }
    // Customer-managed policy — its name tells us nothing, so fetch and evaluate its actual document.
    const doc = await fetcher.getManagedPolicyDocument(policyArn);
    if (!doc) continue;
    const result = evaluatePolicyDocument(doc, `attached policy ${managedPolicyName(policyArn)}`);
    isAdminEquivalent = isAdminEquivalent || result.isAdminEquivalent;
    isBroad = isBroad || result.isBroad;
    reasons.push(...result.reasons);
  }

  const inlinePolicyNames = (await fetcher.listInlinePolicyNames()).slice(0, MAX_INLINE_POLICIES_PER_PRINCIPAL);
  for (const name of inlinePolicyNames) {
    const doc = await fetcher.getInlinePolicyDocument(name);
    if (!doc) continue;
    const result = evaluatePolicyDocument(doc, `inline policy ${name}`);
    isAdminEquivalent = isAdminEquivalent || result.isAdminEquivalent;
    isBroad = isBroad || result.isBroad;
    reasons.push(...result.reasons);
  }

  const privilegeLevel: PrivilegeLevel = isAdminEquivalent ? 'admin_equivalent' : isBroad ? 'broad' : 'scoped';
  if (privilegeLevel === 'scoped') reasons.push(`${principalLabel}: no wildcard grants found in the policies analyzed`);
  return { privilegeLevel, privilegeReasons: reasons, attachedPolicyNames, inlinePolicyNames };
}

/** Decodes IAM's URL-encoded PolicyDocument JSON, tolerating anything malformed by returning null rather than throwing — same degrade-honestly convention as every other AWS response parser in this codebase. */
export function parsePolicyDocument(urlEncodedJson: string | null): PolicyDocument | null {
  if (!urlEncodedJson) return null;
  try {
    return JSON.parse(decodeURIComponent(urlEncodedJson)) as PolicyDocument;
  } catch {
    return null;
  }
}
