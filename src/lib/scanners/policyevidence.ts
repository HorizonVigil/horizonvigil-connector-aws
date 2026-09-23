/**
 * Resource / trust policy EVIDENCE — shared by IAM (role trust policies),
 * SNS (topic policies) and SQS (queue policies).
 *
 * Like securityGroupRules.ts, this module COLLECTS facts about who a policy
 * lets in; it does not decide severity. Posture owns the verdict.
 *
 * The question every consumer asks is the same one: "can someone outside this
 * account -- or anyone at all -- reach this resource?" So the summary keeps,
 * for ALLOW statements only:
 *   - every principal, by kind;
 *   - whether any statement admits "*" with no Condition (anonymous access);
 *   - whether any statement admits "*" WITH a Condition (needs review, not a
 *     clean pass -- conditions like aws:SourceArn are what make "*" safe);
 *   - the external account IDs it trusts;
 *   - the condition keys in use (sts:ExternalId, aws:MultiFactorAuthPresent…).
 *
 * `parsed: false` means the document could not be read -- NOT that it grants
 * nothing. Posture must report that as NOT_ASSESSED.
 */

export interface PolicyPrincipals {
  aws: string[];
  service: string[];
  federated: string[];
  canonicalUser: string[];
}

export interface PolicySummary {
  /** false when the document was absent or unreadable. */
  parsed: boolean;
  /** true when a document was present (distinguishes "no policy" from "unreadable"). */
  present: boolean;
  statementCount: number;
  allowStatementCount: number;
  principals: PolicyPrincipals;
  /** An Allow statement whose principal is "*" (or {"AWS":"*"}) with NO Condition. */
  allowsAnonymous: boolean;
  /** An Allow statement whose principal is "*" but constrained by a Condition. */
  allowsAnyPrincipalWithCondition: boolean;
  /** Allow statements using NotPrincipal -- almost always a mistake, always worth review. */
  usesNotPrincipalAllow: boolean;
  /** 12-digit account IDs trusted by Allow statements, other than the owning account. */
  externalAccountIds: string[];
  /** Lower-cased condition keys across Allow statements, sorted. */
  conditionKeys: string[];
}

const EMPTY_PRINCIPALS = (): PolicyPrincipals => ({ aws: [], service: [], federated: [], canonicalUser: [] });

export function emptyPolicySummary(present: boolean): PolicySummary {
  return {
    parsed: false,
    present,
    statementCount: 0,
    allowStatementCount: 0,
    principals: EMPTY_PRINCIPALS(),
    allowsAnonymous: false,
    allowsAnyPrincipalWithCondition: false,
    usesNotPrincipalAllow: false,
    externalAccountIds: [],
    conditionKeys: [],
  };
}

const XML_ENTITIES: Record<string, string> = { '&quot;': '"', '&apos;': "'", '&lt;': '<', '&gt;': '>', '&amp;': '&' };

/**
 * Policy text as AWS returns it inside XML: entity-escaped (SNS/SQS
 * attributes) and/or URL-encoded (IAM documents). Returns the JSON text, or
 * null when absent.
 */
export function decodePolicyText(raw: string | null | undefined): string | null {
  if (raw === null || raw === undefined) return null;
  let text = raw.trim();
  if (!text) return null;
  text = text.replace(/&(quot|apos|lt|gt|amp);/g, (m) => XML_ENTITIES[m] ?? m);
  if (!text.startsWith('{') && /%[0-9A-Fa-f]{2}/.test(text)) {
    try {
      text = decodeURIComponent(text);
    } catch {
      // Not valid percent-encoding; fall through and let JSON.parse decide.
    }
  }
  return text;
}

const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);
const asStrings = (v: unknown): string[] => asArray(v).filter((x): x is string => typeof x === 'string');

/** Account ID from a principal: bare 12 digits, or any ARN carrying one. */
export function accountIdOfPrincipal(principal: string): string | null {
  if (/^\d{12}$/.test(principal)) return principal;
  const arnAccount = principal.split(':')[4];
  return arnAccount && /^\d{12}$/.test(arnAccount) ? arnAccount : null;
}

/** Account ID segment of any ARN (arn:partition:service:region:ACCOUNT:resource). */
export function accountIdFromArn(arn: string | null | undefined): string | null {
  const account = arn?.split(':')[4];
  return account && /^\d{12}$/.test(account) ? account : null;
}

/**
 * Summarizes a policy document.
 *
 * @param raw           Policy text as returned by AWS (escaped/encoded is fine).
 * @param ownAccountId  The owning account, excluded from externalAccountIds.
 */
export function summarizePolicy(raw: string | null | undefined, ownAccountId: string | null): PolicySummary {
  const text = decodePolicyText(raw);
  if (text === null) return emptyPolicySummary(false);

  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return emptyPolicySummary(true);
  }
  if (!doc || typeof doc !== 'object') return emptyPolicySummary(true);

  const statements = asArray((doc as { Statement?: unknown }).Statement)
    .filter((s): s is Record<string, unknown> => !!s && typeof s === 'object');

  const principals = EMPTY_PRINCIPALS();
  const external = new Set<string>();
  const conditionKeys = new Set<string>();
  let allowStatementCount = 0;
  let allowsAnonymous = false;
  let allowsAnyPrincipalWithCondition = false;
  let usesNotPrincipalAllow = false;

  for (const st of statements) {
    if (st.Effect !== 'Allow') continue;
    allowStatementCount += 1;

    const condition = st.Condition && typeof st.Condition === 'object' ? st.Condition as Record<string, unknown> : null;
    const hasCondition = !!condition && Object.keys(condition).length > 0;
    if (condition) {
      for (const operatorBlock of Object.values(condition)) {
        if (operatorBlock && typeof operatorBlock === 'object') {
          for (const key of Object.keys(operatorBlock)) conditionKeys.add(key.toLowerCase());
        }
      }
    }

    if (st.NotPrincipal !== undefined) usesNotPrincipalAllow = true;

    const p = st.Principal;
    let wildcard = false;
    if (p === '*') {
      wildcard = true;
    } else if (p && typeof p === 'object') {
      const map = p as Record<string, unknown>;
      const aws = asStrings(map.AWS);
      if (aws.includes('*')) wildcard = true;
      principals.aws.push(...aws.filter((a) => a !== '*'));
      principals.service.push(...asStrings(map.Service));
      principals.federated.push(...asStrings(map.Federated));
      principals.canonicalUser.push(...asStrings(map.CanonicalUser));
      for (const a of aws) {
        const account = accountIdOfPrincipal(a);
        if (account && account !== ownAccountId) external.add(account);
      }
    }

    if (wildcard) {
      if (hasCondition) allowsAnyPrincipalWithCondition = true;
      else allowsAnonymous = true;
    }
  }

  const uniqSorted = (xs: string[]) => [...new Set(xs)].sort();
  return {
    parsed: true,
    present: true,
    statementCount: statements.length,
    allowStatementCount,
    principals: {
      aws: uniqSorted(principals.aws),
      service: uniqSorted(principals.service),
      federated: uniqSorted(principals.federated),
      canonicalUser: uniqSorted(principals.canonicalUser),
    },
    allowsAnonymous,
    allowsAnyPrincipalWithCondition,
    usesNotPrincipalAllow,
    externalAccountIds: [...external].sort(),
    conditionKeys: [...conditionKeys].sort(),
  };
}

/**
 * Attribute map from an AWS Query-protocol response.
 *
 * SNS: <Attributes><entry><key>K</key><value>V</value></entry>…
 * SQS: <Attribute><Name>K</Name><Value>V</Value></Attribute>…
 *
 * Regex-based to match xmlList.ts's approach (no DOM parser on Workers).
 * Values are returned raw (still entity-escaped); decodePolicyText handles
 * the one attribute that needs decoding.
 */
export function parseAttributeEntries(xml: string, style: 'sns' | 'sqs'): Record<string, string> {
  const out: Record<string, string> = {};
  const re = style === 'sns'
    ? /<entry>\s*<key>([^<]*)<\/key>\s*<value>([\s\S]*?)<\/value>\s*<\/entry>/g
    : /<Attribute>\s*<Name>([^<]*)<\/Name>\s*<Value>([\s\S]*?)<\/Value>\s*<\/Attribute>/g;
  for (const m of xml.matchAll(re)) out[m[1].trim()] = m[2];
  return out;
}

const XML_TEXT_ENTITIES = /&(quot|apos|lt|gt|amp);/g;
/** Entity-unescaped plain attribute value, or null when absent/blank. */
export function attr(map: Record<string, string>, key: string): string | null {
  const v = map[key];
  if (v === undefined) return null;
  const t = v.replace(XML_TEXT_ENTITIES, (m) => XML_ENTITIES[m] ?? m).trim();
  return t === '' ? null : t;
}