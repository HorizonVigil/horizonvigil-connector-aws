import { extractSection, extractListItems, field } from '../xmlList';

/**
 * AWS-16 / Blocker 6 — security-group inbound rules as retained evidence.
 *
 * WHAT WAS WRONG
 *
 * The EC2 scanner read `ipPermissions` and stored only `.length` as
 * `inboundRuleCount`, discarding every rule. 61 security groups were
 * collected on the live estate and open-ingress — the single check customers
 * most expect from a cloud posture product — was therefore not computable.
 * `postureChecks.ts` declared it an explicit gap rather than passing it, which
 * was honest, but a gap on the most important check is still a gap.
 *
 * WHY ONE ROW PER SOURCE
 *
 * AWS returns one `ipPermissions` item per (protocol, port-range) with a LIST
 * of sources inside it — several CIDRs, several peer groups, a prefix list.
 * "Is anything open to the world?" is a question about a SOURCE, so this fans
 * each permission out to one normalized rule per source. A group whose port 22
 * is reachable from both a bastion group and 0.0.0.0/0 must not be able to
 * average those into one verdict.
 *
 * DISTINGUISHING "NO RULES" FROM "NOT COLLECTED"
 *
 * This is the part that matters for honesty. A security group with no ingress
 * and a security group whose rules were never read both produce zero findings,
 * and only one of them is safe. The scanner therefore writes the `inboundRules`
 * KEY unconditionally, empty array included — its PRESENCE is what makes a
 * resource judgeable. The 61 groups already in inventory were written
 * by the previous scanner and carry no such key, so posture reports them
 * NOT_ASSESSED until the next collection, rather than silently PASS.
 */

/**
 * Stamped on every collected group. Lets a consumer tell evidence produced by
 * this normalizer from evidence produced by a future one, without inferring it
 * from which fields happen to be present.
 */
export const SECURITY_GROUP_RULES_EVIDENCE_VERSION = 1;

export type RuleSource =
  | { kind: 'ipv4'; cidr: string }
  | { kind: 'ipv6'; cidr: string }
  | { kind: 'prefixList'; prefixListId: string }
  | { kind: 'securityGroup'; groupId: string; userId: string | null };

export interface SecurityGroupRule {
  direction: 'ingress' | 'egress';
  /** Normalized: tcp | udp | icmp | icmpv6 | all, or the raw value if unrecognized. */
  protocol: string;
  /**
   * For TCP/UDP these are ports. For ICMP they are type and code — AWS reuses
   * the same fields — so they are NOT renamed to `port`, and any consumer
   * applying port logic must exclude ICMP first.
   */
  fromPort: number | null;
  toPort: number | null;
  source: RuleSource;
  description: string | null;
  /** Deterministic, so the same rule diffs equal across collections. */
  ruleIdentity: string;
}

export interface ParsedRules {
  rules: SecurityGroupRule[];
  /**
   * Permission entries that could not be normalized (no protocol, or no source
   * of any kind). Surfaced rather than dropped: a rule we failed to read is not
   * a rule that does not exist.
   */
  unparsedCount: number;
}

/** AWS accepts IP protocol numbers as well as names. */
const PROTOCOL_NUMBERS: Record<string, string> = {
  '1': 'icmp',
  '6': 'tcp',
  '17': 'udp',
  '58': 'icmpv6',
};

/** `-1` is AWS's "every protocol", which also implies every port. */
export function normalizeProtocol(raw: string | null): string | null {
  if (raw === null || raw.trim() === '') return null;
  const v = raw.trim().toLowerCase();
  if (v === '-1') return 'all';
  return PROTOCOL_NUMBERS[v] ?? v;
}

function intOrNull(raw: string | null): number | null {
  if (raw === null || raw.trim() === '') return null;
  const n = Number(raw);
  return Number.isInteger(n) ? n : null;
}

function identityFor(direction: string, protocol: string, fromPort: number | null, toPort: number | null, source: RuleSource): string {
  const s =
    source.kind === 'ipv4' ? `ipv4:${source.cidr}`
      : source.kind === 'ipv6' ? `ipv6:${source.cidr}`
        : source.kind === 'prefixList' ? `pl:${source.prefixListId}`
          : `sg:${source.groupId}`;
  return `${direction}|${protocol}|${fromPort ?? '*'}|${toPort ?? '*'}|${s}`;
}

/**
 * Normalizes one `ipPermissions` / `ipPermissionsEgress` section.
 *
 * @param sectionXml Inner XML of the permissions container, or null when absent.
 */
export function parsePermissions(sectionXml: string | null, direction: 'ingress' | 'egress'): ParsedRules {
  const rules: SecurityGroupRule[] = [];
  let unparsedCount = 0;

  for (const perm of extractListItems(sectionXml)) {
    const protocol = normalizeProtocol(field(perm, 'ipProtocol'));

    if (protocol === null) {
      // No protocol is not a rule we can reason about at all.
      unparsedCount += 1;
      continue;
    }

    const fromPort = intOrNull(field(perm, 'fromPort'));
    const toPort = intOrNull(field(perm, 'toPort'));

    const sources: { source: RuleSource; description: string | null }[] = [];

    for (const r of extractListItems(extractSection(perm, 'ipRanges'))) {
      const cidr = field(r, 'cidrIp');
      if (cidr) sources.push({ source: { kind: 'ipv4', cidr }, description: field(r, 'description') });
    }

    for (const r of extractListItems(extractSection(perm, 'ipv6Ranges'))) {
      const cidr = field(r, 'cidrIpv6');
      if (cidr) sources.push({ source: { kind: 'ipv6', cidr }, description: field(r, 'description') });
    }

    for (const r of extractListItems(extractSection(perm, 'prefixListIds'))) {
      const id = field(r, 'prefixListId');
      if (id) sources.push({ source: { kind: 'prefixList', prefixListId: id }, description: field(r, 'description') });
    }

    for (const g of extractListItems(extractSection(perm, 'groups'))) {
      const groupId = field(g, 'groupId');
      if (groupId) {
        sources.push({
          source: { kind: 'securityGroup', groupId, userId: field(g, 'userId') },
          description: field(g, 'description'),
        });
      }
    }

    if (sources.length === 0) {
      // A permission with a protocol but no readable source. AWS does not
      // normally emit this; counting it keeps an unreadable rule visible
      // instead of letting it vanish into a clean result.
      unparsedCount += 1;
      continue;
    }

    for (const { source, description } of sources) {
      rules.push({
        direction,
        protocol,
        fromPort,
        toPort,
        source,
        description,
        ruleIdentity: identityFor(direction, protocol, fromPort, toPort, source),
      });
    }
  }

  return { rules, unparsedCount };
}

/*
 * EXPOSURE CLASSIFICATION DELIBERATELY DOES NOT LIVE HERE.
 *
 * This module's job is to COLLECT evidence faithfully. Deciding whether a rule
 * is a finding -- which ports matter, what severity, under which policy
 * version -- is posture's job, and posture is owned by horizonvigil-security
 * (`src/lib/securityGroupExposure.ts`), which is what reads
 * `cloud_resources.metadata` and serves the checks.
 *
 * Keeping one implementation in one place matters more than convenience here:
 * a second copy of the severity rules would drift from the first, and the two
 * would disagree about the same security group while both looked authoritative.
 */
