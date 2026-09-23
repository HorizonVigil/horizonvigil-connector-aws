import { describe, expect, it } from 'vitest';

import { parsePermissions, normalizeProtocol } from './securityGroupRules';

/** One `ipPermissions` container holding the given item XML fragments. */
const perms = (...items: string[]) => items.join('');

const ipv4 = (cidr: string, description?: string) =>
  `<ipRanges><item><cidrIp>${cidr}</cidrIp>${description ? `<description>${description}</description>` : ''}</item></ipRanges>`;

const permission = (protocol: string, fromPort: number | null, toPort: number | null, inner: string) =>
  `<item><ipProtocol>${protocol}</ipProtocol>` +
  (fromPort === null ? '' : `<fromPort>${fromPort}</fromPort>`) +
  (toPort === null ? '' : `<toPort>${toPort}</toPort>`) +
  `${inner}</item>`;

describe('normalizeProtocol', () => {
  it('maps -1 to all protocols', () => {
    expect(normalizeProtocol('-1')).toBe('all');
  });

  it('accepts IP protocol numbers, which AWS also returns', () => {
    expect(normalizeProtocol('6')).toBe('tcp');
    expect(normalizeProtocol('17')).toBe('udp');
    expect(normalizeProtocol('1')).toBe('icmp');
    expect(normalizeProtocol('58')).toBe('icmpv6');
  });

  it('keeps an unrecognized protocol rather than guessing', () => {
    expect(normalizeProtocol('47')).toBe('47');
  });

  it('returns null for absent or blank, so it is not mistaken for a rule', () => {
    expect(normalizeProtocol(null)).toBeNull();
    expect(normalizeProtocol('   ')).toBeNull();
  });
});

describe('parsePermissions', () => {
  it('reads an IPv4 rule with ports', () => {
    const { rules, unparsedCount } = parsePermissions(perms(permission('tcp', 22, 22, ipv4('0.0.0.0/0'))), 'ingress');

    expect(unparsedCount).toBe(0);
    expect(rules).toHaveLength(1);
    expect(rules[0]).toMatchObject({
      direction: 'ingress', protocol: 'tcp', fromPort: 22, toPort: 22,
      source: { kind: 'ipv4', cidr: '0.0.0.0/0' },
    });
  });

  it('reads IPv6 sources', () => {
    const xml = perms(permission('tcp', 443, 443, '<ipv6Ranges><item><cidrIpv6>::/0</cidrIpv6></item></ipv6Ranges>'));
    const { rules } = parsePermissions(xml, 'ingress');
    expect(rules[0].source).toEqual({ kind: 'ipv6', cidr: '::/0' });
  });

  it('reads prefix lists and security-group references', () => {
    const xml = perms(
      permission('tcp', 80, 80, '<prefixListIds><item><prefixListId>pl-123</prefixListId></item></prefixListIds>'),
      permission('tcp', 5432, 5432, '<groups><item><groupId>sg-abc</groupId><userId>111122223333</userId></item></groups>'),
    );
    const { rules } = parsePermissions(xml, 'ingress');

    expect(rules[0].source).toEqual({ kind: 'prefixList', prefixListId: 'pl-123' });
    expect(rules[1].source).toEqual({ kind: 'securityGroup', groupId: 'sg-abc', userId: '111122223333' });
  });

  /**
   * The reason this module fans out. AWS puts many sources under one
   * permission, and "is anything open to the world?" is a question about a
   * source — a bastion group and 0.0.0.0/0 on the same port must stay separate.
   */
  it('splits one permission with several sources into one rule per source', () => {
    const xml = perms(permission('tcp', 22, 22,
      '<ipRanges><item><cidrIp>10.0.0.0/8</cidrIp></item><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges>' +
      '<groups><item><groupId>sg-bastion</groupId></item></groups>'));

    const { rules } = parsePermissions(xml, 'ingress');

    expect(rules).toHaveLength(3);
    expect(rules.filter((r) => r.source.kind === 'ipv4')).toHaveLength(2);
    // The world-open one must survive alongside the restricted one rather than
    // being averaged away with it.
    expect(rules.some((r) => r.source.kind === 'ipv4' && r.source.cidr === '0.0.0.0/0')).toBe(true);
    expect(rules.some((r) => r.source.kind === 'ipv4' && r.source.cidr === '10.0.0.0/8')).toBe(true);
  });

  it('treats -1 as every protocol with no port bounds', () => {
    const { rules } = parsePermissions(perms(permission('-1', null, null, ipv4('0.0.0.0/0'))), 'ingress');
    expect(rules[0].protocol).toBe('all');
    expect(rules[0].fromPort).toBeNull();
    expect(rules[0].toPort).toBeNull();
  });

  it('keeps ICMP type/code in the port fields without renaming them', () => {
    // AWS reuses fromPort/toPort for ICMP type and code; -1 means all types.
    const { rules } = parsePermissions(perms(permission('icmp', -1, -1, ipv4('0.0.0.0/0'))), 'ingress');
    expect(rules[0]).toMatchObject({ protocol: 'icmp', fromPort: -1, toPort: -1 });
  });

  it('carries the rule description through', () => {
    const { rules } = parsePermissions(perms(permission('tcp', 22, 22, ipv4('10.0.0.0/8', 'bastion'))), 'ingress');
    expect(rules[0].description).toBe('bastion');
  });

  it('counts a permission with no protocol as unparsed rather than dropping it', () => {
    const { rules, unparsedCount } = parsePermissions(perms(`<item>${ipv4('0.0.0.0/0')}</item>`), 'ingress');
    expect(rules).toHaveLength(0);
    expect(unparsedCount).toBe(1);
  });

  it('counts a permission with no readable source as unparsed', () => {
    const { rules, unparsedCount } = parsePermissions(perms(permission('tcp', 22, 22, '')), 'ingress');
    expect(rules).toHaveLength(0);
    expect(unparsedCount).toBe(1);
  });

  it('distinguishes no rules from no evidence', () => {
    // An empty container is a real answer: this group has no ingress.
    expect(parsePermissions('', 'ingress')).toEqual({ rules: [], unparsedCount: 0 });
    // A missing container is the same shape HERE; the scanner is what records
    // that it looked, by always writing the inboundRules key.
    expect(parsePermissions(null, 'ingress')).toEqual({ rules: [], unparsedCount: 0 });
  });

  it('keeps duplicate rules distinguishable but identically identified', () => {
    const xml = perms(permission('tcp', 22, 22, ipv4('0.0.0.0/0')), permission('tcp', 22, 22, ipv4('0.0.0.0/0')));
    const { rules } = parsePermissions(xml, 'ingress');
    expect(rules).toHaveLength(2);
    expect(rules[0].ruleIdentity).toBe(rules[1].ruleIdentity);
  });

  it('gives the same rule the same identity across collections', () => {
    const once = parsePermissions(perms(permission('tcp', 22, 22, ipv4('0.0.0.0/0'))), 'ingress');
    const again = parsePermissions(perms(permission('tcp', 22, 22, ipv4('0.0.0.0/0'))), 'ingress');
    expect(once.rules[0].ruleIdentity).toBe(again.rules[0].ruleIdentity);
  });

  it('does not truncate on nested item tags', () => {
    // ipRanges/item sits inside ipPermissions/item; a naive first-</item>
    // match would cut the permission short and lose the second source.
    const xml = perms(
      permission('tcp', 22, 22, '<ipRanges><item><cidrIp>1.2.3.4/32</cidrIp></item></ipRanges>'),
      permission('udp', 53, 53, ipv4('0.0.0.0/0')),
    );
    const { rules } = parsePermissions(xml, 'ingress');
    expect(rules).toHaveLength(2);
    expect(rules[1].protocol).toBe('udp');
  });

  it('trims whitespace around sources so an open rule cannot compare as closed', () => {
    const { rules } = parsePermissions(perms(permission('tcp', 22, 22, ipv4(' 0.0.0.0/0 '))), 'ingress');
    expect(rules[0].source).toEqual({ kind: 'ipv4', cidr: '0.0.0.0/0' });
  });

  it('treats a whitespace-only source as no source (unparsed), not as a rule', () => {
    const { rules, unparsedCount } = parsePermissions(perms(permission('tcp', 22, 22, ipv4('   '))), 'ingress');
    expect(rules).toHaveLength(0);
    expect(unparsedCount).toBe(1);
  });
});