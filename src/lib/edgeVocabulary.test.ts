import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { EDGE_RELATIONSHIP_TYPES } from './edgeVocabulary';

/**
 * AWS-10 regression guard.
 *
 * `relationship_type` is validated ONLY by a database CHECK constraint. tsc
 * cannot see it, vitest cannot see it, and a wrong value costs nothing until
 * an INSERT runs against production.
 *
 * AWS-10 shipped emitting CONTAINED_BY, ATTACHED_TO and PROTECTED_BY. None
 * were permitted. Every topology write raised 23514, the caller's best-effort
 * catch swallowed it, and a 1,904-resource estate reported 3 edges — which
 * the product rendered as "no relationships" rather than as a failed write.
 *
 * Typing edge construction against EDGE_RELATIONSHIP_TYPES makes tsc reject
 * an invented value at the call site. The one thing tsc still cannot check is
 * whether that list matches the database, so it is pinned here.
 */
describe('edge relationship vocabulary', () => {
  /**
   * Verbatim from `cloud_resource_edges_relationship_type_check` in
   * production on 2026-09-15, after
   * 20260915093000_edge_vocabulary_attached_to_protected_by.sql.
   *
   * If a migration changes the constraint, this fails and the change has to
   * be made in both places deliberately — which is the point. The previous
   * arrangement let the two drift with no signal at all.
   */
  const DB_CONSTRAINT_VALUES = [
    'CONTAINS', 'BELONGS_TO', 'OWNS', 'RUNS', 'DEPENDS_ON',
    'CONNECTS_TO', 'EXPOSED_TO', 'CAN_ACCESS', 'ASSUMES', 'HAS_PERMISSION',
    'BUILT_FROM', 'DEPLOYED_TO', 'DEPLOYED_BY', 'STORES_DATA',
    'CONTAINS_VULNERABILITY', 'CONTAINS_SECRET', 'AUTHENTICATES_TO',
    'ROUTES_TO', 'TRUSTS', 'ESCALATES_TO',
    'ATTACHED_TO', 'PROTECTED_BY',
  ];

  it('matches the database CHECK constraint exactly', () => {
    expect([...EDGE_RELATIONSHIP_TYPES].sort()).toEqual([...DB_CONSTRAINT_VALUES].sort());
  });

  it('declares no duplicates', () => {
    expect(new Set(EDGE_RELATIONSHIP_TYPES).size).toBe(EDGE_RELATIONSHIP_TYPES.length);
  });

  /**
   * The migration deliberately did NOT add CONTAINED_BY: it is a synonym for
   * BELONGS_TO, and two names for one relationship makes every consumer check
   * both forever. Pinned so it cannot be reintroduced as "the obvious fix"
   * next time someone hits the constraint.
   */
  it('does not carry a synonym for BELONGS_TO', () => {
    expect(EDGE_RELATIONSHIP_TYPES).toContain('BELONGS_TO');
    expect(EDGE_RELATIONSHIP_TYPES).not.toContain('CONTAINED_BY');
  });

  /**
   * The source-level half. Typing catches a literal passed where an
   * EdgeRelationshipType is expected, but a future materializer that builds
   * its rows as plain objects would slip past. This scans every module that
   * writes edges for quoted SCREAMING_SNAKE values assigned to
   * relationship_type, whatever the surrounding types say.
   */
  it('every relationship_type literal in the connector is a permitted value', () => {
    const libDir = __dirname;
    const files = readdirSync(libDir)
      .filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))
      .map((f) => join(libDir, f));

    const found: { file: string; value: string }[] = [];
    for (const file of files) {
      for (const rawLine of readFileSync(file, 'utf8').split('\n')) {
        const line = rawLine.trim();
        // Comment lines name the rejected values on purpose (CONTAINED_BY is
        // discussed at length in both modules), so scanning them would fail
        // on the very explanation of what this prevents.
        if (line.startsWith('*') || line.startsWith('//')) continue;
        // Only lines that actually construct an edge: the object-property
        // form used by edgeMaterialization.ts, and the push() helper form
        // used by networkTopology.ts. Line-anchored rather than matched
        // across the whole file, because the helper's own arguments contain
        // parentheses -- the first version of this scan used a `[^)]*?` span
        // that could never cross `asString(rel.vpcId)`, so it matched
        // nothing and passed unconditionally. Verified by reintroducing
        // CONTAINED_BY and watching this fail.
        if (!line.includes('relationship_type:') && !line.includes('push(')) continue;
        for (const m of line.matchAll(/'([A-Z][A-Z_]{3,})'/g)) {
          found.push({ file, value: m[1] });
        }
      }
    }

    expect(found.length, 'no edge literals found — the scan pattern has gone stale').toBeGreaterThan(0);
    for (const { file, value } of found) {
      expect(
        EDGE_RELATIONSHIP_TYPES as readonly string[],
        `'${value}' in ${file} violates cloud_resource_edges_relationship_type_check`,
      ).toContain(value);
    }
  });
});
