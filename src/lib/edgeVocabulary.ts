/**
 * The relationship vocabulary `cloud_resource_edges` will actually accept.
 *
 * WHY THIS EXISTS AS A TYPE
 *
 * `relationship_type` is constrained in the DATABASE
 * (`cloud_resource_edges_relationship_type_check`) and nowhere else. A value
 * outside the list is not a type error, not a lint error, and not a test
 * failure — it is a 23514 check_violation raised at INSERT time, in
 * production, against a real estate.
 *
 * AWS-10 shipped emitting `CONTAINED_BY`, `ATTACHED_TO` and `PROTECTED_BY`.
 * None of the three were in the constraint. Every topology write failed, and
 * because the caller treats materialisation as best-effort the failure was
 * caught, logged as a generic database error, and the run reported success
 * with an empty graph. Production held 3 edges for a 1,904-resource estate
 * and the UI rendered that as "no relationships" — a total write failure
 * presented as a fact about the customer's infrastructure.
 *
 * This is the second time this session that a string only the database
 * validates reached production: `collection_runs.trigger` failed the same
 * way with invented values 'scheduled' and 'first_scan'.
 *
 * So the list is a `const` tuple and edges are typed against it. tsc now
 * rejects an invented value at the call site. What tsc CANNOT know is
 * whether this list still matches the constraint — `edgeVocabulary.test.ts`
 * pins that separately.
 */
export const EDGE_RELATIONSHIP_TYPES = [
  'CONTAINS',
  'BELONGS_TO',
  'OWNS',
  'RUNS',
  'DEPENDS_ON',
  'CONNECTS_TO',
  'EXPOSED_TO',
  'CAN_ACCESS',
  'ASSUMES',
  'HAS_PERMISSION',
  'BUILT_FROM',
  'DEPLOYED_TO',
  'DEPLOYED_BY',
  'STORES_DATA',
  'CONTAINS_VULNERABILITY',
  'CONTAINS_SECRET',
  'AUTHENTICATES_TO',
  'ROUTES_TO',
  'TRUSTS',
  'ESCALATES_TO',
  // Added by 20260915_edge_vocabulary_attached_to_protected_by. Both describe
  // relationships the original twenty could not express without losing the
  // distinction that makes them useful:
  //
  //   ATTACHED_TO   a detachable runtime binding (volume on instance). Not
  //                 BELONGS_TO — a volume is independently owned and outlives
  //                 the attachment.
  //   PROTECTED_BY  a control relationship (security group guarding an
  //                 instance). This is the edge exposure analysis traverses;
  //                 collapsing it into DEPENDS_ON would make "what governs
  //                 access to this host" unanswerable.
  'ATTACHED_TO',
  'PROTECTED_BY',
] as const;

export type EdgeRelationshipType = (typeof EDGE_RELATIONSHIP_TYPES)[number];
