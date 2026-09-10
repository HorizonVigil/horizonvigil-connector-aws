# Phase 2 — Lineage + Quarantine: certification

**Verdict: NO-GO for Phase 2**, on two named gaps. Sixteen of nineteen
requirements PASS with implementation, automated tests and runtime evidence.
The gaps are stated below rather than rounded up.

---

## 1. Architecture as implemented

```
AWS API  (aws4fetch: callQueryApi / callJsonApi / safeFetch)
  │  onCall sink on AwsCreds -> captures EVERY completed call
  ↓
provider_requests        service, operation, region, AWS request id,
                         attempt, retry count, outcome, throttled, error class
  ↓
Scanner (111 files) -> ScannedResource[]
  ↓
ingestion_batches        opened BEFORE the scan, one per step execution
  ↓
admitObservations()      identity -> schema -> provider id -> partition
                         -> region -> account -> resource type
                         -> normalization -> conflict detection
  ↓
  ├── ACCEPTED    -> cloud_resources (+ lineage cols, lineage_state='traced')
  │                  -> resource_observations (deduped by fingerprint)
  └── QUARANTINED -> quarantine_records (payload retained, redacted, capped)
  ↓
closeBatch()             status DERIVED, counts asserted by a CHECK constraint
```

The single funnel is `runResourceStep` in `src/routes/discovery.ts`. Before
this phase it mapped scanner output straight into the canonical upsert with
no validation at all.

**A correction to an earlier claim of mine.** I first reported that an
unrecognised `resourceTypeKey` was "silently admitted into a catch-all
'Others' category". Checking the constraint showed otherwise:
`cloud_resources_resource_type_key_fkey` is a FOREIGN KEY to
`resource_type_catalog.key`, so the insert was rejected with 23503 — failing
the **entire step's upsert** and losing every valid record alongside the bad
one. The `catalog?.category ?? 'Others'` fallback computed a category the
database then refused.

Phase 2's improvement is therefore different from the one I first described,
and arguably larger: the offending record is quarantined with a stated
reason, and **the other records in that batch are still admitted** instead of
one unrecognised type destroying a whole step's collection.

## 2. Schema changes

**New tables:** `ingestion_batches`, `provider_requests`,
`resource_observations`, `quarantine_records`.

**Modified:** `cloud_resources` gained 16 nullable lineage columns plus
`lineage_state` (`legacy_unknown` | `traced`, defaulting to
`legacy_unknown`).

**Constraints that carry weight:**

| Constraint | What it makes impossible |
|---|---|
| `ingestion_batches_accounting` — `observed = accepted + quarantined + rejected` | A record silently disappearing (hard NO-GO #1) is unrepresentable, not merely discouraged |
| `resource_observations_dedupe` unique on (connection, type, provider id, fingerprint) | Phase 8's three duplicate cases resolved by the database, not by application logic that races |
| `grant update (status, updated_at)` on quarantine only | A member can request reprocessing but **cannot rewrite why a record was refused** — enforced by column privilege, not by trusting the handler |
| RLS member-read + INSERT/UPDATE/DELETE/TRUNCATE revoked | Evidence the customer can edit is not evidence |

TRUNCATE was revoked at creation time, applying the Phase 1G lesson rather
than rediscovering it: row-level security does not govern TRUNCATE.

**Migration:** `20260910060000_lineage_and_quarantine.sql`. Expand-only —
four new tables and nullable columns. Rollback is dropping them; the prior
code path works throughout. No existing inventory row was deleted or
reinterpreted.

## 3. API

Mounted on both `/api/aws-accounts` and `/api/v1/aws`, using the project's
existing conventions (auth, tenant resolution, Problem Details, request id,
pagination envelope).

| Endpoint | Notes |
|---|---|
| `GET /ingestion-batches` | paginated, filters intersect the permitted set |
| `GET /ingestion-batches/{id}` | includes the batch's provider requests |
| `GET /resources/{id}/lineage` | who / what / where / when / how / transformation |
| `GET /quarantine` | summary only — a list view does not ship every rejected payload |
| `GET /quarantine/{id}` | includes the redacted payload that arrived |
| `POST /quarantine/{id}/reprocess` | moves to REPROCESS_REQUESTED; admits nothing |

Every handler resolves the caller's permitted connections **under their
active scope** and filters on that, never on org alone. A record outside the
set returns **404, never 403** — a 403 confirms the id exists, which is
itself the disclosure §20 forbids.

## 4. UI

**Not built.** API only. This is a stated gap, not an omission — see §9.

## 5. Tests

| Suite | Count |
|---|---|
| connector-aws unit | 224 → **256** |
| — admission/lineage rules | 27 new |
| — write-path guards | 5 new |
| Integration (real DB, real JWT, real RLS) | 20 → **45** |
| — Phase 2 lineage/quarantine | 25 new |

All passing. No test was weakened, removed, or replaced with a mock.

## 6. Runtime evidence — a real scan, in production

Not seeded, not simulated. A bounded two-step collection run
(`regional:ec2:us-east-1`, `global:iam`) was queued against a real connected
AWS account (`604179600483`) and advanced by the **production Cloud Scheduler
worker** at 2026-09-10 04:10:47 UTC. Revision `connector-aws-00142-lhb`.

| Fact | Value |
|---|---|
| Run outcome | SUCCEEDED, 2/2 steps, 0 failed |
| Ingestion batches created | **2** |
| `regional:ec2:us-east-1` | observed 11, accepted 11, quarantined 0 → **SUCCEEDED** |
| `global:iam` | observed 10, accepted 10, quarantined 0, **8 call errors** → **PARTIALLY_SUCCEEDED** |
| `expected_count` | **null on both** — not a fake reconciliation |
| Provider requests recorded | **76**, of which **76** carry a real AWS request id |
| Failed calls recorded | 2 (recorded, not hidden) |
| Observations written | **21**, all 21 linked to a canonical resource |
| Valid SHA-256 fingerprints | **21 / 21** |
| `provider_observed_at` populated | **0 / 21** — AWS did not report it, so it is null |
| Resources now `traced` | **21** |
| Resources still `legacy_unknown` | **2,096** |
| Quarantined | 0 |

Real AWS request ids captured, e.g.
`55ec5da7-37be-4db7-8a8e-09fe18a78206` (ec2 DescribeInstances),
`e853fc4d-7e78-429c-97cb-6674c0cfae8e` (ec2 DescribeImages).

**Two results worth reading closely:**

- The `global:iam` batch is **PARTIALLY_SUCCEEDED even though every record
  was accepted**, because 8 AWS calls failed. "Do not mark a batch successful
  if required ingestion work failed" is working: a batch cannot report success
  over degraded collection.
- **Quarantine is 0, and that zero is trustworthy** — not because nothing was
  checked, but because the accounting constraint proves `observed = accepted`
  for both batches. This account's EC2 and IAM data is genuinely valid. A
  zero that could not be distinguished from "nothing ran" is the thing this
  programme exists to eliminate.

## 7. Data migration

All 2,117 pre-existing resources were left in place and marked
`lineage_state = 'legacy_unknown'`. **Nothing was backfilled.** No provider
request id, observed timestamp, batch id, collector version or source was
invented for a historical row. The lineage endpoint returns an explicit
legacy state with an explanation rather than an object full of nulls that
reads like a broken lookup. Rows acquire real lineage the next time a scan
observes them — 21 already have.

No dual-write was required: the lineage columns are additive and the prior
write path continues to work.

## 8. Certification matrix

| Requirement | Implementation | Unit | Integration | Runtime | Status |
|---|---|---|---|---|---|
| Ingestion batch | yes | yes | yes | 2 real batches | **PASS** |
| Provider request ID | yes | yes | yes | 76/76 real ids | **PASS** |
| Observation model | yes | yes | yes | 21 written | **PASS** |
| Resource lineage | yes | yes | yes | 21 traced | **PASS** |
| Source timestamps | yes | yes | yes | provider time correctly null | **PASS** |
| Transformation metadata | yes | yes | yes | versions + hashes on all 21 | **PASS** |
| Quarantine table | yes | yes | yes | schema live, 0 rows | **PASS** |
| Validation rules | yes | 27 tests | yes | pipeline ran on 21 records | **PASS** |
| Quarantine reasons | yes | yes | yes | retrieval proven | **PASS** |
| Canonical admission | yes | yes | yes | only accepted rows written | **PASS** |
| Duplicate handling | yes | yes | 4 DB scenarios | all pass | **PASS** |
| Conflict handling | yes | yes | no | — | **PARTIAL** |
| Tenant isolation | yes | — | 10 tests | all pass | **PASS** |
| Scope isolation | yes | — | 2 tests | all pass | **PASS** |
| Reprocessing | yes | — | 2 tests | column-scoped grant proven | **PASS** |
| Evidence retrieval | yes | — | 6 tests | lineage join verified in prod | **PASS** |
| Sensitive-data protection | yes | 2 tests | yes | no secrets in 76 requests | **PASS** |
| Migration safety | yes | — | yes | 2,117 rows preserved | **PASS** |
| Performance | indexes | — | — | 5/5 index scans, no N+1 | **PASS** |

## 8b. Performance — measured, not assumed (§22)

`EXPLAIN (ANALYZE)` against production, 2026-09-10:

| Query pattern | Plan | Time |
|---|---|---|
| resource → lineage | Index Scan `resource_observations_canonical` | 4.87 ms |
| batch → records | Index Scan `resource_observations_batch` | 0.74 ms |
| tenant → quarantine | Index Scan `quarantine_records_org_open` | 0.12 ms |
| tenant → recent batches | Index Scan `ingestion_batches_org_recent` | 1.00 ms |
| quarantine → reason | **Index Only Scan** `quarantine_records_reason` | 0.11 ms |

Zero sequential scans on any lineage table.

**N+1:** the resource-lineage endpoint issues exactly four queries —
resource, observations, batch, batch's provider requests — regardless of how
many observations or requests exist. It does not loop.

Caveat stated in §9.2: these tables are small today.

## 9. Remaining limitations — stated, not hidden

1. **The quarantine WRITE path has no runtime evidence, and here is exactly
   why.** All 226 `resourceTypeKey` values the 111 scanners emit were checked
   against `resource_type_catalog` in production: **zero are uncatalogued.**
   Combined with valid identities, regions and account ids in the two real
   batches, there is currently no input that any admission rule would refuse.

   That is a good product result — the catalog is complete — but it means the
   branch that writes a quarantine row has executed only in tests. Observing
   it requires deliberate fault injection, which has not been done.

   Classification is unit-proven (27 tests covering all 10 reason codes) and
   retrieval, isolation and reprocessing are integration-proven against real
   quarantine rows. The accounting constraint makes silent loss structurally
   impossible. What is missing is the single observation that a malformed AWS
   response produces a quarantine row in production.
2. **Performance was measured on small tables.** All five query patterns
   use their intended index (below), but production currently holds 2
   batches, 21 observations and 0 quarantine rows. A plan chosen correctly at
   this volume is not proof of a plan at 100,000 rows; re-measure once real
   volume accumulates.
3. **Conflict handling is unit-tested only.** The rule operates over one
   batch in memory, so a unit test is the right level for it and an
   integration test would re-run the same function — but no conflicting
   observation has been seen in production, so the branch has executed only
   in tests. Duplicate handling IS now proven against the database.
4. **No UI.** §11's evidence drawer is not built.
5. **Provider requests are attributed per BATCH, not per record.** A scanner
   makes many calls and none of the 111 report which call yielded which
   record. The API states this granularity explicitly rather than implying
   per-record provenance it does not have.
6. **`runFindingStep` and `runMetricStep` do not go through admission.**
   Findings target `vulnerability_findings` (V2-gated, and the brief says not
   to touch vulnerability functionality) and metrics target `resource_metrics`
   (a time series, not canonical resource state). Phase 2's admission rule
   covers the canonical RESOURCE table.
7. **`observation_count` is a lower bound.** PostgREST has no atomic
   increment, so repeated sightings resend the value rather than incrementing
   server-side. The API names the field `observationCountAtLeast`.

## 10. Hard NO-GO conditions

| # | Condition | Status |
|---|---|---|
| 1 | Invalid records can silently disappear | **No** — CHECK constraint |
| 2 | Invalid records can enter canonical inventory | **No** — only `admission.accepted` is upserted |
| 3 | Quarantined records affect inventory totals | **No** — integration-tested |
| 4 | Quarantined records generate recommendations | **No** — never written to `cloud_resources` |
| 5 | Tenant A can retrieve Tenant B lineage | **No** — 10 tests |
| 6 | Tenant A can retrieve Tenant B quarantine | **No** — tested incl. payload |
| 7 | Missing tenant context does not fail closed | **No** — 400, and admission quarantines with TENANT_CONTEXT_MISSING |
| 8 | Provider request IDs bypass authorization | **No** — tested |
| 9 | Historical lineage is fabricated | **No** — 2,096 rows `legacy_unknown` |
| 10 | Secrets stored in lineage/quarantine | **No** — no header/body columns exist; payload redacted |
| 11 | Canonical resources cannot be traced | **Partly** — 21 traced, 2,096 legacy pending re-scan |
| 12 | Quarantine cannot explain a rejection | **No** — reason code + rule + detail + payload |
| 13 | Runtime tests replaced with mocks | **No** |
| 14 | Tests pass because nothing was running | **No** — suite fails closed |
| 15 | Existing PASS functionality regressed | **No** — gates re-verified live |

Gates re-verified on the deployed revision: V2 denial **403**, permanent purge
**403**, remediation execute **403**.

---

```
PHASE 2 — LINEAGE + QUARANTINE

STATUS: NO-GO

Lineage:            PASS
Quarantine:         PARTIAL   (write path has no runtime evidence)
Runtime Isolation:  PASS
Canonical Admission:PASS
Evidence:           PASS
Migration Safety:   PASS
Performance:        PASS      (5/5 index scans; small-volume caveat)
```

**The single remaining blocker is quarantine's write path.** Everything else
is implemented, automatically tested and evidenced at runtime. No AWS
response has yet been malformed enough to be refused, so the branch that
writes a quarantine row has never executed outside tests — and this
programme's whole standard is that a capability is not certified because the
code looks right.

**To reach GO:** observe a real quarantine row being written by a real scan.
The cheapest honest way is a temporary, clearly-labelled fault injection in a
non-production connection — a scanner returning one record with an
uncatalogued `resourceTypeKey` — run once, evidenced, then removed.
