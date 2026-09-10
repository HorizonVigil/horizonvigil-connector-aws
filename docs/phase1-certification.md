# Phase 1 — Production Certification Evidence

**Verdict: NO-GO for Phase 1.** One category (1H) is BLOCKED on a fact about
production infrastructure that no amount of code can establish, and three
categories are PARTIAL. Details and the certification table are at the end.

Everything below was executed, not described. Where something was not
executed it is marked BLOCKED or PARTIAL rather than assumed.

---

## Environment

| | |
|---|---|
| Date | 2026-09-10 |
| Application | `horizonvigil-connector-aws`, commit `80369ca` (main) plus the two harness files listed under 1A |
| Integration database | Supabase project `zzglvvsjybuniiqeevag` (`horizonvigil-scanner-platform`) — idle since the scanner work was decommissioned, already paid for |
| Production database | Supabase project `dvyoghaqeknyyrdujssi` (`cloudops360-1-prod`) — read-only inspection plus one migration (1G) |
| Runner | local, Node/vitest 2.1.9 |

Supabase branching would have been the cleaner test-database strategy but
requires the Pro plan; the org is on Free.

---

## Service topology and enforcement path (the inspection 1A asked for first)

```
browser
  ↓  Authorization: Bearer <Supabase JWT>, X-Org-Id, X-Scope-Type/X-Scope-Id
Hono app  (app.fetch — the same entrypoint server.ts hands @hono/node-server)
  ↓  CORS + security headers
  ↓  X-Request-Id / Traceparent            (§14.6)
  ↓  getAuthContext        — real JWT, no forging
  ↓  requireOrgId          — fails closed (400) when absent
  ↓  requireMenuPermission / getOrgConnectionIds / requirePermittedConnection
  ↓  Db  — forwards the CALLER's JWT, so PostgREST applies the caller's RLS
PostgREST → Postgres RLS → row
```

Authorization is not a middleware decision that the database then trusts.
`Db` forwards the caller's token, so the row-level policies are the final
authority; a route that forgot its own check still cannot read another
tenant's rows. That is what makes the tests below meaningful rather than
tests of our own middleware.

Eleven Cloud Run services share this shape. Background work is server-owned
(`collection_runs` + Cloud Scheduler); the browser no longer orchestrates
collection.

---

## 1A — Integration harness

**Files:** `src/integration/harness.ts`, `src/integration/tenantIsolation.integration.test.ts`,
`vitest.integration.config.ts`, `.github/workflows/integration-tests.yml`.

Nothing in the request path is mocked. The harness calls
`app.fetch(request, env)` — the exact entrypoint `server.ts` passes to
`@hono/node-server` — so a test request traverses the full middleware stack
above. Tokens are obtained from the project's real `/auth/v1/token` endpoint;
nothing forges a JWT or stubs `auth.uid()`, because a forged token proves
nothing about the boundary that actually runs.

No listening server: `serve()` only adapts `app.fetch` to a socket, so
calling `app.fetch` directly exercises identical code with no port to
allocate and no teardown to leak.

**Fails closed.** `requireIntegrationEnv()` throws when the database
credentials are absent. There is deliberately no `describe.skipIf` anywhere
in the suite (§1J).

**Result:** 20 tests, 20 passed, 33.4s.

**A positive control guards against vacuity.** `returns the caller their own
data, so a pass is not vacuous` asserts Tenant A actually receives
`A-scope-A-conn`. Without it every isolation assertion could pass simply
because the endpoint returns nothing to anyone. This caught a real problem
during construction: a missing `menu_permissions` fixture made every request
400, and all the negative assertions still "passed".

---

## 1B — Two-tenant isolation

Tenant A (`aaaaaaaa-…0001`), Tenant B (`bbbbbbbb-…0001`), each with its own
connections, resources, collection runs, recommendations, alerts and audit
rows.

**Assertions are on the response BODY, not the status code.** A 200 with an
empty list and a 200 that leaked a resource name are both 200.
`assertNoTenantBData()` greps the raw body for Tenant B's markers
(`bbbbbbbb-…`, `TENANT-B-ONLY-CONNECTION`, `TENANT-B-ONLY-ALERT`,
`999999999999`, `i-TENANT-B-SECRET`, `B-secret-res`, `B SECRET idle`,
`B-SECRET-AUDIT`) so a leaked id inside a nested field, an error message or
a count is caught.

| # | Case | Result |
|---|---|---|
| 1 | A reads its own objects | PASS (positive control) |
| 2 | B reads its own objects | PASS (`and the reverse direction holds too`) |
| 3 | A fetches B connection by id | 403/404, no B markers |
| 4 | B → A direction | PASS |
| 5 | List endpoints exclude B | PASS |
| 6 | **Search endpoints** | **NOT COVERED** — see gaps |
| 7 | Aggregates exclude B | PASS (`dashboard aggregate`) |
| 8 | Jobs not referenceable across tenants | PASS (inspect, cancel, start) |
| 9 | Recommendations not referenceable | PASS |
| 10 | **Reports/exports** | **NOT COVERED** — served by `horizonvigil-reports`, not this service |
| 11 | **Audit/activity cross-tenant** | **NOT COVERED** |
| 12 | Direct DB access stays tenant-scoped | PASS — `Db` forwards the caller JWT; RLS is the boundary |

Also proven: **spoofing `X-Org-Id` to Tenant B is refused.** The header is
attacker-controlled in production, so membership — not the header — is what
authorizes.

**Two real findings came out of building this**, both fixed:

1. **A leak-scan false positive that was almost "fixed" the wrong way.**
   Marker `B-conn` matched Tenant A's own `A-scope-B-conn`. The tempting fix
   is to weaken the scan to word boundaries; the correct one is to make
   every marker unique to Tenant B, because the scan is a substring search
   *on purpose* so a leaked id nested in a payload is still caught.
2. **RFC 9457 `instance` echoes the caller's own supplied id.** Excluded
   from the leak scan — a principled exclusion of one field that reflects
   back only what the caller already knew, not a relaxation. Every other
   part of the body is still searched.

---

## 1C — Disjoint scope inside one tenant

`scoped-a` is a member of Tenant A, so tenant isolation alone does not
protect Scope B from them — the scope predicate does.

| Case | Result |
|---|---|
| Scope A user sees Scope A | PASS |
| Scope A user does not see Scope B | PASS |
| Scope A user fetches Scope B connection by id (IDOR) | 403/404, no `A-scope-B-conn` |
| search / aggregate / jobs / recommendations / reports / exports / activity / audit **at scope level** | **NOT COVERED** |

During fixture construction the scoped user initially saw an empty list.
That was Phase 0.7 deny-by-default working correctly — the *fixture* was
missing a project-scoped `role_grants` row, not the code. Worth recording
because the instinct is to assume the code is wrong.

---

## 1D — Job isolation

| Case | Result |
|---|---|
| A cannot inspect B's run | 403/404, no B markers |
| A cannot cancel B's run | 403/404 |
| A cannot **start** a run against B's connection | 403/404/409 |
| A cannot retry / finalize B's run | **NOT COVERED** |
| A cannot read B's checkpoints | **NOT COVERED** |
| Worker execution preserves tenant identity | **NOT COVERED at runtime** |
| Duplicate/idempotent job creation still works | **NOT COVERED at runtime** (partial unique index exists and is unit-tested) |

The start case is the most consequential direction: not a read leak but an
attempt to make our worker touch another tenant's cloud account.

---

## 1E — Database / RLS

Isolation is tested through the real application path, which is the only
path that proves the whole chain. Additional direct-database tests were
added for 1F and 1G, where the property under test is a database property.

- `tenant_id` mandatory: `requireOrgId` returns **400** with no `X-Org-Id`
  (test: `rejects a request with no organization context`). Fails closed.
- Unauthenticated: **401** (test: `rejects an unauthenticated request`).
- Scope predicates enforced: 1C.
- RLS not bypassable by application roles: 1G, executed as the real
  `authenticated` role.
- Service-role usage restricted: writes to `collection_runs`,
  `credential_versions` and `report_download_grants` go through the service
  role only; `credential_versions` and `report_download_grants` have RLS on
  with **no read policy at all**.

**Regression test added for a discovered bypass:** see 1G.

---

## 1F — Audit hash chain

Implemented as a database trigger, not in `writeAuditLog()`. Application-side
hashing cannot satisfy "concurrent writes cannot silently create multiple
chain heads" — two workers would both read the same head and both link to
it, forking the chain with neither side erroring. The trigger takes a
per-org `pg_advisory_xact_lock` inside the inserting transaction, and a
unique index on `(org_id, seq)` makes a fork unrepresentable even if the
lock were bypassed.

**What is hashed**, in order, joined by `chr(31)` (U+001F unit separator, a
byte that cannot occur in any field, so no rearrangement of values can
produce the same input):

`seq`, `org_id`, `actor_id`, `action`, `target_type`, `target_id`,
`ip_address`, `metadata`, `created_at`, `prev_hash`

`metadata` is cast through `jsonb`, whose text form Postgres normalises
(keys sorted, whitespace removed), so logically identical metadata always
hashes identically. `created_at` is rendered as microsecond ISO-8601 in UTC
so the hash never depends on session timezone. `sha256()` from `pg_catalog`
is used rather than pgcrypto's `digest()`, so the chain does not depend on
an extension staying installed in a particular schema.

**`chain_origin` is the honest part.** A row hashed at write time is
tamper-evident from that moment. A row hashed retroactively by the backfill
proves only that nothing has changed *since* the backfill. The two
populations are reported separately rather than presented as equivalent.

### Runtime evidence — `tests/audit_chain_tamper.sql`, 10/10 PASS

Run against the integration database 2026-09-10. Creates and drops its own
org; never touches another tenant's trail.

| # | Scenario | Expected | Result |
|---|---|---|---|
| 1 | valid chain | no problems | PASS — 0 |
| 2 | modified payload | `hash_mismatch` @2 | PASS — 1 |
| 3 | modified `entry_hash` | `hash_mismatch` @2 + `link_mismatch` @3 | PASS — 2 of 2 |
| 4 | modified `prev_hash` | `link_mismatch` @3 | PASS — 1 |
| 5 | deleted entry | `sequence_gap` | PASS — 1 |
| 6 | reordered entries | `hash_mismatch` | PASS — 2 |
| 7 | inserted entry | `link_mismatch` @4 | PASS — 1 |
| 8 | duplicate sequence | **refused by unique index** | PASS — 23505 |
| 9 | caller cannot choose chain position | seq assigned 4, not 99 | PASS |
| 10 | chain intact after all restores | no problems | PASS — 0 |

Scenario 8 asserts the write is *refused*, which is stronger than detecting
it afterwards. Scenario 9 covers the concurrency requirement's testable
half: the trigger overwrites caller-supplied `seq`/`prev_hash`/`entry_hash`,
so a writer cannot choose its own position; the advisory lock is what makes
the assigned value correct under concurrent inserts.

Scenario 10 earned its place immediately — it caught a bug in the suite's
own scenario-6 restore, where the obvious-looking mirror of the swap left
the two entries still transposed.

### Production chain status, 2026-09-10

```
intact = true   problems = 0   total = 443
live = 2        backfilled = 441        verified_from_seq = 442
```

**This is not a claim of tamper-proofing.** Anyone who can write with the
service role can also recompute the chain. What the chain provides is that
they must do so deliberately and completely — a single edited row, a
deletion, a reorder or an insertion is detected.

---

## 1G — Append-only, and a real bypass found

Tested by executing as the real `authenticated` role against the real
policies, not by reading the schema.

**Before:**

| Operation | Outcome |
|---|---|
| UPDATE | BLOCKED (0 rows — no UPDATE policy, so no row is visible) |
| DELETE | BLOCKED (0 rows) |
| **TRUNCATE** | **ALLOWED — table emptied** |

**TRUNCATE is not a row operation, so RLS never consults a policy for it.**
Supabase's default `grant all on all tables in schema public to anon,
authenticated` therefore handed every ordinary role the ability to destroy
an entire table in one statement. All 89 public tables carried it; it is a
platform default, not an `audit_log`-specific mistake.

**Why it matters more here than anywhere else:** the hash chain cannot
detect it. `verify_audit_chain()` over an emptied table returns **zero
problems** — an empty chain is an internally consistent chain. The integrity
evidence would have reported "intact" over a trail that no longer existed.
That is the same failure shape as the restore-rehearsal finding: not a
corrupted chain, which announces itself, but a plausible one.

**Reachability, stated honestly:** PostgREST never issues TRUNCATE, so this
was not exploitable through the normal API with a user JWT. It becomes
reachable through any path that executes SQL under the caller's role. The
grant has no legitimate use, so it should not exist.

**Fixed** — migration `20260910025734_audit_log_append_only_and_revoke_truncate`,
applied to production and to the integration project. Verified beforehand
that `truncate` appears nowhere in any service as SQL (every occurrence in
the codebase is the CSS class or prose) and that nothing UPDATEs or DELETEs
`audit_log`.

**After:**

| Operation | Outcome |
|---|---|
| UPDATE | BLOCKED — `42501 permission denied` |
| DELETE | BLOCKED — `42501 permission denied` |
| TRUNCATE | BLOCKED — `42501 permission denied` |
| INSERT as a real member | **ALLOWED** — chain trigger fired, `seq=1`, `origin=live`, 0 chain problems |

The INSERT positive control matters: without it, "append-only" could
silently have become "no writes at all". Note that `set role authenticated`
alone leaves `auth.uid()` null and the RLS membership predicate correctly
refuses — that is fail-closed behaviour working, but it proves nothing about
a real member, so the probe supplies a JWT claim.

Production grants now: `anon` and `authenticated` hold `INSERT, REFERENCES,
SELECT, TRIGGER` on `audit_log` and **zero** public tables grant TRUNCATE to
either role.

---

## 1H — Restore rehearsal → **BLOCKED**

Full record: [`repos/supabase/RESTORE_RUNBOOK.md`](../../supabase/RESTORE_RUNBOOK.md).

A restore rehearsal was executed for real on the integration project. Data
was genuinely destroyed — independently confirmed by the integration suite
dropping from 19/19 to 4 failed — and genuinely restored, with the resource
fingerprint matching the baseline byte for byte
(`312871393367b9040a364b35aab86370`) and the suite returning to 19/19.

Measured: RPO 8.76 s, RTO ~5 m 52 s. **Neither number transfers to
production** and neither should be quoted as a production figure: the
fixture set is 12 rows, and almost all of the RTO was diagnosing a one-time
schema-drift problem.

The rehearsal also produced a genuine operational finding, and corrected my
own first statement of it. A blanket "restoring through the chain trigger
corrupts the chain" is **false** — replaying a complete chain into an empty
table recomputes byte-identical hashes. The damage is specific to a
**partial** restore into a **non-empty** chain, where recovered entries are
silently moved to the end of the trail and re-hashed — and the result
**verifies clean**.

**Why this is BLOCKED rather than PASS:** the org is on the Supabase **free
plan**, and managed daily backups and point-in-time recovery are plan-gated.
This rehearsal proves we can restore *from a backup*; it does not establish
that production *has* one. That is a fact about infrastructure and a
purchasing decision, not something to implement:

1. Confirm in the Supabase dashboard what backup coverage production
   actually has today, and its retention.
2. If none, a plan upgrade is the prerequisite for any production RPO claim.
3. Re-run this rehearsal against a restore of a **real** production backup,
   at production volume.

Until then the honest statement is: *the restore procedure is proven; the
backup it depends on is not.*

---

## 1I — Runtime evidence

This document is the record. Every category above states environment,
timestamp, commit, tenant/scope setup, the request or operation, expected
result, actual result, and pass/fail. Correlation headers are asserted on a
real response (`carries the §14.6 correlation headers on a real response`),
so a request id in a customer's response resolves to the log line.

---

## 1J — CI

| Suite | Workflow | Behaviour when the environment is missing |
|---|---|---|
| Unit (224 tests, 22 files) | `build-and-test` | n/a — no database |
| Integration / isolation (20 tests) | `.github/workflows/integration-tests.yml` | **FAILS**, does not skip |
| Schema drift + audit tamper (10 scenarios) | `repos/supabase/.github/workflows/schema-drift.yml` | **FAILS**, does not skip |

The drift workflow also runs on a daily schedule, because drift is
introduced by applying a migration out-of-band — which touches neither
`push` nor `pull_request`.

---

## Discovered authorization / isolation bugs

| Bug | Severity | Status |
|---|---|---|
| `TRUNCATE` granted to `anon`/`authenticated` on all 89 public tables; RLS does not govern it; an emptied audit chain verifies as intact | High (low reachability) | **FIXED** in prod + integration, CI guard added |
| `alerts` table in the integration project hand-approximated (`title`/`created_at`) vs production (`alert_name`/`triggered_at`); the dashboard alerts query returned 42703 for **every** tenant, so that part of the aggregate isolation assertion was vacuous | Test-integrity | **FIXED** — schema copied from production, positive-control test added |
| Integration project missing the audit chain trigger/functions entirely | Test-integrity / DR | **FIXED** — parity migrations applied |
| 19 migrations applied to production existed only in the database, with no file in source control | DR / cannot rebuild from source | **FIXED** — all 19 recovered, CI guard added |

---

## Certification table

| Category | Implementation | Automated Tests | Runtime Evidence | Status |
|---|---|---|---|---|
| 1A Integration harness | yes | 20 tests | 20/20, 2026-09-10 | **PASS** |
| 1B Two-tenant isolation | yes | 13 tests | all pass, body-level | **PARTIAL** — search, reports/exports, audit/activity not covered |
| 1C Disjoint scope | yes | 3 tests | all pass | **PARTIAL** — list + by-id only |
| 1D Job isolation | yes | 3 tests | all pass | **PARTIAL** — retry/finalize/checkpoints/worker identity/idempotency not runtime-tested |
| 1E RLS / fail-closed | yes | 2 tests + 1G probes | 400/401 verified | **PASS** |
| 1F Audit hash chain | yes | 10 scenarios + 7 unit | 10/10; prod chain intact, 443 entries | **PASS** |
| 1G Append-only | yes | 4 probes | UPDATE/DELETE/TRUNCATE 42501; INSERT works | **PASS** |
| 1H Restore rehearsal | procedure yes | rehearsal executed | destroyed + restored, fingerprint match | **BLOCKED** — production has no certified backup source (free plan) |
| 1I Runtime evidence | this document | — | — | **PASS** |
| 1J CI | yes | 3 workflows | fail-closed verified in harness | **PASS** |

---

# PHASE 1: NO-GO

Six of ten categories PASS. The blocker is **1H**: production's backup
source is unconfirmed and the org is on a plan where managed backups and
PITR are gated. A restore procedure that has been rehearsed is worth having,
but it is not disaster recovery until there is a backup to restore *from*,
and asserting otherwise would be exactly the kind of claim this whole
programme exists to eliminate.

The three PARTIAL categories are narrower: the isolation model is proven at
runtime across the highest-risk surfaces (list, get-by-id, IDOR, header
spoofing, aggregates, job start/cancel/inspect), and the uncovered cases are
mostly additional endpoints of the same shape rather than unexercised
mechanisms. They are listed explicitly so the gap is visible rather than
implied.

**To reach GO:** confirm or purchase production backup coverage and re-run
1H against a real production backup; extend 1B/1C to search, reports/exports
and activity; extend 1D to retry/finalize/checkpoints and idempotent
creation.
