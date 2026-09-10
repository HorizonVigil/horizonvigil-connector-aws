# Phase 2 — Lineage + Quarantine: architecture

## Phase 0 — what the repository actually does today

Inspected 2026-09-10. This is the real path, not the prompt's assumed one.

```
AWS API
  │   aws4fetch, three helpers in src/lib/awsApi.ts:
  │     callQueryApi  (Query protocol, XML)
  │     callJsonApi   (JSON protocol)
  │     safeFetch     (raw signed client; 38 scanners use this)
  │   retry + error classification in src/lib/awsErrors.ts
  │   `onCallFailure` sink hangs off AwsCreds — reaches all 111 scanners
  │   without any scanner being edited
  │   ✗ AWS request IDs were DISCARDED (only `retry-after` was read)
  ↓
Scanner  (111 files, src/lib/scanners/)  →  ScannedResource[]
  { resourceTypeKey, resourceId, resourceName?, region, state?,
    isDefault?, tags?, metadata?, relationships? }
  ↓
runResourceStep()   src/routes/discovery.ts        ← THE admission funnel
  │   loadConnection → requirePermittedConnection  (tenant + scope)
  │   resolveCredentials
  │   scanner({ creds, region })
  │   ✗ no validation   ✗ no fingerprint   ✗ no lineage
  │   catalog lookup:  category ?? 'Others'        ← unknown type ADMITTED
  ↓
db.insert('cloud_resources?on_conflict=connection_id,resource_type_key,resource_id',
          'resolution=merge-duplicates')
  ↓
CANONICAL  (public.cloud_resources)
```

Driven by two callers, both server-owned:
`src/lib/collectionRuns.ts` (claim-and-advance worker, `STEPS_PER_SLICE=120`,
15-minute lease) and `src/routes/internalScan.ts` (scheduled).

### What already exists and is reused, not duplicated

| Prompt concept | Existing table | Note |
|---|---|---|
| Collection Job / Run | `collection_runs` | Phase 3 work; has correlation_id, lease, checkpoint |
| Collection Step | `collection_run_steps` | keyed `(run_id, step_id)` |
| Canonical Resource | `cloud_resources` | unique `(connection_id, resource_type_key, resource_id)` |
| Resource type registry | `resource_type_catalog` | `key`, `category`, `service`, `entity_class` |
| Tenant / scope | `cloud_connections.org_id`, `role_grants`, RLS | `Db` forwards the caller JWT |

### What was missing

`cloud_resources` carries **no provenance at all**. `connection_id`,
`account_id`, `region` and `resource_id` are *identity*, not lineage — they
say what the resource is, not where the belief came from. Of the ~25 lineage
fields the phase requires, one (`region`) existed.

There was no ingestion batch, no provider request record, no observation
model, and no quarantine.

### The specific silent-admission paths found

1. **Unknown resource type** → `catalog?.category ?? 'Others'`. A typo'd or
   brand-new `resourceTypeKey` becomes a real inventory row in a catch-all
   category. Nothing records that it was unrecognised.
2. **No identity validation** — a `ScannedResource` with an empty
   `resourceId` upserts on a conflict key containing an empty string.
3. **No account check** — a scanner returning a resource from a different
   AWS account is written under this connection's `account_id` regardless.
4. **A thrown scanner** returns a step error, which is visible; but a scanner
   that *returns* a malformed record has no path that records the fact.

---

## What Phase 2 adds

```
AWS API
  ↓  provider_requests           ← request id, service, operation, region,
  │                                attempt, outcome, throttled, error class
  ↓
Scanner → ScannedResource[]
  ↓
ingestion_batches               ← one per step execution
  │                                (one scanner × one region × one run)
  ↓
admitObservations()   src/lib/admission.ts
  │   1 identity        2 tenant/account     3 schema
  │   4 provider id     5 partition/region   6 resource type
  │   7 normalization   8 canonical identity 9 duplicate/conflict
  ↓
  ├── ACCEPTED    → resource_observations → cloud_resources (+ lineage cols)
  └── QUARANTINED → quarantine_records     (canonical untouched)
```

Every record ends in exactly one of those two, counted in the batch.
`accepted + quarantined = observed` is asserted, so a record cannot vanish.

### Why an ingestion batch is one step execution

A step is already the unit the system schedules, retries, checkpoints and
reports (`collection_run_steps`), and it is exactly "one scanner, one region,
one run" — a logically grouped ingestion operation. Inventing a second
grouping would create a concept with no owner and no lifecycle.

### Why observations are deduplicated by fingerprint

Writing one observation row per resource per scan would add ~1,800 rows per
scan per connection and grow without bound, answering no question the
fingerprint does not already answer.

`resource_observations` is therefore unique on
`(connection_id, resource_type_key, provider_resource_id, record_fingerprint)`:

| case | behaviour |
|---|---|
| same identity, **same** fingerprint | dedupe — bump `last_observed_at`, `observation_count`, refresh lineage to the latest batch |
| same identity, **new** fingerprint | new row — a genuinely new observation with its own lineage |
| same canonical identity, **incompatible** provider identity | QUARANTINE — canonical is not overwritten |

That is Phase 8's three cases, enforced by a unique index rather than by
application logic that races.

### Why raw payloads are not stored for accepted records

The phase says not to store huge raw payloads where a safer strategy exists.
There is no blob store in this architecture, so:

- **Accepted**: no raw payload is retained. The canonical row *is* the
  normalized form, and `record_fingerprint` + `configuration_hash` prove what
  was observed. A second full copy on every scan would multiply storage by
  scan frequency and answer nothing new.
- **Quarantined**: the offending payload **is** retained, size-capped and
  redacted. It is the evidence, it is bounded (quarantine is rare by
  design), and without it "why was this rejected" cannot be answered.

This asymmetry is deliberate and is the honest reading of the requirement.

### Validation strictness — a deliberate limit

Region is validated by **format and partition consistency**, not against a
hardcoded region list. The connector has 17 hardcoded regions (known gap
AWS-P1-01); validating membership against that list would quarantine every
resource in a region AWS launched afterwards. **An over-strict validator
manufactures false quarantines, which is its own kind of dishonesty** — it
would report a healthy account as full of invalid records.

The same reasoning applies to resource types: an uncatalogued type is
quarantined as `UNKNOWN_RESOURCE_TYPE` only because the catalog is
authoritative in this system and a missing entry means we genuinely cannot
classify the row. That is a real unknown, not a guess about AWS.

---

## Historical data

Existing `cloud_resources` rows predate all of this. Their lineage is
**`legacy_unknown`** — a real state, not a blank.

Nothing is invented: no provider request ids, no observed timestamps, no
batch ids, no collector versions. `lineage_state = 'legacy_unknown'` says
exactly what is true — this row was admitted before admission was recorded —
and rows acquire real lineage the next time a scan observes them.

No existing inventory row is deleted for lacking lineage.


---

# Operating guide

## Quarantine reason codes

Ten codes, each backed by a rule that actually runs. Codes with no rule
behind them would be a checklist, not a diagnosis.

| Code | Rule | Retryable | Meaning |
|---|---|---|---|
| `INVALID_SCHEMA` | `schema.is_object`, `schema.<field>_is_object` | no | The record is not an object, or `tags`/`metadata`/`relationships` is not an object |
| `MISSING_REQUIRED_IDENTITY` | `identity.resource_id_present`, `identity.resource_type_present` | no | No resource id, or no type key |
| `INVALID_PROVIDER_ID` | `provider_id.length`, `provider_id.control_characters` | no | Id over 1024 chars, or containing control characters |
| `INVALID_REGION` | `region.format` | no | A present region that is not a valid AWS region name. A **null** region is valid — global services have none |
| `INVALID_PARTITION` | `partition.known`, `partition.region_consistency` | no | ARN declares an unknown partition, or one contradicting its region |
| `UNKNOWN_RESOURCE_TYPE` | `resource_type.catalogued` | **yes** | Not in `resource_type_catalog`; becomes valid when the catalog gains the entry |
| `ACCOUNT_MISMATCH` | `account.matches_connection` | no | The ARN's account differs from the connection's |
| `DUPLICATE_CONFLICT` | `identity.conflict` | no | Two records in one batch claim the same identity with different ARNs |
| `NORMALIZATION_FAILURE` | `normalization.fingerprint` | yes | Fingerprinting threw |
| `TENANT_CONTEXT_MISSING` | `tenant.context_present` | yes | No org resolved; nothing may be admitted |

`retryable` answers one question: could revalidating **the same payload**
succeed later? A missing catalog entry can be added; a malformed payload
will never become well-formed.

## Troubleshooting quarantine

1. `GET /quarantine?status=QUARANTINED` — what is refused, newest first.
2. `GET /quarantine?reasonCode=UNKNOWN_RESOURCE_TYPE` — group by cause.
3. `GET /quarantine/{id}` — the redacted payload that arrived, the rule that
   refused it, and the batch it came from.
4. `GET /ingestion-batches/{id}` — every AWS request that batch made.
5. Fix the cause (usually: add the catalog entry).
6. `POST /quarantine/{id}/reprocess` — marks it for revalidation. **Nothing
   is admitted by this call.** The next scan that observes the resource runs
   the same pipeline it would have run anyway.

## Interpreting evidence

- **`expected` is null, not zero.** AWS list operations do not report how
  many results exist before paging them. `expected = observed` would be a
  reconciliation that always passes.
- **`providerObservedAt` is null on most records.** AWS did not say when it
  last observed the resource. `collectorObservedAt` is when we looked. They
  are different facts and are never merged.
- **A batch can be `PARTIALLY_SUCCEEDED` with zero quarantine.** Failed AWS
  calls count too: a batch cannot report success over degraded collection.
- **`lineage_state: legacy_unknown`** means the row predates lineage. Its
  provenance is genuinely unknown and was not invented.
- **Provider requests are per BATCH, not per record.** A scanner makes many
  calls and none report which call yielded which record.
- **`observationCountAtLeast` is a lower bound.** PostgREST has no atomic
  increment.

## Retention and sensitive data

Quarantine is the only place a raw provider record is retained. It is
redacted (any key matching secret/token/credential/password/key patterns) and
capped at 16,000 characters before storage. `provider_requests` has no
column for headers or request bodies, so there is nowhere to put a
credential even by accident.

None of these tables has a retention policy yet. `resource_observations`
grows only when a resource's fingerprint changes, which bounds it to real
change rather than scan frequency — but a long-lived, frequently-changing
estate will accumulate rows, and a retention decision will be needed.

## Tenant and scope isolation

All four tables are `org_id`-scoped with RLS member-read. Every API handler
additionally resolves the caller's permitted connections **under their active
scope** and filters on that, so a folder-scoped user cannot read another
folder's ingestion evidence. Anything outside the permitted set returns 404,
never 403.
