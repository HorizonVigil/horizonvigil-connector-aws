# ADR 0001 — Durable collection jobs on Cloud Run + Postgres, not Temporal on EKS

- **Status:** Accepted for V1
- **Date:** 2026-09-09
- **Context:** Phase 3 of the AWS connector productionization
- **Supersedes:** nothing
- **Required by:** connector build prompt rule 14 and §21; audit finding AWS-P1-09

## Context

PRD §42.2 mandates regional AWS data planes on EKS, an AWS-native storage and
event stack, a Next.js BFF, Go services, and Temporal for workflow durability.

The deployed platform is none of those. It is TypeScript/Hono services on
Google Cloud Run in `us-central1`, Supabase Postgres, Cloud Scheduler, and a
React/Vite SPA. The 2026-09-08 audit records this as AWS-P1-09, "Architecture
contract is unresolved", and is explicit that the conflict must not be hidden.

Phase 3 has to make collection durable. That forces the question: implement
§42.2, or meet its guarantees on the stack that exists?

## Decision

**Implement durable collection on the current stack.** Do not migrate to
EKS/Temporal/Go as part of this work.

The mechanism is a **claim-and-advance worker**:

- A `collection_runs` row IS the job. It owns status, a step cursor, a lease,
  an attempt counter, an idempotency key, and immutable terminal state.
- `collection_run_steps` records each step's outcome, so terminal status is
  computed from committed child rows rather than from anything a client sends.
- A Cloud Scheduler tick calls an internal worker endpoint. The worker claims
  due runs by taking a time-boxed lease (`lease_expires_at`, `lease_owner`),
  executes a **bounded slice** of steps that fits inside the Cloud Run request
  budget, writes a checkpoint, and returns.
- The next tick resumes from the checkpoint. A worker that dies mid-slice
  loses only its lease; the run is reclaimed once the lease expires.

## Why not simply implement §42.2

Rule 14: "Do not perform a speculative full-stack rewrite solely to match the
reference architecture. Preserve the current stack where it can meet the
contracts." And §21: "never make a hurried big-bang infrastructure migration
part of an emergency bug fix."

A migration to EKS + Temporal + Go is a multi-quarter programme touching every
service, its deployment, its observability and its on-call model. Phase 3's
actual defect is that **the browser owns collection** — a 1,628-step scan runs
in a tab, and closing the tab loses the run. That defect is fixed by moving
ownership to the server. It is not fixed by changing which server.

Sequencing the rewrite first would leave the browser orchestrating production
scans for the entire duration of the migration.

## Why claim-and-advance rather than one long request

Cloud Run caps a request at 60 minutes. Observed discovery runs have a median
of ~14 minutes and a maximum of ~384 minutes (6.4 hours). A synchronous
"run the whole scan in one request" design would therefore fail outright on
large accounts — the very accounts that matter most.

Options considered:

1. **One long request.** Rejected: exceeds the platform limit, and a
   redeploy or instance recycle loses the run with no checkpoint.
2. **Background work after responding.** Rejected: Cloud Run throttles CPU
   after a response unless "CPU always allocated" is on, so this silently
   half-runs. Depending on an undocumented margin is how the current
   browser-orchestration bug happened in the first place.
3. **Cloud Tasks fan-out, one task per step.** Viable, and closer to §42.2's
   spirit. Rejected for V1 because 1,628 tasks per scan per connection needs
   queue-level rate control, a dead-letter policy, and per-task auth before it
   is safer than what it replaces — more new infrastructure than the defect
   requires. Kept as the natural next step if slice throughput becomes the
   constraint.
4. **Claim-and-advance (chosen).** Uses only what is already deployed and
   already proven: Postgres for state, Cloud Scheduler for the tick, the
   existing `internalScan` step executor for the work.

## Equivalence to the guarantees §42.2 was chosen for

| Guarantee | Temporal | This design |
|---|---|---|
| Survives worker death | Event-sourced replay | Lease expiry + step cursor; work resumes on the next tick |
| Exactly-once effects | Idempotent activities | Idempotent upserts on natural keys, already how scanners write |
| No duplicate runs | Workflow ID reuse policy | `idempotency_key` unique per active run, plus a per-connection lease |
| Cancellation | Cancellation scopes | `CANCEL_REQUESTED`, observed by the worker between steps |
| Progress visibility | Workflow history | `collection_run_steps` rows |
| Retry with backoff | Activity retry policy | `attempt` + `next_attempt_at`, reusing the jittered backoff already in `awsErrors.ts` |

What this design does **not** match: sub-second scheduling latency (a tick is
minutes), cross-service saga orchestration, and Temporal's replay-based
debugging. None of those are requirements for periodic provider collection.

## Consequences

- A manual sync starts within one tick interval rather than instantly. This is
  a real, visible UX change and must be stated in the UI, not hidden behind a
  spinner that implies immediate work.
- Slice size becomes a tuning parameter. Too large risks hitting the request
  timeout mid-slice; the checkpoint makes that recoverable but wasteful.
- If step throughput becomes the binding constraint, option 3 (Cloud Tasks) is
  the upgrade path and does not require revisiting the data model.

## Revisit when

- Cloud Run request limits or the scan step count change materially, or
- the platform migrates to AWS for reasons independent of this ADR, or
- multi-service saga orchestration becomes a real requirement.

Until one of those is true, this ADR — not PRD §42.2 — describes how
collection durability is achieved. The PRD should be formally amended or this
divergence explicitly accepted; it must not be left implicit, and no claim of
"§42.2 compliance" should be made while it stands.
