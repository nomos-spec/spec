# NOMOS-SPEC-003: Temporal Validity and Staleness Signalling

**Status:** Active  
**Version:** 1.3.1  
**Extends:** NOMOS-SPEC-001 v1.0.0, NOMOS-SPEC-002 v1.1.0  
**Published:** 2026-06-24  
**Authors:** SafeHaven LLC / NOMOS Protocol Working Group  
**spec_version string:** `"NOMOS-SPEC-003"`

---

## Abstract

NOMOS-SPEC-001 defines governance rules as static — once sealed, a rule applies
until the artifact is deprecated. This model is correct for policy that is
genuinely timeless, but many institutional rules are not. Compliance deadlines,
promotional windows, and regulatory transition periods are inherently temporal.
Without a first-class mechanism for expressing time-bounded validity, authors
are forced to create and deprecate entire artifacts to handle transitions that
are structurally just date ranges.

This document extends the rule schema with two optional fields — `valid_from`
and `valid_until` — that allow rule authors to declare the precise interval
during which a rule is active. A compliant runtime MUST evaluate temporal
bounds before walking the condition tree, and MUST record skipped rules in the
audit trace with result `"expired"`.

This document also introduces the **staleness signal**: a passive advisory
returned in the execution response envelope when the number of decisions
executed against an artifact since its last triangulation exceeds a
configurable threshold. The signal is informational only — it never changes
the verdict. Consuming applications decide what to do with it.

This document also defines **deterministic replay**: a mechanism by which a
caller can supply an `execution_at` timestamp in the request, causing the
runtime to evaluate temporal bounds as if it were that historical instant.
This closes the regulatory audit requirement: given the same sealed artifact,
the same inputs, and the same `execution_at`, a conformant runtime MUST
produce an identical verdict.

NOMOS-SPEC-001 and NOMOS-SPEC-002 artifacts remain valid under a
NOMOS-SPEC-003 runtime. The new fields are optional and the staleness signal
is absent when the runtime has no triangulation baseline.

---

## Table of Contents

1. Conventions and Terminology
2. Motivation
3. Temporal Validity — Rule Schema Extension
4. Runtime Evaluation Algorithm
5. Audit Trace Extension
6. Staleness Signal
7. Execution Response Extension
8. Deterministic Replay
9. Conformance
10. Security Considerations
11. Examples

---

## 1. Conventions and Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**,
**RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be
interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

All examples use JSON. All other conventions from NOMOS-SPEC-001 §1 apply.

Additional terms defined in this document:

**Temporal bounds** — The `valid_from` and `valid_until` fields on a rule,
expressing the half-open interval `[valid_from, valid_until)` during which the
rule is considered active.

**Execution instant** — The single `Date` value captured at the start of a
runtime execution call. All temporal bounds in a given execution MUST be
evaluated against the same instant.

**Expired rule** — A rule whose temporal bounds exclude the execution instant.
An expired rule is skipped; it does not contribute to the verdict.

**Triangulation baseline** — The execution count and timestamp recorded when an
artifact was last triangulated (validated against real decision data).

**Staleness delta** — The number of executions against an artifact since the
triangulation baseline was recorded.

**Staleness threshold** — The maximum acceptable staleness delta. When exceeded,
the runtime includes a staleness advisory in the response. Defaults to 500.

---

## 2. Motivation

### 2.1 Temporal validity

Regulatory thresholds change. Promotional approval criteria expire. Seasonal
escalation rules apply only during specific windows. Under NOMOS-SPEC-001,
handling these transitions requires sealing a new artifact for each period —
a full extraction, triangulation, and sealing cycle for what is structurally
just a date range change.

`valid_from` and `valid_until` allow a single artifact to express a complete
temporal policy: the rule set that applies before a transition, the rule set
that applies after, and the exact instant of cutover — all sealed together,
all auditable.

### 2.2 Staleness signal

An artifact sealed from a behavioral baseline reflects the reality of the
organisation at a point in time. As decisions accumulate, that baseline ages.
Drift between sealed behavior and current behavior may grow without triggering
any observable error — the runtime continues executing correctly against the
sealed rules.

The staleness signal makes this invisible drift visible. It does not make
decisions — it reports a fact: this artifact has executed N decisions since
it was last validated against real data. The threshold at which the signal
fires is configurable. The consuming application decides whether to
re-triangulate, escalate, or continue.

---

## 3. Temporal Validity — Rule Schema Extension

### 3.1 New fields

Two optional fields are added to the Rule object defined in NOMOS-SPEC-001 §4.5:

| Field | Type | Required | Description |
|---|---|---|---|
| `valid_from` | string (ISO 8601 UTC) | No | Rule is inactive before this instant |
| `valid_until` | string (ISO 8601 UTC) | No | Rule is inactive at and after this instant |

Both fields, when present, MUST be ISO 8601 UTC datetime strings
(e.g. `"2026-01-01T00:00:00Z"`).

### 3.2 Interval semantics

The temporal validity interval is **half-open**: `[valid_from, valid_until)`.

- If `valid_from` is present and the execution instant is strictly before
  `valid_from`, the rule MUST be skipped.
- If `valid_until` is present and the execution instant is at or after
  `valid_until`, the rule MUST be skipped.
- If neither field is present, the rule is unconditionally active (existing
  behavior).
- If only `valid_from` is present, the rule activates at that instant and
  never expires.
- If only `valid_until` is present, the rule is active from the beginning
  of time until that instant.

### 3.3 Seal integrity

`valid_from` and `valid_until` are part of the rule object and therefore
covered by the artifact seal. They MUST NOT be modified after sealing. Any
modification invalidates the seal hash.

---

## 4. Runtime Evaluation Algorithm

A NOMOS-SPEC-003 compliant runtime MUST extend the rule evaluation loop
defined in NOMOS-SPEC-001 §6 as follows:

1. Capture the **execution instant** as a single `Date` value at the start
   of the execution call. This value MUST NOT change during the evaluation
   of any rule in this execution.

2. For each rule, before evaluating the `condition` tree:

   ```
   if valid_from is present AND execution_instant < valid_from:
     record trace entry: { rule_id, result: "expired" }
     continue to next rule

   if valid_until is present AND execution_instant >= valid_until:
     record trace entry: { rule_id, result: "expired" }
     continue to next rule
   ```

3. Rules that pass temporal bounds proceed to condition evaluation per
   NOMOS-SPEC-001 §6.

The execution instant MUST be the same value used for the `ts` field in the
execution response.

---

## 5. Audit Trace Extension

### 5.1 Decision trace result values

The `result` field in a decision trace entry (NOMOS-SPEC-001 §6.3) is extended
with one new value:

| Value | Meaning |
|---|---|
| `"matched"` | Rule condition evaluated to true (existing) |
| `"not_matched"` | Rule condition evaluated to false (existing) |
| `"error"` | Condition evaluation produced an error (existing) |
| `"expired"` | Rule was skipped due to temporal bounds |

### 5.2 Audit requirement

A compliant runtime MUST record a trace entry with `result: "expired"` for
every rule that is skipped due to temporal bounds. This ensures the audit
trail reflects the complete rule set considered at execution time, including
rules that were present but outside their active window.

A verifier auditing past decisions MUST be able to determine, from the audit
trace alone, which rules were active and which were expired at the moment of
each decision.

---

## 6. Staleness Signal

### 6.1 Triangulation baseline

When an artifact is sealed following a triangulation run (validation against
real decision data), the compliant runtime SHOULD record a **triangulation
baseline record** with the following normative fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `artifact_id` | string | REQUIRED | The `artifact_id` of the sealed artifact |
| `artifact_version` | string | REQUIRED | The `version` of the sealed artifact at triangulation time |
| `triangulated_at` | string (ISO 8601 UTC) | REQUIRED | Timestamp of the triangulation run |
| `decision_volume_at_triangulation` | integer | REQUIRED | Count of executions logged against this artifact at triangulation time |

The baseline record is stored by the runtime, not embedded in the artifact.
It is keyed by `artifact_id + artifact_version` — a new baseline record MUST
be created when a new artifact version is sealed; it MUST NOT overwrite the
baseline of a prior version.

A baseline record MUST NOT be modified after it is written. If the runtime
needs to record a re-triangulation, it creates a new baseline record for the
new artifact version produced by the re-sealing.

Forked artifacts (artifacts created by copying rules from an existing artifact)
do not inherit the source artifact's baseline. A forked artifact has no
baseline until it is sealed following its own triangulation run.

### 6.2 Staleness delta computation

After each execution, the runtime SHOULD compute:

```
delta = current_execution_count - decision_volume_at_triangulation
```

where `current_execution_count` is the total number of executions logged
against this `artifact_id + artifact_version` pair since it was first sealed.

**Approximate counting is acceptable.** The staleness signal is advisory;
exact global consistency of the execution counter is not required. In
distributed or multi-region deployments, counters may drift. A delta that
is occasionally imprecise produces false positives (advisory fires
unnecessarily) or false negatives (advisory fires late) — neither affects
the verdict. Implementations MUST NOT block or delay execution responses
to achieve a strongly consistent count.

### 6.3 Staleness threshold

The default staleness threshold is **500**. Runtimes MAY make this
configurable per artifact or per deployment.

### 6.4 Advisory emission

If `delta >= staleness_threshold` AND a triangulation baseline exists for
this artifact, the runtime MUST include a `staleness_advisory` object in
the execution response (§7).

The advisory is **informational only**. It MUST NOT affect the verdict,
the audit hash, or any other field of the execution response. The consuming
application is responsible for deciding whether to act on the advisory.

### 6.5 Absence of baseline

If no triangulation baseline exists for an artifact (e.g. the artifact was
sealed in Quick Mode without behavioral data), the staleness signal MUST NOT
be emitted. The absence of the `staleness_advisory` field is not an error.

---

## 7. Execution Response Extension

A NOMOS-SPEC-003 compliant runtime extends the execution response defined in
NOMOS-SPEC-001 §7 with one optional field:

### 7.1 `staleness_advisory`

| Field | Type | Required | Description |
|---|---|---|---|
| `staleness_advisory` | object | No | Present when staleness delta exceeds threshold |

When present, `staleness_advisory` MUST contain:

| Field | Type | Description |
|---|---|---|
| `triangulated_at` | string (ISO 8601 UTC) | Timestamp of the last triangulation run |
| `decisions_since_triangulation` | integer | Staleness delta at time of this execution |
| `threshold` | integer | The threshold that was exceeded |
| `recommendation` | string | Always `"consider_retriangulation"` |

Example:

```json
{
  "verdict": "proceed",
  "allowed": true,
  "artifact_id": "pub_lending_v1",
  "ts": "2026-06-24T14:00:00Z",
  "audit_hash": "a3f9c1...",
  "contradictions": 0,
  "staleness_advisory": {
    "triangulated_at": "2026-05-30T09:41:00Z",
    "decisions_since_triangulation": 503,
    "threshold": 500,
    "recommendation": "consider_retriangulation"
  }
}
```

---

## 8. Deterministic Replay

### 8.1 Motivation

Regulatory and compliance contexts require the ability to reconstruct exactly
what verdict would have been produced at any past instant — for incident
investigation, audit, and backtesting. NOMOS-SPEC-003 runtimes MUST support
this via the `execution_at` request field.

### 8.2 `execution_at` field

An optional `execution_at` field MAY be supplied in the execution request
alongside `inputs` and other required fields.

| Field | Type | Required | Description |
|---|---|---|---|
| `execution_at` | string (ISO 8601 UTC) | No | The instant to use for temporal bound evaluation. MUST be ≤ the server's current clock. Future timestamps MUST be rejected. |

### 8.3 Runtime behaviour

A compliant runtime MUST:

1. Parse `execution_at` as an ISO 8601 UTC datetime. If parsing fails,
   return an error with code `INVALID_EXECUTION_AT` (HTTP 422).

2. If `execution_at` is strictly after the server clock at the time of
   the request, return `INVALID_EXECUTION_AT` (HTTP 422). Future replay
   is not permitted.

3. Set `executionNow = execution_at`. Use this value for all temporal
   bound checks per §4. The same value MUST be used for the `ts` field
   in the response.

4. Persist `execution_at` to the audit record. A verifier MUST be able
   to confirm, from the audit trail alone, which instant was used for
   temporal evaluation.

5. Include `replay: true` in the response envelope when `execution_at`
   was supplied, so consumers can distinguish replay responses from
   live executions.

### 8.4 Determinism guarantee

Given the same sealed artifact, the same `inputs`, and the same
`execution_at`, a conformant runtime MUST produce an identical `verdict`
on every invocation. Implementations MUST NOT introduce non-deterministic
state (random seeds, external calls that may differ) into the rule
evaluation path during replay.

### 8.5 Replay audit semantics

Replay executions SHOULD be written to the audit trail with `replay: true`.
They SHOULD NOT increment quota counters, staleness deltas, or drift metrics
— they are observations of past state, not new governance decisions.

### 8.6 Example

```json
// Request — replay at a historical instant
POST /api/v1/verify-decision
{
  "artifact_id":  "art_7f3c9a...",
  "decision":     "loan_application_review",
  "inputs":       { "amount": 45000, "credit_score": 730 },
  "execution_at": "2026-01-01T00:00:00Z"
}

// Response
{
  "allowed":        false,
  "outcome":        "escalated",
  "ts":             "2026-01-01T00:00:00Z",
  "replay":         true,
  "execution_at":   "2026-01-01T00:00:00Z",
  "expired_rules":  ["updated_threshold"],
  "audit_hash":     "c9d6e3f0a7b4c1d8..."
}
```

At `2026-01-01T00:00:00Z`, `updated_threshold` (with `valid_from:
"2026-01-01T00:00:00Z"`) is active, but `legacy_threshold` (with
`valid_until: "2026-01-01T00:00:00Z"`) is expired at and after that
instant. The verdict reflects the rule set in force at that exact moment.

---

## 9. Conformance

A runtime claims NOMOS-SPEC-003 conformance if and only if it satisfies all
of the following:

1. **Temporal evaluation**: Before evaluating any rule's condition, the runtime
   checks `valid_from` and `valid_until` against the execution instant per §4.

2. **Single instant**: The execution instant is captured once per execution
   call and used for all temporal bound checks in that call.

3. **Expired trace entries**: Every rule skipped due to temporal bounds
   produces a trace entry with `result: "expired"` per §5.

4. **Non-blocking advisory**: The staleness advisory, when emitted, does not
   affect the verdict or any other required response field.

5. **Baseline recording**: When an artifact is sealed following triangulation,
   the runtime records the triangulation baseline per §6.1.

6. **Backward compatibility**: NOMOS-SPEC-001 and NOMOS-SPEC-002 artifacts
   without `valid_from`/`valid_until` fields execute identically to their
   behavior under prior spec versions.

7. **Deterministic replay**: When `execution_at` is supplied, the runtime
   validates, applies, and records it per §8. Future timestamps are rejected.
   The determinism guarantee in §8.4 MUST hold.

### 9.1 Conformance levels

| Level | Requirements |
|---|---|
| **Temporal-only** | §3, §4, §5 — temporal bounds; staleness and replay not required |
| **Full** | §3, §4, §5, §6, §7, §8 — temporal bounds + staleness signal + deterministic replay |

---

## 10. Security Considerations

### 10.1 Clock integrity

Temporal bounds depend on the runtime clock. A compromised or manipulated
clock can cause active rules to appear expired or expired rules to appear
active. Runtimes operating in high-integrity environments SHOULD use a
trusted time source (NTP with authentication, HSM clock).

The execution instant recorded in the audit trace and in the `ts` field of
the response provides a verifiable record of the clock value used for temporal
evaluation. Verifiers auditing past decisions can cross-reference the `ts`
field against external time sources.

**Distributed and microservice deployments:** In architectures where the
calling service and the policy runtime are separate processes, clock skew
between hosts can cause the same rule to appear active on one node and expired
on another. The correct mitigation is not to fix clocks (clock drift is
unavoidable) but to use the `execution_at` field (§8): the initiating service
captures a single timestamp from its own clock and propagates it to the policy
runtime as `execution_at`. All temporal bound checks are then performed against
the caller-supplied instant, eliminating inter-service skew. Implementations
that operate as policy sidecars or remote services SHOULD document this pattern
and encourage callers to supply `execution_at` explicitly.

### 10.2 Staleness advisory integrity

The `staleness_advisory` is computed from the runtime's own execution log and
is not part of the sealed artifact. It cannot be forged by an artifact author.
It can be omitted by a non-compliant runtime. Consumers relying on the advisory
for governance assurance SHOULD verify that the runtime is NOMOS-SPEC-003
conformant before treating absence of the advisory as evidence of freshness.

### 10.3 Replay integrity

The `execution_at` field is caller-supplied and not part of the sealed
artifact. A malicious caller could supply any past timestamp to observe
how the artifact would have behaved at a different moment — this is by
design, since historical verdicts are not secret. However:

- Runtimes MUST reject future timestamps to prevent speculation about
  rules not yet active.
- Replay executions SHOULD be marked in the audit trail so auditors can
  distinguish live decisions from retrospective reconstructions.
- The determinism guarantee means the verdict for a given
  (artifact, inputs, execution_at) triple is reproducible by anyone
  with the artifact and inputs — treat the artifact as a public document
  if replay transparency is a concern.

---

## 11. Examples

### 11.1 Temporal rule — regulatory transition

```json
{
  "id": "legacy_threshold",
  "text": "Approve if amount <= 50000 (pre-2026 regulatory threshold)",
  "condition": { "op": "lte", "field": "amount", "value": 50000 },
  "action": "ALLOW",
  "priority": 10,
  "source": "policy",
  "valid_until": "2026-01-01T00:00:00Z"
}
```

```json
{
  "id": "updated_threshold",
  "text": "Approve if amount <= 35000 (2026 regulatory threshold)",
  "condition": { "op": "lte", "field": "amount", "value": 35000 },
  "action": "ALLOW",
  "priority": 10,
  "source": "policy",
  "valid_from": "2026-01-01T00:00:00Z"
}
```

Both rules are sealed in the same artifact. Before 2026-01-01, only
`legacy_threshold` is active. At and after 2026-01-01, only `updated_threshold`
is active. The cutover is atomic and auditable.

### 11.2 Audit trace showing expired rule

```json
{
  "decisions": [
    { "decision_id": "legacy_threshold", "result": "expired" },
    { "decision_id": "updated_threshold", "result": "matched", "outcome": "allow" }
  ]
}
```

The audit trace records both rules — the one that was skipped and the one
that fired — providing a complete picture of the rule set at the moment of
the decision.

### 11.3 Staleness advisory

```json
{
  "verdict": "proceed",
  "allowed": true,
  "artifact_id": "pub_lending_v1",
  "artifact_version": "1.0.0",
  "confidence": "VALIDATED",
  "request_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
  "ts": "2026-06-24T14:00:00Z",
  "audit_hash": "c9d6e3f0a7b4c1d8e5f2a9b6c3d0e7f4a1b8c5d2e9f6a3b0c7d4e1f8a5b2c9d6",
  "contradictions": 0,
  "staleness_advisory": {
    "triangulated_at": "2026-05-30T09:41:00Z",
    "decisions_since_triangulation": 503,
    "threshold": 500,
    "recommendation": "consider_retriangulation"
  }
}
```
