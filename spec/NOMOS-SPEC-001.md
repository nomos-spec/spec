# NOMOS-SPEC-001: Governance Artifact Protocol

**Status:** Active  
**Version:** 1.1.0  
**Published:** 2026-01-15  
**Updated:** 2026-06-21  
**Authors:** SafeHaven LLC / NOMOS Protocol Working Group  

---

## Abstract

NOMOS-SPEC-001 defines a portable, vendor-neutral format for packaging organisational governance policies as sealed, machine-executable artifacts (`.nomos` files). The specification covers artifact structure, the rule expression language, confidence classification, the cryptographic sealing procedure, the execution model, the audit trail schema, and conformance requirements for compliant runtimes.

The goals are reproducibility (identical inputs produce identical outputs), auditability (every decision is traceable to a sealed rule), and interoperability (any compliant runtime can execute any conformant artifact without access to the original policy documents).

Sealed artifacts may be distributed and verified independently of the producing platform. The official TypeScript SDK (`@nomosprotocol/sdk`) and the NOMOS Exchange provide reference implementations of the distribution and execution layers described in this specification.

---

## Table of Contents

1. Conventions
2. Terminology
3. Artifact Structure
4. Rule Expression Language
5. Confidence Classification
6. Execution Model
7. Audit Trail
8. Sealing Procedure
9. Conformance
10. Security Considerations
11. Error Catalog
12. SDK & Distribution

---

## 1. Conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

All examples use JSON. String values MUST be UTF-8 encoded. All timestamps MUST be ISO 8601 in UTC (`Z` suffix).

---

## 2. Terminology

**Artifact** — A sealed `.nomos` file; the output of the NOMOS compilation step.

**Rule** — A single declarative governance statement: a condition tree + an action.

**Confidence tier** — A classification indicating how the rules were derived and validated. Valid values: `DECLARED`, `VALIDATED`, `CERTIFIED`, `PROVEN`, `SOVEREIGN`.

**Seal** — A cryptographic block appended to a frozen artifact, binding all fields to a specific key and timestamp.

**Runtime** — Any system that loads a `.nomos` artifact and evaluates decisions against its rules.

**Verdict** — The outcome of a single execution: `ALLOW`, `DENY`, or `ESCALATE`.

**Audit hash** — A SHA-256 digest that chains consecutive verdicts for a given artifact into a tamper-evident log.

---

## 3. Artifact Structure

A `.nomos` file is a UTF-8 JSON document. The top-level object MUST contain the following fields:

```json
{
  "artifact_id":   "<string>",
  "version":       "<semver>",
  "spec_version":  "NOMOS-SPEC-001",
  "confidence":    "DECLARED | VALIDATED | CERTIFIED | PROVEN | SOVEREIGN",
  "domain":        { ... },
  "rules":         [ ... ],
  "contradiction_report": { ... },
  "readiness":     { ... },
  "seal":          { ... }
}
```

### 3.1 `artifact_id`

A URL-safe string uniquely identifying this artifact within an organisation. Implementations SHOULD use lowercase ASCII, digits, underscores, and hyphens only. Maximum 128 characters.

### 3.2 `version`

Semantic version (`MAJOR.MINOR.PATCH`). Implementations MUST NOT treat two artifacts with different `version` values as equivalent even if `artifact_id` matches.

**When to increment:**

| Increment | Trigger |
|-----------|---------|
| `MAJOR` | Any change to rule conditions, actions, or `conflict_resolution` that alters the verdict for any previously valid input. Adding a rule that can `DENY` a previously `ALLOW`ed context is a MAJOR change. |
| `MINOR` | Adding rules that can only escalate or allow inputs that previously received the default `ALLOW` verdict (no matching rule). |
| `PATCH` | Metadata-only changes — `domain.tags`, `rule.text`, `rule.metadata` — that do not alter evaluation. |

**In-flight executions:** A runtime MAY serve multiple versions of the same `artifact_id` simultaneously. Callers SHOULD pin to a specific `version` in production. A runtime MUST NOT silently upgrade a pinned request to a newer version.

**Re-sealing:** Any change that affects verdict output REQUIRES a new `version` and a new `seal`. Re-sealing without a version increment is not conformant.

### 3.3 `spec_version`

Fixed string `"NOMOS-SPEC-001"`. A runtime that does not recognise the `spec_version` MUST refuse to execute the artifact and return a `spec_version_unsupported` error.

### 3.4 `domain`

Metadata about the governance domain. All fields are OPTIONAL except `name`.

```json
{
  "name":           "<string>",
  "organization":   "<string>",
  "effective_date": "<ISO 8601 date>",
  "jurisdiction":   "<string>",
  "tags":           ["<string>"]
}
```

### 3.5 `rules`

An ordered array of Rule objects (see §4). The order determines evaluation priority when `conflict_resolution` is `first_match`.

### 3.6 `contradiction_report`

A summary of detected rule conflicts produced during the compilation step.

```json
{
  "contradiction_count": 0,
  "contradictions": [
    {
      "type": "threshold_conflict | role_conflict | ghost_term | rule_collision | layer_divergence",
      "rule_ids": ["<string>"],
      "description": "<string>",
      "severity": "low | medium | high"
    }
  ]
}
```

An artifact with `contradiction_count > 0` MAY still be sealed, but the runtime MUST surface the contradiction count in every verdict response.

### 3.7 `readiness`

ARI (AI Readiness Index) scores produced during compilation. All score fields are floats in [0, 1].

```json
{
  "lis": 0.82,
  "drs": 0.71,
  "res": 0.14,
  "gms": 0.75,
  "ari": 0.73,
  "autonomy_band": "autonomous | bounded | human_governed"
}
```

`autonomy_band` is derived from `ari`: ≥ 0.60 → `autonomous`; ≥ 0.30 → `bounded`; < 0.30 → `human_governed`.

### 3.8 `seal`

See §8 for the sealing procedure.

### 3.9 `data_contract` (optional)

Declares the minimum context fields the artifact requires to evaluate correctly. A runtime MUST check that all `required_fields` are present in the execution request context **before** beginning rule evaluation. If any are missing, the runtime MUST return a `data_contract_violation` error (§11) rather than evaluating with incomplete inputs.

```json
{
  "data_contract": {
    "required_fields": ["credit_score", "amount", "employment_type"],
    "field_types": {
      "credit_score": "number",
      "amount":       "number",
      "employment_type": "string"
    }
  }
}
```

`required_fields` is the normative constraint. `field_types` is OPTIONAL documentation — runtimes SHOULD NOT perform type coercion on incoming context values.

```json
{
  "algorithm": "HMAC-SHA256",
  "ts":        "<ISO 8601 UTC>",
  "hash":      "<hex-encoded SHA-256 of canonical payload>",
  "sig":       "<hex-encoded HMAC-SHA256 of hash>"
}
```

---

## 4. Rule Expression Language

Each element of the `rules` array MUST conform to the following structure:

```json
{
  "id":          "<string>",
  "text":        "<natural language description>",
  "condition":   { ... },
  "action":      "ALLOW | DENY | ESCALATE",
  "priority":    "<integer>",
  "source":      "policy | behavioral | inferred",
  "confidence":  "<float 0–1>",
  "metadata": {
    "section":      "<string>",
    "page":         "<integer>",
    "tags":         ["<string>"],
    "last_modified": "<ISO 8601>"
  }
}
```

### 4.1 Condition AST

Conditions are expressed as a recursive Abstract Syntax Tree. Each node is one of:

**Leaf node** (field comparison):
```json
{ "op": "eq | neq | gt | gte | lt | lte | in | nin | exists | regex",
  "field": "<dot-separated path>",
  "value": "<scalar | array>" }
```

**Branch node** (logical):
```json
{ "op": "and | or | not",
  "left": { ... },
  "right": { ... } }
```

`not` uses `left` only; `right` MUST be omitted.

**Examples:**

```json
{ "op": "and",
  "left":  { "op": "gte", "field": "patron_age", "value": 18 },
  "right": { "op": "eq",  "field": "account_standing", "value": "good" } }
```

```json
{ "op": "in",
  "field": "item_type",
  "value": ["reference", "periodical"] }
```

### 4.2 Supported operators

| Operator | Types | Semantics |
|----------|-------|-----------|
| `eq` | any scalar | strict equality |
| `neq` | any scalar | strict inequality |
| `gt` / `gte` | number, date-string | greater than / greater than or equal |
| `lt` / `lte` | number, date-string | less than / less than or equal |
| `in` | any, array | field value is in the provided array |
| `nin` | any, array | field value is not in the provided array |
| `exists` | — | field is present and non-null |
| `regex` | string | field matches the provided RE2 pattern |
| `and` / `or` | — | logical connectives |
| `not` | — | logical negation |

A runtime MAY support additional operators via extension, but MUST NOT fail on unrecognised operators — it MUST instead return an `ESCALATE` verdict with `reason: "unsupported_operator"`.

### 4.3 Field paths

Field paths use dot notation: `applicant.credit_score`, `loan.amount_usd`. Array indexing is not defined in this spec version.

### 4.4 Conflict resolution modes

The `conflict_resolution` field at the artifact root (OPTIONAL, default `first_match`) governs multi-rule evaluation:

| Mode | Behaviour |
|------|-----------|
| `first_match` | Return the action of the highest-priority matching rule |
| `collect_and_resolve` | Evaluate all rules; resolve conflicts by `DENY > ESCALATE > ALLOW` |
| `highest_priority` | Among all matching rules, apply only the one with the highest `priority` |

---

## 5. Confidence Classification

Confidence tiers are assigned during compilation and sealed into the artifact. They reflect both how rules were derived (policy-only vs. behavioral triangulation) and whether the artifact meets quantitative ARI thresholds for distribution on the NOMOS Exchange.

### 5.1 DECLARED

Rules derived exclusively from uploaded policy documents. No behavioral data was used.

- `drs` in `readiness` MUST be `null`.
- The artifact carries reduced statistical confidence.
- Suitable for new deployments where historical decision data does not yet exist.
- Not eligible for publication to the NOMOS Exchange.

### 5.2 VALIDATED

Rules derived from policy documents and confirmed against behavioral decision logs. Statistical triangulation was performed but full gap analysis was not required or was inconclusive.

- `drs` in `readiness` MUST be a float in [0, 1].
- The artifact has passed contradiction detection.
- Suitable for production deployments where behavioral data is available but the dataset does not yet meet the threshold for `CERTIFIED`.

### 5.3 CERTIFIED

Rules triangulated against behavioral decision logs with full gap analysis. Statistical validation passed.

- `drs` in `readiness` MUST be a float in [0, 1].
- The artifact has passed contradiction detection and gap analysis.
- Suitable for production deployments requiring regulator-grade auditability.

### 5.4 PROVEN

`CERTIFIED` artifacts that additionally meet a minimum ARI threshold.

- All `CERTIFIED` requirements apply.
- `readiness.ari` MUST be ≥ 0.60.
- `readiness.autonomy_band` MUST be `autonomous`.
- Eligible for publication to the NOMOS Exchange.
- Distribution platforms MUST enforce the ARI gate before accepting a `PROVEN` artifact and MUST reject with a `confidence_gate_failed` error if the condition is not met.

### 5.5 SOVEREIGN

The highest confidence tier. Reserved for artifacts with demonstrated statistical reliability above the autonomous threshold.

- All `PROVEN` requirements apply.
- `readiness.ari` MUST be ≥ 0.75.
- Eligible for publication to the NOMOS Exchange with priority placement.
- Distribution platforms MUST require administrator review before activating a `SOVEREIGN` artifact listing.

**Summary table:**

| Tier | Behavioral data | ARI gate | Exchange eligible |
|---|---|---|---|
| `DECLARED` | No | None | No |
| `VALIDATED` | Yes | None | No |
| `CERTIFIED` | Yes (full) | None | No |
| `PROVEN` | Yes (full) | ≥ 0.60 | Yes |
| `SOVEREIGN` | Yes (full) | ≥ 0.75 | Yes (admin review) |

A runtime MAY surface the confidence tier in its API response. A runtime MUST NOT change the `confidence` field of a sealed artifact without re-sealing.

---

## 6. Execution Model

### 6.1 Request

Submit a decision payload to a conformant runtime via `POST /api/v1/verify-decision`.

```json
{
  "artifact_id":  "<string>",
  "decision":     "<string, ≤ 200 chars>",
  "inputs":       { "<field>": "<value>", ... },
  "domain_id":    "<integer | omit if not domain-scoped>",
  "caller": {
    "agent_id":        "<string | omit>",
    "correlation_id":  "<string, ≤ 256 chars | omit>",
    "user_id":         "<string | omit>"
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `artifact_id` | REQUIRED | Identifier of a sealed artifact in `active` or `superseded` state. A runtime MUST reject `draft` or `deprecated` artifacts with HTTP 422. |
| `decision` | REQUIRED | Human-readable label for the decision point. Recorded in the audit trail and used for escalation routing. |
| `inputs` | REQUIRED | Key/value map of decision factors. Types MUST match the data contract declared in the artifact (§3.9). Unknown keys are recorded in the audit trail but do not affect rule evaluation. |
| `domain_id` | OPTIONAL | Scopes the execution to a specific domain. The runtime verifies the caller has access. |
| `caller.agent_id` | OPTIONAL | Identity of the calling agent. SHOULD be stable across calls from the same agent instance. Recorded verbatim in the audit trail. |
| `caller.correlation_id` | OPTIONAL | Caller-assigned trace identifier. Propagated to audit records and LangSmith traces. Serves as the idempotency key (see §6.7). |
| `caller.user_id` | OPTIONAL | End-user identifier for downstream accountability. Recorded in the audit trail. |

A runtime MUST NOT include credential material (passwords, tokens, private keys) from `inputs` in plaintext audit records. Fields declared in the artifact's redaction policy MUST be hashed or masked before storage (see §3.9).

### 6.2 Authentication

A conformant runtime MUST support two authentication methods, evaluated in this order:

1. **API key** — Supply `X-Nomos-Api-Key: <key>` in the request header. The key is validated against a stored hash; the plaintext MUST NOT be stored. Keys are scoped to a domain and a subscription tier.
2. **Session** — For callers with an active session, the runtime MAY accept the session credential. The session identity MUST have domain access.

Unauthenticated requests MUST be rejected with HTTP 401.

### 6.3 Version negotiation

A runtime MUST support two response formats selected by the `Accept-Nomos-Version` request header:

| Header value | Response format | Response header |
|---|---|---|
| `1.0.0` | Spec-compliant `ExecutionReceipt` (§6.5) | `Content-Nomos-Version: 1.0.0` |
| `1.0` or omitted | Legacy verdict object (§6.6) | `Content-Nomos-Version: 1.0` |

New integrations SHOULD request `Accept-Nomos-Version: 1.0.0`. The legacy format is stable but will not receive new fields.

### 6.4 Evaluation pipeline

1. **Scope validation** — confirm `artifact_id` resolves to a known sealed artifact in an executable state.
2. **Seal verification** — verify the artifact's HMAC-SHA-256 seal (§8.1). A runtime MUST NOT evaluate rules against an artifact with a broken seal.
3. **Data contract validation** — check that all `required_fields` from the artifact's data contract (§3.9) are present in `inputs`. Record `missing_required` for the response.
4. **Confidence check** — compute `inputs.confidence` (§6.8). If it falls below `min_confidence_for_autonomy`, apply the `on_low_confidence` policy before rule evaluation.
5. **Constraint enforcement** — evaluate speed, quality, and sovereignty dials from the artifact's calibration profile.
6. **Rule evaluation** — iterate rules in priority order (or per `conflict_resolution` mode). Evaluate each condition against `inputs`.
7. **Conflict resolution** — apply the artifact's `conflict_resolution` mode if multiple rules match (`first_match`, `highest_priority`, or `collect_and_resolve`).
8. **Action execution** — execute outcome actions with idempotency tracking keyed on `caller.correlation_id`.
9. **Verdict emission** — return an `ExecutionReceipt` (§6.5) or legacy verdict (§6.6).
10. **Audit append** — append the verdict to the artifact's hash-chained audit trail (§7).

### 6.5 Spec-compliant response (v1.0.0)

When `Accept-Nomos-Version: 1.0.0` is requested, the runtime returns an `ExecutionReceipt`:

```json
{
  "receipt_version": "1.0.0",

  "artifact": {
    "artifact_id":        "<string>",
    "artifact_version":   "<semver>",
    "seal_hash":          "<hex-encoded HMAC-SHA-256 | null>",
    "verification_tier":  "DECLARED | CERTIFIED | null"
  },

  "execution": {
    "execution_id":  "<uuid>",
    "started_at":    "<ISO 8601 UTC>",
    "ended_at":      "<ISO 8601 UTC>",
    "status":        "allowed | blocked | escalated | deferred | error",
    "final_reason":  "<string — matched rule ID and condition>",
    "latency_ms":    "<integer>"
  },

  "inputs": {
    "provided":          { "<field>": "<value>", ... },
    "missing_required":  ["<field>", ...],
    "confidence":        "<float 0–1>",
    "provenance":        { "<field>": "<source>", ... }
  },

  "trace": {
    "constraints": [
      { "constraint_id": "<string>", "result": "passed | violated", "message": "<string | omit>" }
    ],
    "decisions": [
      { "decision_id": "<rule_id>", "result": "matched | not_matched | error", "outcome": "allow | block | escalate | omit", "error": "<string | omit>" }
    ],
    "actions": [
      { "action": "<string>", "result": "success | failure | skipped", "idempotency_key": "<string>", "error": "<string | omit>" }
    ],
    "escalation": {
      "role_required":  "<string>",
      "trigger_id":     "<rule_id>",
      "payload_fields": ["<field>", ...],
      "sla_minutes":    "<integer | null>"
    }
  },

  "audit": {
    "event_ids": ["<uuid>", ...],
    "redaction": {
      "strategy":        "hash | mask | remove",
      "fields_redacted": ["<field>", ...]
    }
  },

  "errors": [
    { "code": "<string>", "message": "<string>", "location": "<string | omit>" }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `receipt_version` | `"1.0.0"` | Literal. MUST be `"1.0.0"` for receipts conforming to this specification. |
| `artifact.seal_hash` | `string \| null` | The artifact's HMAC-SHA-256 seal. Null only when the artifact record has no seal — a condition that MUST NOT arise in production. |
| `execution.execution_id` | UUID | Assigned by the runtime. Stable reference for audit queries. |
| `execution.status` | enum | See §6.6 for the full status table. |
| `execution.final_reason` | string | Human-readable explanation of the verdict. SHOULD include the matched rule ID and the condition that determined the outcome. |
| `execution.latency_ms` | integer | Wall-clock evaluation time in milliseconds. Excludes network round-trip. |
| `inputs.confidence` | float | 0–1. Reflects data contract validation; degrades for missing or mistyped fields (see §6.8). |
| `inputs.missing_required` | string[] | Fields declared `REQUIRED` in the data contract that were absent from the payload. Non-empty implies `confidence < 1.0`. |
| `inputs.provenance` | object | Maps field names to their declared source. Populated from the data contract's `provenance` entries. |
| `trace.escalation` | object \| null | Present when `status` is `escalated`. Identifies the required reviewer role, trigger rule, and SLA in minutes. |
| `audit.event_ids` | string[] | IDs of audit trail entries written for this execution. Retrieve the full hash-chained record via `GET /api/audit/:id`. |
| `audit.redaction.strategy` | enum | How sensitive fields were handled before storage. Declared in the artifact's data contract (§3.9). |
| `errors` | array | Non-fatal evaluation errors. An empty array is the normal case. Errors here do not prevent a verdict but degrade `inputs.confidence`. |

### 6.6 Status values

| Status | Meaning |
|--------|---------|
| `allowed` | All applicable rules evaluated; at least one `allow` rule matched and no `block` rule matched. |
| `blocked` | A `block` rule matched. The decision MUST NOT proceed. |
| `escalated` | No rule produced a definitive outcome, OR a rule explicitly routed to a human reviewer. The `trace.escalation` object identifies the required role and SLA. |
| `deferred` | Data confidence fell below `min_confidence_for_autonomy` and `on_low_confidence` is `"defer"`. A human decision is required within the declared SLA. |
| `error` | The runtime encountered a fatal evaluation error. The `errors` array contains details. A runtime MUST NOT return `allowed` when `errors` is non-empty and any error affected a `block` or `escalate` rule. |

### 6.7 Legacy response (v1.0)

When `Accept-Nomos-Version` is omitted or set to `1.0`, the runtime returns:

```json
{
  "verdict":          "approved | escalated | blocked",
  "rule_applied":     "<condition expression>",
  "rule_id":          "<string | null>",
  "rule_reference":   "<string>",
  "rule_description": "<string>",
  "confidence":       "<float 0–1>",
  "latency_ms":       "<integer>",
  "audit_hash":       "sha256:<hex>",
  "evaluated_at":     "<ISO 8601 UTC>"
}
```

`audit_hash` in the legacy format is a content hash of the verdict record (SHA-256 of `{ artifact_id, decision, inputs, verdict, ts }`). It is suitable for spot-checking response integrity but does not constitute a full audit chain. Use the spec-compliant `audit.event_ids` field and `GET /api/audit/:id` for a verifiable, hash-chained trail.

### 6.8 Confidence degradation

`inputs.confidence` reflects how fully the runtime could trust the decision payload. Three landmark values are defined:

| Value | Condition |
|-------|-----------|
| `0.99` | All required fields present, correctly typed, within declared ranges, and all field-level confidence thresholds satisfied. |
| `0.92` | One field is borderline — within 10% of a numeric threshold or near a categorical boundary. |
| `0.85` | Multiple borderline fields. Degrades further for each additional borderline condition. |

When `inputs.confidence` falls below the artifact's `min_confidence_for_autonomy` threshold, the runtime MUST apply the `on_low_confidence` policy declared in the data contract:

- `block` → return `status: blocked`
- `escalate` → return `status: escalated`
- `defer` → return `status: deferred` and write a pending decision record

A runtime MUST NOT return `status: allowed` when confidence is below the declared threshold.

If a required field is absent from `inputs` and its condition cannot be evaluated:

- A runtime MUST NOT default missing numeric fields to `0` or string fields to `""`.
- If `autonomy_band` is `human_governed` → status is `escalated`.
- Otherwise → status is `escalated` with `final_reason: "missing_context_field"`.

### 6.9 Idempotency

`caller.correlation_id` is the idempotency key for an execution. If a runtime receives a request with a `correlation_id` it has already processed within the deduplication window (RECOMMENDED: 5 minutes), it MUST return the original cached receipt without creating a new audit trail entry.

The cached response MUST include a `"cached": true` field at the top level and the original `execution.execution_id`. The audit trail entry count MUST NOT increment for a cache hit.

A runtime MUST NOT use caller IP address or payload hash as the primary deduplication mechanism. If `correlation_id` is omitted, the runtime SHOULD generate one and include it in the response — the execution is treated as non-idempotent.

### 6.10 Quota and rate limits

A conformant runtime MUST return the following headers on every execution response:

| Header | Description |
|--------|-------------|
| `X-Verifications-Used` | Verifications consumed in the current billing period. |
| `X-Verifications-Limit` | Monthly limit for the account's subscription tier. `"unlimited"` for uncapped tiers. |
| `X-Overage` | Present and set to `"true"` when the account has exceeded its monthly limit. |
| `X-Overage-Count` | Calls beyond the monthly limit in the current billing period. |

When the free tier limit is reached the runtime MUST return HTTP 429 with `code: "QUOTA_EXCEEDED"`, a `reset_date` field (ISO 8601), and an `upgrade_url`.

---

## 7. Audit Trail

### 7.1 Entry schema

Every execution appends one entry to the artifact's immutable audit trail:

```json
{
  "entry_id":     "<uuid>",
  "artifact_id":  "<string>",
  "version":      "<semver>",
  "ts":           "<ISO 8601 UTC>",
  "request_id":   "<uuid>",
  "verdict":      "ALLOW | DENY | ESCALATE",
  "matched_rules": ["<rule_id>"],
  "context_hash": "<sha256 of serialised context>",
  "prev_hash":    "<hex | null for first entry>",
  "entry_hash":   "<sha256 of this entry minus entry_hash>",
  "actor":        "<api_key_id | session_user_id>"
}
```

### 7.2 Hash chain

`entry_hash` is computed as:

```
SHA-256( entry_id || artifact_id || ts || verdict || prev_hash )
```

where `||` denotes concatenation of UTF-8 byte representations and `prev_hash` is the `entry_hash` of the immediately preceding entry for the same `artifact_id`, or the all-zeros 64-character hex string for the first entry.

A verifier MUST walk the chain from genesis to tip and confirm each `entry_hash` recomputes correctly. Any gap or hash mismatch MUST be reported as chain corruption.

---

## 8. Sealing Procedure

Sealing is a one-way operation. Once a `.nomos` artifact is sealed, its payload MUST NOT be modified. Any modification invalidates the seal.

### Step 1: Assemble payload

Construct the artifact JSON object with all fields EXCEPT `seal`. The object MUST include `artifact_id`, `version`, `spec_version`, `confidence`, `domain`, `rules`, `contradiction_report`, and `readiness`.

### Step 2: Canonicalize

Serialize the payload using [RFC 8785 JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785):

- Keys sorted lexicographically (Unicode code point order)
- No insignificant whitespace
- Numbers in IEEE 754 double-precision canonical form
- Strings escaped per RFC 8259

### Step 3: Compute payload hash

```
hash = SHA-256( canonical_bytes )
```

Encode as lowercase hex (64 characters).

### Step 4: Compute signature

```
sig = HMAC-SHA256( key=SEAL_KEY, msg=hash )
```

`SEAL_KEY` is a 256-bit secret held by the sealing authority. Encode `sig` as lowercase hex (64 characters).

### Step 5: Embed seal block

Append the `seal` field to the artifact object:

```json
"seal": {
  "algorithm": "HMAC-SHA256",
  "ts":        "<ISO 8601 UTC at time of sealing>",
  "hash":      "<hex hash from step 3>",
  "sig":       "<hex sig from step 4>"
}
```

The artifact is now sealed and MUST be treated as immutable.

### 8.1 Verification

To verify a sealed artifact:

1. Extract and save the `seal` block.
2. Remove the `seal` field from the object.
3. Re-canonicalize (Step 2).
4. Recompute `SHA-256` (Step 3).
5. Confirm `hash` in the seal matches the recomputed value.
6. Recompute `HMAC-SHA256(SEAL_KEY, hash)`.
7. Confirm `sig` in the seal matches the recomputed HMAC (constant-time comparison).

Failure at Step 5 indicates the payload was modified after sealing. Failure at Step 7 indicates the artifact was sealed with a different key or the signature was forged.

### 8.2 Key rotation

`SEAL_KEY` MUST NOT be rotated after artifacts are in production use. Rotation invalidates the seal of every previously issued artifact. If rotation is unavoidable, all affected artifacts MUST be re-issued with new `version` values and re-sealed under the new key.

---

## 9. Conformance

### 9.1 Compliant runtime

A runtime is **conformant** if it:

1. Refuses to execute an artifact whose `spec_version` it does not recognise.
2. Refuses to execute an artifact whose seal does not verify (§8.1), unless operating in an explicitly flagged `insecure_no_verify` mode for testing.
3. Evaluates all rule operators defined in §4.2.
4. Returns `ESCALATE` for unrecognised operators rather than failing silently.
5. Appends a hash-chained audit entry (§7) for every execution.
6. Surfaces `contradictions` count in every verdict response.

### 9.2 Compliant artifact producer

A producer is **conformant** if it:

1. Generates artifacts that validate against `schema/artifact.schema.json`.
2. Seals artifacts using the procedure in §8.
3. Assigns `confidence` per the following rules (in order of precedence):
   - `SOVEREIGN`: behavioral data used, full gap analysis passed, ARI ≥ 0.75.
   - `PROVEN`: behavioral data used, full gap analysis passed, ARI ≥ 0.60.
   - `CERTIFIED`: behavioral data used, full gap analysis passed, ARI < 0.60.
   - `VALIDATED`: behavioral data used, contradiction detection passed, gap analysis not completed or inconclusive.
   - `DECLARED`: no behavioral data used.
4. Populates `contradiction_report` with any detected conflicts before sealing.
5. Does NOT assign `PROVEN` or `SOVEREIGN` if ARI conditions are not met, and MUST produce a producer error rather than silently downgrading.
6. Does NOT publish a `DECLARED` or `VALIDATED` artifact to any distribution platform that enforces the Exchange eligibility gate (§5.4–5.5).

---

## 10. Security Considerations

**Seal key protection** — The `SEAL_KEY` is the root of trust for all artifacts. It MUST be stored in a secrets manager and never embedded in application code or version control.

**Replay attacks** — The `request_id` in an execution request SHOULD be a UUIDv4. Runtimes SHOULD reject duplicate `request_id` values within a configurable window (recommended: 5 minutes).

**Context injection** — Runtimes MUST NOT evaluate user-supplied strings as code. Condition evaluation MUST be performed against a static rule tree only.

**Audit trail integrity** — The hash-chain audit trail is append-only. Runtimes MUST NOT expose a deletion endpoint for audit entries. Backup and replication of the audit store is REQUIRED for production deployments.

**Confidence tier downgrade** — Altering the `confidence` field without re-sealing constitutes misrepresentation of the artifact's provenance. Runtimes MUST preserve the `confidence` field verbatim from the sealed artifact. Valid values are `DECLARED`, `VALIDATED`, `CERTIFIED`, `PROVEN`, and `SOVEREIGN`. Any other value MUST be rejected with `confidence_tier_invalid`.

---

## 11. Error Catalog

All errors produced by a conformant runtime MUST use the machine-readable codes listed below. HTTP status codes apply to REST transport bindings; non-HTTP runtimes SHOULD map these to an equivalent error channel.

| Code | HTTP | Origin | Trigger | Recovery |
|------|------|--------|---------|----------|
| `spec_version_unsupported` | 400 | §3.3 | `spec_version` is not recognised by this runtime | Upgrade the runtime or use a supported spec version |
| `seal_verification_failed` | 400 | §8.1 | Payload hash or HMAC does not match the `seal` block | Artifact may be tampered; do not execute; re-seal from source |
| `artifact_not_found` | 404 | §6.4 | `artifact_id` not in registry or not in an executable state | Confirm the artifact has been sealed and registered |
| `data_contract_violation` | 422 | §3.9 | One or more `required_fields` absent from execution context | Add the missing fields before retrying |
| `confidence_tier_invalid` | 400 | §5 | `confidence` value is not one of `DECLARED`, `VALIDATED`, `CERTIFIED`, `PROVEN`, `SOVEREIGN` | Fix the producer; re-seal with a valid confidence value |
| `confidence_gate_failed` | 422 | §5.4–5.5 | Artifact claims `PROVEN` or `SOVEREIGN` but ARI score does not meet the required threshold | Re-compile with sufficient behavioral data to achieve ARI ≥ 0.60 (`PROVEN`) or ≥ 0.75 (`SOVEREIGN`) |
| `duplicate_request_id` | 409 | §6.9 | `correlation_id` already processed within the dedup window | Use a fresh UUID; retrieve cached response from original call |
| `chain_corruption` | 500 | §7.2 | Audit chain hash verification fails at one or more entries | Halt writes; alert operator; restore from verified backup |
| `unsupported_operator` | — | §4.2 | Condition node `op` is not in the operator table | Not an error response — runtime MUST return `ESCALATE` with `reason: "unsupported_operator"` |
| `unknown_agent` | — | SPEC-002 §3 | `agent_id` not in the artifact's `agents` manifest | Advisory mode: ESCALATE. Enforce mode: hard block |
| `deny_list_violation` | 403 | SPEC-002 §4 | Agent `agent_id` is in `cannot_call` for this action | Hard block in both advisory and enforce mode |

### 11.1 Error response format

All error responses MUST follow this envelope:

```json
{
  "error": {
    "code":    "data_contract_violation",
    "message": "Required context field 'credit_score' is missing",
    "hint":    "Supply all required_fields defined in this artifact's data_contract.",
    "doc_url": "https://nomosprotocol.com/spec#data-contract-violation"
  },
  "request_id": "<uuid>"
}
```

`code` is REQUIRED. `message` and `hint` are RECOMMENDED. `doc_url` is OPTIONAL. Runtimes MUST NOT return different codes for the same error condition across calls.

---

---

## 12. SDK & Distribution

### 12.1 TypeScript SDK

The official SDK (`@nomosprotocol/sdk`) provides a typed client for interacting with any conformant NOMOS runtime. It is zero-dependency, fetch-based, and auto-retries on rate limits and transient errors.

```bash
npm install @nomosprotocol/sdk
```

**Core methods:**

| Method | Maps to | Notes |
|---|---|---|
| `nomos.decisions.verify(params)` | `POST /api/v1/verify` or `/api/v1/verify-decision` | Public artifacts (`pub_*`) use the open endpoint; custom artifacts require an API key |
| `nomos.artifacts.list(params)` | `GET /api/exchange/artifacts` | Filter by band, domain, jurisdiction |
| `nomos.artifacts.retrieve(id)` | `GET /api/exchange/artifacts/:id` | Returns full artifact metadata |
| `nomos.governance.generate(params)` | `POST /api/v1/generate-governance` | Compile a governance artifact from policy text |
| `nomos.governance.detectContradictions(params)` | `POST /api/v1/detect-contradictions` | Check rules array for conflicts before sealing |

**Typed errors:** `NomosAuthenticationError`, `NomosAuthorizationError`, `NomosRateLimitError`, `NomosValidationError`, `NomosNotFoundError`, `NomosAPIError`, `NomosNetworkError` — all extend `NomosError`.

```typescript
import { Nomos, NomosRateLimitError } from '@nomosprotocol/sdk';

const nomos = new Nomos('nms_live_...');

const result = await nomos.decisions.verify({
  artifact_id:      'loan_approval_v1',
  decision_context: { credit_score: 720, loan_amount: 50_000 },
});
// result.allowed, result.verdict, result.audit_record
```

### 12.2 NOMOS Exchange

The NOMOS Exchange is the distribution layer for sealed artifacts. Publishers may list `PROVEN` (ARI ≥ 0.60) and `SOVEREIGN` (ARI ≥ 0.75) artifacts. `DECLARED` and `VALIDATED` artifacts are not eligible.

**Exchange lifecycle:**

1. Artifact sealed in Studio (`PROVEN` or `SOVEREIGN`)
2. Publisher submits `POST /api/exchange/artifacts` — quality gate enforced server-side
3. Artifact enters `pending` status (admin review for `SOVEREIGN`)
4. Artifact activated → discoverable at `/exchange/:artifactId`
5. Consumers fork to Studio or download `.nomos` directly
6. Forked artifact records provenance (`forkedFrom.artifactId`, `forkedFrom.sealHash`)

**Autonomy band filter:** Consumers may filter Exchange listings by `autonomy_band` (`autonomous` / `bounded` / `human_governed`), which is derived from `readiness.ari` per §3.7.

### 12.3 Public demo artifacts

The reference runtime ships with pre-sealed public artifacts accessible without authentication. Their `artifact_id` values carry a `pub_` prefix:

| Artifact ID | Domain | Confidence |
|---|---|---|
| `pub_lending_v1` | Loan approval | PROVEN |
| `pub_fraud_v1` | Fraud detection | CERTIFIED |
| `pub_kyc_v1` | KYC screening | CERTIFIED |

Public artifacts are callable via `POST /api/v1/verify` with no API key. They are read-only and not listed on the Exchange.

---

*End of NOMOS-SPEC-001*
