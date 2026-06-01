# NOMOS-SPEC-001: Governance Artifact Protocol

**Status:** Active  
**Version:** 1.0.0  
**Published:** 2026-01-15  
**Authors:** SafeHaven LLC / NOMOS Protocol Working Group  

---

## Abstract

NOMOS-SPEC-001 defines a portable, vendor-neutral format for packaging organisational governance policies as sealed, machine-executable artifacts (`.nomos` files). The specification covers artifact structure, the rule expression language, confidence classification, the cryptographic sealing procedure, the execution model, the audit trail schema, and conformance requirements for compliant runtimes.

The goals are reproducibility (identical inputs produce identical outputs), auditability (every decision is traceable to a sealed rule), and interoperability (any compliant runtime can execute any conformant artifact without access to the original policy documents).

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

---

## 1. Conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

All examples use JSON. String values MUST be UTF-8 encoded. All timestamps MUST be ISO 8601 in UTC (`Z` suffix).

---

## 2. Terminology

**Artifact** — A sealed `.nomos` file; the output of the NOMOS compilation step.

**Rule** — A single declarative governance statement: a condition tree + an action.

**Confidence tier** — A classification indicating how the rules were derived (`DECLARED` or `CERTIFIED`).

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
  "confidence":    "DECLARED | CERTIFIED",
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

Semantic version (`MAJOR.MINOR.PATCH`). Incrementing `MAJOR` signals backward-incompatible rule changes. Implementations MUST NOT treat two artifacts with different `version` values as equivalent even if `artifact_id` matches.

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

### 5.1 DECLARED

Rules derived exclusively from uploaded policy documents. No behavioral data was used.

- `drs` in `readiness` MUST be `null`.
- The artifact carries reduced statistical confidence.
- Suitable for new deployments where historical decision data does not yet exist.

### 5.2 CERTIFIED

Rules triangulated against behavioral decision logs. Statistical validation passed.

- `drs` in `readiness` MUST be a float in [0, 1].
- The artifact has passed contradiction detection and gap analysis.
- Suitable for production deployments requiring regulator-grade auditability.

A runtime MAY surface the confidence tier in its API response. A runtime MUST NOT downgrade a `CERTIFIED` artifact to `DECLARED` or vice versa without re-sealing.

---

## 6. Execution Model

### 6.1 Request

An execution request carries:

```json
{
  "artifact_id": "<string>",
  "version":     "<semver | omit for latest>",
  "context":     { "<field>": "<value>", ... },
  "request_id":  "<uuid>"
}
```

`context` is a flat or nested JSON object whose keys correspond to field paths referenced in rule conditions.

### 6.2 Evaluation pipeline

1. **Scope validation** — confirm `artifact_id` and `version` resolve to a known sealed artifact.
2. **Data contract validation** — check that required context fields are present.
3. **Rule evaluation** — iterate rules in priority order (or per `conflict_resolution` mode). Evaluate each condition against `context`.
4. **Conflict resolution** — apply the artifact's `conflict_resolution` mode if multiple rules match.
5. **Verdict emission** — return a Verdict object (§6.3).
6. **Audit append** — append the verdict to the artifact's audit trail (§7).

### 6.3 Verdict

```json
{
  "verdict":       "ALLOW | DENY | ESCALATE",
  "confidence":    "<float 0–1>",
  "matched_rules": ["<rule_id>"],
  "artifact_id":   "<string>",
  "version":       "<semver>",
  "request_id":    "<uuid>",
  "ts":            "<ISO 8601 UTC>",
  "audit_hash":    "<hex-encoded SHA-256>",
  "contradictions": 0
}
```

`audit_hash` is the hash-chain value linking this verdict to the previous verdict for the same artifact (see §7.2).

### 6.4 Missing context

If a required field is absent from `context` and the condition cannot be evaluated:

- If `autonomy_band` is `human_governed` → verdict is `ESCALATE`.
- Otherwise → verdict is `ESCALATE` with `reason: "missing_context_field"`.

A runtime MUST NOT default missing numeric fields to `0` or string fields to `""`.

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
3. Sets `confidence` to `DECLARED` when no behavioral data was used, and `CERTIFIED` only after statistical triangulation.
4. Populates `contradiction_report` with any detected conflicts before sealing.

---

## 10. Security Considerations

**Seal key protection** — The `SEAL_KEY` is the root of trust for all artifacts. It MUST be stored in a secrets manager and never embedded in application code or version control.

**Replay attacks** — The `request_id` in an execution request SHOULD be a UUIDv4. Runtimes SHOULD reject duplicate `request_id` values within a configurable window (recommended: 5 minutes).

**Context injection** — Runtimes MUST NOT evaluate user-supplied strings as code. Condition evaluation MUST be performed against a static rule tree only.

**Audit trail integrity** — The hash-chain audit trail is append-only. Runtimes MUST NOT expose a deletion endpoint for audit entries. Backup and replication of the audit store is REQUIRED for production deployments.

**Confidence tier downgrade** — Displaying a `CERTIFIED` artifact as `DECLARED` (or vice versa) constitutes misrepresentation of the artifact's provenance. Runtimes MUST preserve the `confidence` field verbatim from the sealed artifact.

---

*End of NOMOS-SPEC-001*
