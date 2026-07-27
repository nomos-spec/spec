# NOMOS-SPEC-001: Governance Artifact Protocol

**Status:** Active  
**Version:** 2.0.0  
**Published:** 2026-01-15  
**Updated:** 2026-07-27  
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group

---

## Abstract

NOMOS-SPEC-001 defines a portable, vendor-neutral format for packaging organisational governance policies as sealed, machine-executable artifacts (`.nomos` files). The specification covers artifact structure, the rule expression language, confidence classification, the cryptographic sealing procedure, the execution model, the audit trail schema, and conformance requirements for compliant runtimes.

The goals are reproducibility (identical inputs produce identical outputs), auditability (every decision is traceable to a sealed rule), and interoperability (any compliant runtime can execute any conformant artifact without access to the original policy documents).

Sealed artifacts may be distributed and verified independently of the producing platform. The official TypeScript SDK (`@nomosprotocol/sdk`) and the NOMOS Exchange provide reference implementations of the distribution and execution layers described in this specification.

**2.0.0 is a breaking correction, not an addition.** §3 and §4 of v1.1.0 described an artifact structure and condition format that did not match any artifact ever produced by a conformant implementation — an EU AI Act artifact sealed and published on the reference deployment failed validation against v1.1.0's own `schema/artifact.schema.json`. This version replaces §3 and §4 with the structure real conformant producers actually emit, verified directly against a live sealed artifact. §5 through §12 are corrected in smaller, targeted ways — most of that content was already accurate; see the CHANGELOG for the exact line-level diff. Per `DEPRECATION.md` principle 2, this is why the version increments rather than being published as editorial errata: §3/§4 changes alter what a conformant producer or runtime must accept.

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

**Artifact** — A sealed `.nomos` file; the output of the NOMOS compilation step. MUST be valid UTF-8 JSON. SHOULD be saved with the `.nomos` extension and served with media type `application/vnd.nomos+json` (§3.0) — never as a bare `.json` file with generic `Content-Type: application/json`.

**Decision** — A single declarative governance statement: a condition (`when`), one or more outcomes (`then`), and a priority. NOMOS-SPEC-001 v1.1.0 called this a "Rule" with a condition tree; §4 corrects this — the condition is a string expression, not a tree object.

**Verification tier** — A classification of how much confidence a runtime should place in an artifact's rules, stamped into the artifact at `meta.verification_tier`. Valid values: `compiled`, `proven`, `sovereign` (§5.1). A separate, unrelated vocabulary — `DECLARED`/`VALIDATED`/`CERTIFIED` — is used by the reference deployment's un-sealed public demo artifacts (§5.2); the two are not interchangeable and a runtime MUST NOT conflate them.

**Seal** — A cryptographic block appended to a frozen artifact, binding all fields (except itself and `attestations`) to a specific key and timestamp.

**Runtime** — Any system that loads a `.nomos` artifact and evaluates decisions against its rules.

**Verdict** — The outcome of a single execution. The vocabulary differs by API surface — see §6 for the two real, distinct execution APIs and their respective verdict vocabularies.

**Audit hash** — A SHA-256 digest that chains consecutive execution entries for a given artifact into a tamper-evident log (§7).

---

## 3. Artifact Structure

### 3.0 File Extension and Media Type

A `.nomos` artifact SHOULD be saved with the `.nomos` file extension and served with media type `application/vnd.nomos+json` — a vendor-specific JSON media type, the same convention `.docx` and similar container formats use to be both a valid, generic JSON document and an unambiguously identifiable artifact type. Implementations MUST NOT serve or save a sealed artifact as a bare `.json` file (e.g. `artifact.nomos.json`) with generic `Content-Type: application/json` — doing so loses the distinction between "some JSON" and "a portable governance artifact" that this specification exists to establish.

### 3.1 Top-level structure

A `.nomos` file's top-level object MUST contain the following nine keys:

```json
{
  "nomos_version":  "1.0.0",
  "meta":           { ... },
  "scope":          { ... },
  "data_contract":  { ... },
  "logic":          { ... },
  "governance":     { ... },
  "execution":      { ... },
  "audit":          { ... },
  "seal":           { ... }
}
```

An artifact MAY additionally carry `agents` (NOMOS-SPEC-002, multi-agent governance manifest), `provenance` (compilation lifecycle record — session id, source documents, review summary), and `attestations` (NOMOS-SPEC-004, third-party co-signatures). Runtimes MUST ignore top-level keys they do not recognise rather than rejecting the artifact.

### 3.2 `nomos_version`

Type: string. MUST equal `"1.0.0"` for artifacts conformant with this specification's artifact-structure requirements (§3–§4). A runtime that does not recognise `nomos_version` MUST refuse to execute the artifact.

### 3.3 `meta` — Identity, provenance, ownership

```json
{
  "artifact_id":         "<string, UUID recommended>",
  "name":                "<string>",
  "version":             "<semver>",
  "created_at":          "<ISO 8601 UTC>",
  "owner": {
    "org_name": "<string>",
    "org_id":   "<string>",
    "contact":  "<string, email>"
  },
  "tags":                ["<string>"],
  "description":         "<string>",
  "industry":            "<string>",
  "verification_tier":   "compiled | proven | sovereign"
}
```

`artifact_id` and `version` are REQUIRED. `owner` is REQUIRED; `owner.org_id` and `owner.contact` are REQUIRED, `owner.org_name` is RECOMMENDED. `verification_tier` is REQUIRED once sealed (§5.1). `jurisdictions` (array of strings) is OPTIONAL.

Any change that affects verdict output for any previously valid input REQUIRES a `meta.version` increment and a new seal. Re-sealing without a version increment is not conformant.

### 3.4 `scope` — What workflow this governs

```json
{
  "workflow": {
    "domain":         "<string>",
    "workflow_name":  "<string>",
    "workflow_key":   "<string>",
    "intent":         "<string>"
  },
  "boundaries": {
    "in_scope":     ["<string>"],
    "out_of_scope": ["<string>"],
    "assumptions":  ["<string>"]
  }
}
```

Both `workflow` and `boundaries` are REQUIRED. `boundaries.out_of_scope` and `assumptions` MAY be empty arrays.

### 3.5 `data_contract` — Inputs, types, confidence policy

```json
{
  "inputs": {
    "<field_name>": {
      "type":        "string | number | integer | boolean | date | datetime | enum | object | array",
      "description": "<string>",
      "required":    true
    }
  },
  "required_fields":  ["<field_name>"],
  "provenance": {
    "allowed_sources":       ["<string>"],
    "verification_methods":  ["<string>"]
  },
  "confidence_policy": {
    "min_confidence_for_autonomy": 0.9,
    "min_confidence_per_field":    {},
    "on_low_confidence":           "block | escalate | defer"
  }
}
```

`inputs` and `required_fields` are REQUIRED. A runtime MUST check that every field in `required_fields` is present in the execution request's inputs before evaluating decisions; a runtime that receives a request missing one or more `required_fields` MUST NOT evaluate with the incomplete input set — see §6 for how each real execution API surfaces this.

### 3.6 `logic` — Decision graph

```json
{
  "variables":   {},
  "decisions":   [ { ... } ],
  "resolution": {
    "conflict_policy": "first_match | highest_priority | collect_and_resolve",
    "tie_breaker":      "deny_wins | allow_wins | escalate_wins"
  }
}
```

`decisions` is the ordered array of decision objects — see §4 for their structure and the expression language used in `when`. `resolution` is REQUIRED; RECOMMENDED default is `collect_and_resolve` + `deny_wins`.

### 3.7 `governance` — Constraints, escalation, roles, compliance

```json
{
  "constraints": [
    { "id": "<string>", "type": "budget | privacy | compliance | risk | data | timing | custom",
      "rule": "<expression string, §4.1>", "on_violation": "block | escalate", "message": "<string>" }
  ],
  "escalations": [
    { "id": "<string>", "role_required": "<string>", "trigger": "<expression string>",
      "payload": { "show": ["<field>"], "question": "<string>" }, "sla_minutes": 240 }
  ],
  "roles": [
    { "role_id": "<string>", "name": "<string>", "authority_scope": ["<string>"] }
  ],
  "compliance": {
    "requirements": ["<string>"], "logging_level": "minimal | standard | forensic", "retention_days": 365
  }
}
```

All four keys are REQUIRED (`constraints`, `escalations`, and `roles` MAY be empty arrays). Constraints MUST be enforced on every execution, independent of `logic.decisions` evaluation.

### 3.8 `execution` — Allowed actions and integrations

```json
{
  "actions": {
    "<action_name>": {
      "type":       "api_call | message | record_write | task_create | webhook",
      "connector":  "<connector id>",
      "request":    { "method": "POST", "path": "<string>" },
      "idempotency": { "key": "<expression string>", "strategy": "reject_duplicates | safe_retry" }
    }
  },
  "connectors": [
    { "id": "<string>", "kind": "http | queue | database | service", "endpoint": "<string>", "auth": { "ref": "<string>" } }
  ]
}
```

`connectors[].auth` MUST NOT contain secrets in plaintext — reference an external secret store only.

### 3.9 `audit` — Event schema and redaction policy

```json
{
  "event_schema": { "type": "nomos.audit.v1", "fields": ["artifact_id", "decision_trace", "constraint_trace", "actions"] },
  "emit_on":      ["decision", "constraint_violation", "action", "escalation", "completion"],
  "redaction":    { "pii_fields": [], "strategy": "hash | mask | remove", "hash_salt_ref": "<string, optional>" }
}
```

This declares the redaction policy a runtime MUST apply before persisting audit entries (§7) — it does not itself contain audit entries.

### 3.10 `seal`

See §8 for the full sealing procedure.

```json
{
  "status":              "draft | sealed",
  "hash":                "<hex-encoded SHA-256 of canonical payload, excluding seal and attestations> | null",
  "canonicalization":     "JCS",
  "signed_by":            { "name": "...", "org_id": "...", "role": "...", "timestamp": "<ISO 8601 UTC>" } | null,
  "signature":            "<base64 signature over JCS({hash, signed_by})> | null",
  "signature_algorithm":  "Ed25519 | RS256 | HMAC-SHA256"
}
```

If `status` is `sealed`, `signed_by` and `signature` MUST both be present and non-null. A hash-only artifact — `status: "sealed"` with a populated `hash` but `signature: null` — is not conformant; it indicates the producer computed integrity but never invoked the signing step. Ed25519 is RECOMMENDED: it is the only one of the three algorithms publicly (third-party) verifiable without a shared secret — see §8.2 for public key discovery.

### 3.11 `data_contract` in the request path

A runtime MUST verify `required_fields` from §3.5 before evaluating `logic.decisions` for a given request. Which specific field of the response reports this (`missing_required`, `incomplete_inputs`, etc.) depends on the execution API surface — see §6.

---

## 4. Rule Expression Language ("Nomos-Expr v1")

### 4.1 Condition strings

Each decision's `when` field (§4.2) is a **string** in a small, deterministic expression language — not a condition-tree object. Expressions MUST be pure: no network calls, no randomness, no side effects.

Supported syntax:

| Category | Syntax | Example |
|---|---|---|
| Boolean | `and`, `or`, `not` | `a > 5 and b == "x"` |
| Comparison | `==`, `!=`, `>`, `>=`, `<`, `<=` | `invoice_amount > 25000` |
| Set membership | `in`, `contains` | `item_type in ["reference", "periodical"]` |
| Arithmetic | `+`, `-`, `*`, `/` | `amount * 0.1 > fee_cap` |
| Functions | `exists(x)`, `len(x)`, `lower(x)`, `startsWith(a, b)` | `exists(vendor_risk_score)` |

A sentinel condition `"always == true"` is used for unconditional decisions.

A runtime MUST parse and evaluate these expressions deterministically: identical inputs against an identical `when` string MUST always produce the same boolean result. A runtime MUST NOT fail silently on an unparseable expression — it MUST return an evaluation error that the calling API surface (§6) reports to the caller.

### 4.2 Decision object

Each element of `logic.decisions` (§3.6) MUST have this shape:

```json
{
  "id":          "<string>",
  "description": "<string>",
  "when":        "<Nomos-Expr v1 string, §4.1>",
  "then":        [ { "type": "allow | block | escalate | set | emit | action", "...": "..." } ],
  "else":        [ { ... } ],
  "priority":    100,
  "provenance": {
    "source_id":           "<string, optional>",
    "source_name":         "<string, optional>",
    "extractor_version":   "<string, optional>",
    "extraction_timestamp": "<ISO 8601, optional>"
  }
}
```

`id`, `description`, `when`, `then`, and `priority` are REQUIRED. `else` MAY be an empty array. `provenance` is OPTIONAL, RECOMMENDED for any decision derived from a source document — every `.nomos` decision SHOULD be traceable to the section of the source it came from.

### 4.3 Outcome objects

Each element of `then`/`else` MUST have a `type` of one of:

| `type` | Meaning | Additional fields |
|---|---|---|
| `allow` | Permits the action | — |
| `block` | Denies the action | `reason` (RECOMMENDED) |
| `escalate` | Routes to human review | `escalation_id` referencing `governance.escalations` (§3.7) |
| `set` | Assigns a `logic.variables` value | `variable`, `value` |
| `emit` | Emits an audit/event record | event payload |
| `action` | Invokes a named action from `execution.actions` (§3.8) | `action_name` |

A runtime MUST evaluate eligible decisions in descending `priority` order and apply outcomes per `logic.resolution.conflict_policy` (§3.6) when more than one decision is eligible for a given input.

### 4.4 Field paths

Field paths use dot notation for nested access (e.g. `applicant.credit_score`). Array indexing is not defined in this spec version.

### 4.5 Deprecated: condition-tree format

An earlier internal execution path (predating the reference deployment's Studio/Exchange product) represents `when` as a structured tree object (`{ type: "and" | "or" | "condition", expressions: [...], condition: {...} }`) rather than a string. This is a distinct, older internal representation, not a conformant `.nomos` artifact structure under this spec version, and MUST NOT be produced by new conformant producers. A runtime encountering it internally MUST convert it to the string form before treating an artifact as spec-conformant.

---

## 5. Confidence Classification

Two separate, non-interchangeable vocabularies exist in the reference deployment. A runtime MUST NOT conflate them, and a conformant producer MUST use the one appropriate to what it is producing.

### 5.1 Verification tier (sealed artifacts — `meta.verification_tier`)

Assigned when an artifact is sealed (§3.10, §8). Valid values, in ascending order of confidence:

| Tier | Meaning |
|---|---|
| `compiled` | Rules extracted from policy documents (and, if provided, behavioral data), schema-valid, seal-valid. The baseline for any sealed artifact. |
| `proven` | `compiled`, plus the artifact includes measurable evidence references and a performance ledger from real behavioral data. |
| `sovereign` | `proven`, plus a verified compliance profile, forensic-level audit logging, and enforced governance constraints. |

A runtime MUST preserve `meta.verification_tier` verbatim from the sealed artifact and MUST NOT infer or override it independently.

### 5.2 Confidence band (un-sealed public demo artifacts only)

The reference deployment's public demo catalog (§12.3) uses a separate field, `confidence_band`, with values `DECLARED | VALIDATED | CERTIFIED`. These artifacts are not run through the sealing procedure in §8 and do not carry a `seal` block in the sense of §3.10. `DECLARED` means the rules reflect standard industry practice, not empirically validated thresholds from real behavioral data — every artifact currently in the reference deployment's public demo catalog is `DECLARED`. `VALIDATED` and `CERTIFIED` are reserved values for a forked, behaviorally-triangulated version of a demo artifact; as of this spec version no shipped demo artifact carries either value.

---

## 6. Execution Model

The reference deployment exposes **two separate, real execution APIs**, serving different artifact populations, with different authentication and different response shapes. A conformant runtime implementing only one is not thereby non-conformant with the other — pick the surface matching your artifact population. Do not assume the two are interchangeable.

### 6.1 Domain execution — `POST /api/nomos/execute`

Session-authenticated (cookie), used for artifacts loaded via the enterprise "Domain" model.

**Request:**

```json
{
  "domain_id":   "<integer>",
  "input_data":  { "<field>": "<value>", ... },
  "options":     { ... },
  "caller": { "user_id": "<string, optional>", "correlation_id": "<string, optional>" }
}
```

**Version negotiation:** set request header `Accept-Nomos-Version: 1.0.0` for the spec-compliant response below; omit it (or send `1.0`) for a legacy response format. Response header `Content-Nomos-Version` echoes which format was returned.

**Spec-compliant response (`ExecutionReceipt`):**

```json
{
  "receipt_version": "1.0.0",
  "artifact": {
    "artifact_id":       "<string>",
    "artifact_version":  "<semver>",
    "seal_hash":          "<hex | null>",
    "verification_tier":  "compiled | proven | sovereign | null"
  },
  "execution": {
    "execution_id": "<string>",
    "started_at":   "<ISO 8601 UTC>",
    "ended_at":     "<ISO 8601 UTC>",
    "status":       "allowed | blocked | escalated | deferred",
    "final_reason": "<string>",
    "latency_ms":   "<integer>"
  },
  "inputs": {
    "provided":         { "<field>": "<value>" },
    "missing_required":  ["<field>"],
    "confidence":        "<float 0-1>",
    "provenance":        {}
  },
  "trace": {
    "constraints": [ { "constraint_id": "<string>", "result": "passed | violated", "message": "<string, optional>" } ],
    "decisions":   [ { "decision_id": "<string>", "result": "matched | not_matched | expired", "outcome": "allow | block | escalate" } ],
    "actions":     [ { "action": "<string>", "result": "success | failure", "idempotency_key": "<string>", "error": "<string, optional>" } ],
    "escalation":  { "role_required": "<string>", "trigger_id": "<string>", "payload_fields": ["<field>"] } 
  }
}
```

`execution.status` mapping from the internal outcome vocabulary: `approved → allowed`, `rejected → blocked`, `escalated → escalated`, `held → deferred`.

### 6.2 Exchange execution — `POST /api/v1/verify` and `POST /api/v1/verify-decision`

API-key-authenticated (`X-Nomos-Api-Key` header) or session, used by the official SDK (§12.1) and by any caller integrating with the NOMOS Exchange or Studio-sealed artifacts. `/verify` serves the public demo catalog only (`pub_*` artifact IDs, §12.3, no auth required); `/verify-decision` serves everything else (`art_*` Studio artifacts, Exchange catalog slugs, and `dom_*` domain routing), routed by `artifact_id` prefix.

**Request:**

```json
{
  "artifact_id":  "<string>",
  "decision":     "<string, ≤200 chars>",
  "inputs":       { "<field>": "<value>" },
  "caller": { "agent_id": "<string, optional>", "correlation_id": "<string, optional>", "user_id": "<string, optional>", "tool": "<string, optional>" },
  "execution_at": "<ISO 8601, optional — replay as of this instant>",
  "decision_type": "<string, optional>"
}
```

**Response:**

```json
{
  "id":             "req_<uuid>",
  "object":         "decision",
  "artifact_id":    "<string>",
  "artifact_name":  "<string>",
  "allowed":        true,
  "verdict":        "approved | rejected | escalated",
  "rule":           { "id": "<string>", "description": "<string | null>", "action": "allow | deny | escalate" },
  "evaluation": {
    "rules_evaluated": "<integer>", "rules_matched": "<integer>", "rules_expired": "<integer>", "conflicts_resolved": "<integer>",
    "rules_checked": [ { "id": "<string>", "name": "<string>", "fired": true, "conditions": [ { "field": "<string>", "check": "<string>", "input": "<value>", "present": true, "passed": true } ] } ]
  },
  "classifications": [ { "field": "<string>", "value": "<value>", "rule_id": "<string>", "rule_name": "<string>" } ],
  "obligations":     [ "<string>" ],
  "confidence":      { "tier": "<string>", "score": "<float 0-1>", "description": "<string>" },
  "audit":           { "hash": "<hex>", "timestamp": "<ISO 8601 UTC>" },
  "performance":     { "latency_ms": "<integer>" },
  "verdict_description": "<string>",
  "incomplete_inputs":   { "fields": ["<field>"], "count": "<integer>", "warning": "<string>" },
  "paths_to_approval":   ["<string>"],
  "expired_rules":       ["<string>"],
  "replay":              true,
  "active_decision_type": { "id": "<string>", "name": "<string>", "auto_scoped": true }
}
```

`classifications`, `obligations`, `incomplete_inputs`, `paths_to_approval`, `expired_rules`, `replay`, and `active_decision_type` are present only when applicable to the specific evaluation — omitted otherwise, not null.

The simpler public-artifact response from `POST /api/v1/verify` follows the same `allowed`/`outcome`/`verdict_description`/`audit_record` shape but without the `rule`/`evaluation`/`confidence` nesting above — see §12.3.

### 6.3 Idempotency

`caller.correlation_id` is accepted on both APIs and is recorded in the audit trail (§7). **As of this spec version, neither API deduplicates or caches a response by `correlation_id`** — a repeated call with the same `correlation_id` re-executes and produces a new audit entry. This is a known gap relative to the idempotency behavior a caller might reasonably expect from the field's presence; treat `correlation_id` today as a trace identifier only, not a dedup key.

### 6.4 Quota and rate limits (Exchange execution only)

A conformant response from `/api/v1/*` MUST include:

| Header | Description |
|---|---|
| `X-Verifications-Used` | Verifications consumed in the current billing period |
| `X-Verifications-Limit` | Monthly limit for the account's subscription tier, or `unlimited` |
| `X-Overage` | `"true"` when the account has exceeded its monthly limit |
| `X-Overage-Count` | Calls beyond the monthly limit in the current billing period |

---

## 7. Audit Trail

### 7.1 Entry hash chain

Every execution appends one entry to a hash chain, keyed per artifact (Domain execution, §6.1) or per Studio session (Exchange execution, §6.2). The chain primitive is shared:

```
entryHash = SHA-256( previousHash + "|" + JCS(eventData) + "|" + timestamp )
```

where `JCS(eventData)` is the JSON-Canonicalization-Scheme-canonicalized (§8) event payload for this entry, and `previousHash` is the immediately preceding entry's `entryHash` for the same chain. `"|"` is a literal delimiter character preventing length-extension ambiguity between the three concatenated components.

**Genesis entry** (first entry in a chain):

```
genesisHash = SHA-256( "genesis:" + chainId + ":" + timestamp )
```

used as `previousHash` for the first real entry. `chainId` is the decision id (Domain execution) or session id (Exchange execution).

A verifier MUST walk the chain from genesis to tip and confirm each `entryHash` recomputes correctly from the recorded `eventData` and `timestamp`. Any gap or mismatch indicates chain corruption.

### 7.2 Per-query audit hash (Exchange `/query` only)

The Exchange's separate public-query surface (not an execution API under §6, but a read-oriented "ask this artifact a question" endpoint) computes a simpler, non-chained integrity hash per query:

```
audit_hash = SHA-256( JCS({ query_id, seal_hash, inputs, verdict, queried_at }) )
```

This is suitable for confirming a single query response was not altered in transit or storage; it is not a hash chain and does not itself detect a missing or reordered query.

---

## 8. Sealing Procedure

Sealing is a one-way operation. Once a `.nomos` artifact is sealed, its payload MUST NOT be modified. Any modification invalidates the seal.

### 8.1 Canonicalization

Runtimes MUST canonicalize using JCS (JSON Canonicalization Scheme, [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) for both hashing and signing: object keys sorted lexicographically at every nesting level, no insignificant whitespace, UTF-8 string escaping per the JSON spec.

### 8.2 Hash

```
seal.hash = SHA-256( JCS(artifact_without_seal_and_attestations) )
```

`seal` and `attestations` (NOMOS-SPEC-004) are excluded from the hash input — `seal` cannot cover itself, and `attestations` are added after sealing by third parties without invalidating the original seal.

### 8.3 Signature

```
payload = JCS({ hash: seal.hash, signed_by: seal.signed_by })
```

A conformant producer signs `payload` using one of, in order of preference:

1. **Ed25519** (RECOMMENDED) — asymmetric; publicly verifiable with only the published public key (§8.4), no shared secret. `signature_algorithm: "Ed25519"`, `kid` set to the signing key's id.
2. **RS256/EC** — asymmetric, caller-supplied key.
3. **HMAC-SHA256** — symmetric, dev/fallback only. `signature_algorithm: "HMAC-SHA256"`. **Not publicly (third-party) verifiable** — the verifier needs the same secret as the signer. MUST NOT be represented as publicly verifiable.

A producer that stamps `status: "sealed"` MUST have actually executed one of these three signing steps and populated a non-null `signature`. Populating `hash` while leaving `signature: null` — however common a coding mistake this may be for an implementation that computes the hash but forgets to invoke the signing step — produces a non-conformant artifact per §3.10.

### 8.4 Public key discovery

Ed25519 public keys are published at `/.well-known/nomos-signing-keys` as `[{ kid, algorithm: "Ed25519", public_key_pem }]`. A verifier resolves the correct key for a given seal by its `kid`, which is a deterministic content hash of the public key (first 16 characters of base64url-SHA-256 of the SPKI-encoded public key) — this allows key rotation without invalidating verification of seals made under a retired key, as long as its public key remains published or otherwise available to the verifier.

### 8.5 Verification

```
hash_match      = timingSafeEqual( SHA-256(JCS(artifact_without_seal_and_attestations)), seal.hash )
signature_valid = crypto.verify( payload, seal.signature, publicKey )   // Ed25519: no pre-hash; RSA/EC: sha256 pre-hash
verified        = hash_match AND signature_valid
```

Both comparisons MUST be timing-safe. A verifier MUST report `hash_match` and `signature_valid` as distinct booleans, not only a combined `verified` — a hash-only artifact (§3.10) is a real, distinguishable state (content pinned, not signed), not identical to "verification failed."

---

## 9. Conformance

### 9.1 Compliant runtime

A runtime is conformant if it:

1. Refuses to execute an artifact whose `nomos_version` it does not recognise.
2. Evaluates `logic.decisions` per §4, in descending `priority` order, applying `logic.resolution.conflict_policy` when multiple decisions are eligible.
3. Enforces `governance.constraints` (§3.7) on every execution, independent of decision evaluation.
4. Verifies `required_fields` from `data_contract` (§3.5) before evaluating, per whichever execution API surface (§6) it implements.
5. Appends a hash-chained audit entry (§7.1) for every execution, or a per-query audit hash (§7.2) for every read-oriented query.
6. Preserves `meta.verification_tier` verbatim (§5.1) and does not infer or override it.

### 9.2 Compliant artifact producer

A producer is conformant if it:

1. Generates artifacts that validate against `schema/artifact.schema.json`.
2. Seals artifacts per §8, populating a real, non-null `signature` whenever `seal.status` is `"sealed"` — never `hash`-only.
3. Assigns `meta.verification_tier` per §5.1's ascending criteria, and does not assign `proven` or `sovereign` without the evidence those tiers require.
4. Populates decision `provenance` (§4.2) for every decision derived from a source document.

---

## 10. Security Considerations

**Signing key protection** — The signing key is the root of trust for all artifacts. For Ed25519, the **private** key MUST be stored in a secrets manager (env/KMS/HSM) and never embedded in code, version control, or the artifact; only the **public** key is published (§8.4), and publishing it is safe because it cannot forge a seal. For HMAC, the shared secret is both signer and verifier and MUST be treated as a top-level secret. Making seals publicly verifiable removes the *verification* secret, not the *signing* secret — signing remains a privileged operation.

**Key provenance** — Publishing a public key at `/.well-known/nomos-signing-keys` lets verifiers fetch it over TLS, which binds trust to the domain's certificate. Deployments requiring a stronger anchor SHOULD pin the key out of band or record its publication in an append-only transparency log.

**Context injection** — Runtimes MUST NOT evaluate user-supplied strings as arbitrary code. `when`/constraint expression evaluation (§4.1) MUST be performed by the deterministic Nomos-Expr v1 evaluator only.

**Audit trail integrity** — The hash-chain audit trail (§7.1) is append-only. Runtimes MUST NOT expose a deletion endpoint for audit entries.

**Verification tier downgrade** — Altering `meta.verification_tier` without re-sealing constitutes misrepresentation of the artifact's provenance. Runtimes MUST preserve it verbatim from the sealed artifact.

**Idempotency gap** — Per §6.3, `correlation_id` is not currently a dedup key on either execution API. A caller relying on it for exactly-once semantics today will not get them; this is a real, disclosed gap, not a documentation omission.

---

## 11. Error Catalog

The reference deployment's two execution APIs (§6) do not share a single error-code vocabulary today. This is a real, disclosed inconsistency, not a specification gap to be papered over with an idealized unified table.

### 11.1 Domain execution (`/api/nomos/execute`, `/api/nomos/domain/*`)

Returns `{ "error": "<message>" }` with an HTTP status code and **no machine-readable `code` field**. A caller must currently match on HTTP status and message text. HTTP statuses used: `400` (invalid request/domain id), `401` (authentication required), `403` (access denied to domain/decision), `404` (domain or decision not found).

### 11.2 Exchange execution (`/api/v1/verify`, `/api/v1/verify-decision`)

Returns `{ "error": "<message>", "code": "<UPPER_SNAKE_CASE code>" }`. Codes actually in use:

| Code | HTTP | Trigger |
|---|---|---|
| `VALIDATION_ERROR` | 400 | Request body fails schema validation |
| `WRONG_ENDPOINT` | 400 | `pub_*` artifact id sent to `/verify-decision` (must use `/verify`) |
| `NOT_FOUND` | 404 | `artifact_id` not found in the relevant registry |
| `AUTH_REQUIRED` | 401 | Non-public artifact requested without `X-Nomos-Api-Key` or session |
| `FORBIDDEN` | 403 | API key does not have access to this artifact |
| `NO_RULES` | 400 | Artifact has no governance rules to evaluate |
| `DATA_CONTRACT_VIOLATION` | 422 | None of the provided input fields are referenced by any rule |
| `SCHEMA_MISMATCH` | 422 | One or more `data_contract.required_fields` missing from `inputs` |
| `INVALID_EXECUTION_AT` | 422 | `execution_at` is not a valid, non-future ISO 8601 timestamp |
| `INVALID_KEY` | 401 | `X-Nomos-Api-Key` is invalid or revoked |
| `ALLOTMENT_EXCEEDED` | 402 | Free monthly query allotment reached, no active paid plan |

### 11.3 Error response envelope (Exchange execution)

```json
{ "error": "<human-readable message>", "code": "<CODE>" }
```

`error` and `code` are both REQUIRED on this surface. Domain execution (§11.1) does not currently include `code` — a caller integrating with both surfaces MUST branch on which one it is calling rather than assuming a shared shape.

---

## 12. SDK & Distribution

### 12.1 TypeScript SDK

The official SDK (`@nomosprotocol/sdk`, published on npm) provides a typed client for interacting with the reference deployment. It is zero-dependency, fetch-based, and auto-retries on rate limits and transient errors.

```bash
npm install @nomosprotocol/sdk
```

**Core methods:**

| Method | Calls | Notes |
|---|---|---|
| `nomos.decisions.verify(params)` | `POST /api/v1/verify` (public artifacts) or `/api/v1/verify-decision` (everything else), chosen by `artifact_id` prefix | See §6.2 |
| `nomos.artifacts.retrieve(id)` | `GET /api/v1/artifacts/:id` | |
| `nomos.artifacts.list(params)` | `GET /api/v1/artifacts` | Filter by band, domain, jurisdiction |
| `nomos.artifacts.schema(id)` | `GET /api/v1/artifacts/:id/schema` | Field names/types the artifact's rules reference |
| `nomos.governance.generate(params)` | `POST /api/v1/generate-governance` | Compile a governance artifact from policy text |
| `nomos.governance.detectContradictions(params)` | `POST /api/v1/detect-contradictions` | Check rules for conflicts before sealing |

**Typed errors:** `NomosAuthenticationError`, `NomosAuthorizationError`, `NomosRateLimitError`, `NomosValidationError`, `NomosNotFoundError`, `NomosAPIError`, `NomosNetworkError` — all extend `NomosError`, which carries a `code` from `NomosErrorCode` (`authentication_error | authorization_error | rate_limit_error | validation_error | not_found | api_error | network_error | webhook_signature_error`) — note this SDK-level code vocabulary is lowercase_snake_case and is distinct from the transport-level `code` values in §11.2.

```typescript
import { Nomos } from '@nomosprotocol/sdk';

const nomos = new Nomos('nmk_live_...');

const result = await nomos.decisions.verify({
  artifact_id: 'pub_lending_v1',
  decision:    'approve_loan',
  inputs:      { credit_score: 720, amount: 15000 },
});
// result.allowed, result.verdict, result.verdict_description
```

### 12.2 NOMOS Exchange

The NOMOS Exchange is the distribution layer for sealed Studio artifacts. Publishers list a sealed artifact; consumers query it via §6.2 or fork it into their own Studio session. The `proven`/`sovereign` verification tiers (§5.1) are the tiers a listing quality gate would reasonably require — this spec version does not assert a specific enforced gate, since that policy lives in the Exchange product, not the artifact format.

### 12.3 Public demo artifacts

The reference deployment ships five pre-built, un-sealed demo artifacts, callable via `POST /api/v1/verify` with no authentication:

| Artifact ID | Domain | Confidence band (§5.2) |
|---|---|---|
| `pub_lending_v1` | Consumer loan approval | `DECLARED` |
| `pub_refund_v1` | Refund policy | `DECLARED` |
| `pub_fraud_v1` | Fraud detection | `DECLARED` |
| `pub_hr_leave_v1` | HR leave approval | `DECLARED` |
| `pub_kyc_v1` | KYC screening | `DECLARED` |

All five are `DECLARED` — none have been forked and re-triangulated against real behavioral data, and none are listed on the Exchange (§5.2's `VALIDATED`/`CERTIFIED` values are reserved for a forked, behaviorally-triangulated version, not the shipped demo artifacts themselves).
