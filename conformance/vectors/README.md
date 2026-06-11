# NOMOS Conformance Test Vectors

This directory contains **deterministic test vectors** for NOMOS runtime implementors. Each vector specifies an artifact, an execution context, and the exact output a conformant runtime MUST produce.

Test vectors prove interoperability. If your runtime passes all 12 vectors, it correctly implements the normative requirements in NOMOS-SPEC-001.

---

## How to use

For each `v{nn}_*.json` file:

1. Load `artifact` as the governance artifact.
2. Send `context` (and `request_id` if present) as the execution request.
3. Assert that the runtime output matches `expected`.

Skip seal verification (`insecure_no_verify` mode) for vectors that use the public test seal (`deadbeef...` hash/sig). Only v10 tests actual seal verification — all others use the test seal as a placeholder.

---

## Vector index

| ID | Category | Tests |
|----|----------|-------|
| v01 | verdict_correctness | Single `eq` rule matches → ALLOW |
| v02 | verdict_correctness | `gt` rule matches → DENY |
| v03 | verdict_correctness | No rule matches → default ALLOW |
| v04 | conflict_resolution | `first_match`: two rules match, higher priority wins |
| v05 | conflict_resolution | `collect_and_resolve`: DENY+ALLOW → DENY wins |
| v06 | conflict_resolution | `highest_priority`: three rules, only top priority applies |
| v07 | missing_context | `data_contract` required field absent → `data_contract_violation` error |
| v08 | missing_context | Unknown operator → ESCALATE with `reason: "unsupported_operator"` |
| v09 | missing_context | AND branch: only left matches → rule does NOT fire |
| v10 | seal_security | All-zero hash/sig (tampered artifact) → `seal_verification_failed` |
| v11 | seal_security | Unknown `spec_version` → `spec_version_unsupported` error |
| v12 | seal_security | Duplicate `request_id` within dedup window → `cached: true`, no new audit entry |

---

## Vector file format

```json
{
  "id": "v01",
  "category": "verdict_correctness | conflict_resolution | missing_context | seal_security",
  "description": "Human-readable explanation of what this vector tests",
  "artifact": { ... },
  "context": { ... },
  "request_id": "<optional — present only when testing idempotency>",
  "expected": {
    "verdict": "ALLOW | DENY | ESCALATE | null",
    "matched_rule_id": "<string | null>",
    "error": "<error_code | null>",
    "cached": "<boolean | omitted>",
    "note": "Explains the requirement being tested"
  }
}
```

### `expected.verdict`

`null` means the runtime MUST NOT produce a verdict — it must instead emit an error. Any runtime that returns a verdict for v10, v11, or v07 (contract violation) fails the vector.

### `expected.error`

The machine-readable error code from §11 of NOMOS-SPEC-001. `null` means no error should occur.

### Public test seal

Vectors that are not testing seal integrity use the public test seal:
```
hash: deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
sig:  deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
```

Runtimes MUST support an `insecure_no_verify` flag for test environments that disables HMAC verification without disabling evaluation logic.

---

## Adding new vectors

Vectors MUST be deterministic — the same artifact + context must produce the same verdict across all conformant runtimes. Do not write vectors that depend on runtime-specific behaviour (e.g. random tie-breaking between equal-priority rules).

File naming: `v{NN}_{short_description}.json`. Numbers are sequential; never reuse a number.

Submit new vectors via the spec change process in `CONTRIBUTING.md`.
