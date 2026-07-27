# NOMOS Conformance Test Suite

Tests the conformance requirements defined in NOMOS-SPEC-001 §9.1 and §9.2, against the
artifact structure corrected in v2.0.0 (§3/§4).

## Requirements under test

### Runtime (§9.1)
| ID | Requirement |
|----|-------------|
| R1 | Refuses to execute an artifact whose `nomos_version` it does not recognise |
| R2 | Refuses to execute an artifact whose seal does not verify |
| R3 | Evaluates decisions' `when` as Nomos-Expr v1 strings (§4.1), not condition trees |
| R4 | Returns ESCALATE for an unrecognised function call rather than failing silently |
| R5 | `/api/v1/verify` response schema requires `audit_record` |
| R6 | `/api/v1/verify` response schema requires `contradictions` |

### Producer (§9.2)
| ID | Requirement |
|----|-------------|
| P1 | Generates artifacts that validate against `schema/artifact.schema.json` |
| P2 | Seals artifacts using the procedure in §8 — including a real, non-null `signature` |
| P2-neg | `status: "sealed"` with `signature: null` is detectable as non-conformant (§3.10) — the exact defect NOMOS-SPEC-001 v2.0.0 was written to catch |
| P3 | Sets `meta.verification_tier` correctly: `compiled` / `proven` / `sovereign` — distinct from the un-sealed public demo catalog's `DECLARED`/`VALIDATED`/`CERTIFIED` `confidence_band` (§5) |

## Running the suite

```bash
npx tsx conformance/run.ts
```

Prints a pass/fail table and exits with code 0 (all pass) or 1 (any fail). There is currently
only a TypeScript runner — no Python equivalent exists yet, despite what an earlier version of
this README claimed.

## Fixture artifacts

| File | Purpose |
|------|---------|
| `fixtures/valid_declared.nomos` | Valid `compiled`-tier artifact — all runtime tests should pass |
| `fixtures/valid_validated.nomos` | Valid `proven`-tier artifact — verification tier test |
| `fixtures/tampered_seal.nomos` | Seal hash is wrong — R2 must reject |
| `fixtures/unknown_spec_version.nomos` | `nomos_version` is unrecognised — R1 must reject |
| `fixtures/unknown_operator.nomos` | Decision calls an unrecognised function — R4 must escalate |
| `fixtures/missing_required_field.nomos` | Top-level required field (`scope`) omitted — P1 must reject |
| `fixtures/sealed_no_signature.nomos` | `status: "sealed"` but `signature: null` — P2-neg must detect this as non-conformant |
