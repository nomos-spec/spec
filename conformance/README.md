# NOMOS Conformance Test Suite

Tests the nine conformance requirements defined in NOMOS-SPEC-001 §9.1 and §9.2.

## Requirements under test

### Runtime (§9.1)
| ID | Requirement |
|----|-------------|
| R1 | Refuses to execute an artifact whose `spec_version` it does not recognise |
| R2 | Refuses to execute an artifact whose seal does not verify |
| R3 | Evaluates all rule operators defined in §4.2 |
| R4 | Returns ESCALATE for unrecognised operators rather than failing silently |
| R5 | Appends a hash-chained audit entry for every execution |
| R6 | Surfaces `contradictions` count in every verdict response |

### Producer (§9.2)
| ID | Requirement |
|----|-------------|
| P1 | Generates artifacts that validate against `schema/artifact.schema.json` |
| P2 | Seals artifacts using the procedure in §8 |
| P3 | Sets `confidence` correctly: DECLARED / VALIDATED / CERTIFIED |

## Running the suite

```bash
# TypeScript (Node.js)
npx tsx conformance/run.ts

# Python
python3 conformance/run.py
```

Both runners print a pass/fail table and exit with code 0 (all pass) or 1 (any fail).

## Fixture artifacts

| File | Purpose |
|------|---------|
| `fixtures/valid_declared.nomos` | Valid DECLARED artifact — all runtime tests should pass |
| `fixtures/valid_validated.nomos` | Valid VALIDATED artifact — confidence tier test |
| `fixtures/tampered_seal.nomos` | Seal hash is wrong — R2 must reject |
| `fixtures/unknown_spec_version.nomos` | spec_version is unrecognised — R1 must reject |
| `fixtures/unknown_operator.nomos` | Rule uses an operator not in §4.2 — R4 must escalate |
| `fixtures/missing_required_field.nomos` | Top-level required field omitted — P1 must reject |
