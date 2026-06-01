# NOMOS Protocol — Open Specification

The **NOMOS Protocol** defines an open, vendor-neutral format for packaging governance policies as sealed, machine-executable artifacts.

A `.nomos` file is a signed JSON document containing extracted policy rules, confidence metadata, and a cryptographic seal. Any compliant runtime can load a `.nomos` artifact and evaluate decisions against it — deterministically, without calling an AI model at runtime.

---

## Why

Governance policies live in PDFs. AI agents making decisions live in code. NOMOS is the translation layer: a compile step that converts natural-language policy into structured, auditable rules that machines can enforce without interpretation.

**Compile-time**: A policy document is uploaded to NOMOS Studio. Rules are extracted and verified. A `.nomos` artifact is sealed.

**Runtime**: Your system calls the NOMOS Runtime API. Rules are evaluated deterministically. Every verdict comes with an audit hash.

---

## Repository Contents

| Path | Description |
|------|-------------|
| `spec/NOMOS-SPEC-001.md` | Full protocol specification |
| `schema/artifact.schema.json` | JSON Schema for `.nomos` artifact files |
| `schema/rule.schema.json` | JSON Schema for a single rule object |
| `examples/lending_policy_v1.nomos` | Example — public lending policy |
| `examples/healthcare_triage_v1.nomos` | Example — clinical triage protocol |
| `verify/verify.py` | Reference verifier (Python) |
| `verify/verify.ts` | Reference verifier (TypeScript/Node) |

---

## Quickstart

### Verify an artifact (Python)
```bash
# No external dependencies needed for the verifier
python verify/verify.py examples/lending_policy_v1.nomos \
  --key deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
```

### Verify an artifact (TypeScript)
```bash
npx tsx verify/verify.ts examples/lending_policy_v1.nomos \
  --key deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
```

> **Note:** The example artifacts in `examples/` are sealed with the public test key above (`deadbeef...`). Production artifacts use a private `NOMOS_SEAL_KEY` held by the sealing authority.

### Evaluate a decision locally
```bash
curl -X POST https://nomosprotocol.com/api/nomos/execute \
  -H "x-api-key: <key>" \
  -H "Content-Type: application/json" \
  -d '{
    "artifactId": "lending_policy_v1",
    "context": {
      "patron_age": 18,
      "account_standing": "good",
      "item_type": "reference"
    }
  }'
```

---

## Confidence Tiers

| Tier | Meaning |
|------|---------|
| `DECLARED` | Rules extracted from policy documents only |
| `CERTIFIED` | Rules triangulated against behavioral decision logs; statistical validation passed |

---

## Seal Integrity

Every `.nomos` artifact carries a `seal` block:

```json
"seal": {
  "algorithm": "HMAC-SHA256",
  "ts": "2026-01-15T10:30:00.000Z",
  "hash": "<sha256-of-canonical-payload>",
  "sig": "<hmac-sha256-of-hash>"
}
```

The seal is computed over the artifact body canonicalized per [RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785). Any modification to any field — including whitespace — produces a different hash and invalidates the signature.

See `spec/NOMOS-SPEC-001.md §8` for the full sealing procedure.

---

## Versioning

This repository tracks the NOMOS artifact format specification. Backward-incompatible changes increment the spec version (NOMOS-SPEC-002, etc.). The `spec_version` field inside every artifact records which version it was sealed against.

---

## License

The NOMOS Protocol specification and schemas are released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implementations may be proprietary.

---

## Links

- Hosted runtime: [nomosprotocol.com](https://nomosprotocol.com)
- Protocol Spec: [nomosprotocol.com/spec](https://nomosprotocol.com/spec)
- API Reference: [nomosprotocol.com/docs](https://nomosprotocol.com/docs)
