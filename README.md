# NOMOS Protocol — Open Specification

[![Spec 001](https://img.shields.io/badge/spec-NOMOS--SPEC--001-blue)](spec/NOMOS-SPEC-001.md)
[![Spec 002](https://img.shields.io/badge/spec-NOMOS--SPEC--002-green)](spec/NOMOS-SPEC-002.md)
[![Spec 003](https://img.shields.io/badge/spec-NOMOS--SPEC--003-orange)](spec/NOMOS-SPEC-003.md)
[![Spec 004](https://img.shields.io/badge/spec-NOMOS--SPEC--004-blueviolet)](spec/NOMOS-SPEC-004.md)
[![Spec 005](https://img.shields.io/badge/spec-NOMOS--SPEC--005-yellow)](spec/NOMOS-SPEC-005.md)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Validate](https://github.com/nomos-spec/spec/actions/workflows/validate.yml/badge.svg)](https://github.com/nomos-spec/spec/actions/workflows/validate.yml)

The **NOMOS Protocol** defines an open, vendor-neutral format for packaging governance policies as sealed, machine-executable artifacts.

A `.nomos` file is a JSON document containing extracted policy rules, confidence metadata, and a cryptographic seal — signed with Ed25519 by default, so anyone can verify an artifact is authentic and unmodified offline, with the publisher's public key alone, no server call and no shared secret. Any compliant runtime can load a `.nomos` artifact and evaluate decisions against it — deterministically, without calling an AI model at runtime.


---

## Why

Governance policies live in PDFs. AI agents making decisions live in code. NOMOS is the translation layer: a compile step that converts natural-language policy into structured, auditable rules that machines can enforce without interpretation.

Think of a `.nomos` file the way you think of a `.pdf` file — except instead of capturing a document's visual layout for portable rendering, it captures an organisation's decision logic for portable execution. The meaning is collapsed into structure before runtime begins.

A `.nomos` artifact now moves through three distinct moments, not two:

**Compile-time**: A policy document is uploaded to NOMOS Studio. Rules are extracted and verified — optionally composed from a shared base artifact (SPEC-004). The result is sealed.

**Runtime**: Your system calls the NOMOS Runtime API (or runs the CLI locally). Rules are evaluated deterministically, respecting any temporal bounds (SPEC-003). Every verdict comes with an audit hash.

**Attest** *(optional, post-seal)*: An independent party — a regulator, an auditor — co-signs the exact sealed version with their own key (SPEC-004), without altering the artifact or its seal.

---

## Repository Contents

| Path | Description |
|------|-------------|
| `spec/NOMOS-SPEC-001.md` | Core protocol specification — rules, sealing, execution |
| `spec/NOMOS-SPEC-002.md` | Multi-agent extension — agents manifest, guard phases, constraints DSL |
| `spec/NOMOS-SPEC-003.md` | Temporal validity, staleness signalling, deterministic replay |
| `spec/NOMOS-SPEC-004.md` | Composable artifacts (`extends`) + third-party attestations |
| `schema/artifact.schema.json` | JSON Schema for `.nomos` artifact files |
| `schema/rule.schema.json` | JSON Schema for a single rule object |
| `examples/lending_policy_v1.nomos` | Example — public lending policy |
| `examples/healthcare_triage_v1.nomos` | Example — clinical triage protocol |
| `examples/minimal_v1.nomos` | Minimal valid artifact (structure check only) |
| `cli/nomos.ts` | NOMOS CLI — validate, verify, exec, diff, lint |
| `verify/verify.py` | Reference verifier (Python) |
| `verify/verify.ts` | Reference verifier (TypeScript/Node) |

---

## Quickstart

### TypeScript SDK (fastest path)

```bash
npm install @nomosprotocol/sdk
```

```typescript
import { Nomos } from '@nomosprotocol/sdk';

const nomos = new Nomos('nms_live_...');

const result = await nomos.decisions.verify({
  artifact_id:      'loan_approval_v1',
  decision_context: { credit_score: 720, loan_amount: 50_000 },
});

result.allowed            // true | false
result.verdict            // 'auto_approved' | 'auto_rejected' | 'escalated'
result.audit_record       // SHA-256 — store for compliance
```

Zero dependencies. Auto-retry. Full TypeScript types. Node ≥18.

---

### Install the CLI

```bash
git clone https://github.com/nomos-spec/spec.git nomos-spec
cd nomos-spec
npm install
```

### Validate structure

```bash
npx tsx cli/nomos.ts validate examples/lending_policy_v1.nomos
```

### Verify cryptographic seal

Production artifacts are sealed with **Ed25519** and are **publicly verifiable** — anyone checks the seal offline with the published public key, no secret and no call to the sealing authority:

```bash
# Fetch the public key once from /.well-known/nomos-signing-keys, then verify locally:
npx tsx verify/verify.ts <artifact.nomos> --url https://nomosprotocol.com
# …or fully offline with a pinned public key:
npx tsx verify/verify.ts <artifact.nomos> --pubkey signing_key.pub.pem
```

The verifier runs two independent, offline checks: **integrity** (recompute the JCS/SHA-256 hash) and **authenticity** (verify the Ed25519 signature against the public key for the seal's `kid`). Tampering the artifact fails the hash check; a forged or wrong-key signature fails authenticity. See §8 of NOMOS-SPEC-001.

> **Legacy:** The bundled `examples/` are older HMAC-SHA256 test artifacts (symmetric — not third-party verifiable), sealed with the public test key `deadbeef…`. Verify them with `--key deadbeef…`. HMAC is retained for backward compatibility only; new seals SHOULD be Ed25519.

### Execute a decision locally

```bash
npx tsx cli/nomos.ts exec examples/lending_policy_v1.nomos \
  --input '{"patron_age": 18, "account_standing": "good", "item_type": "book"}'
```

### Diff two artifact versions

```bash
npx tsx cli/nomos.ts diff examples/lending_policy_v1.nomos examples/lending_policy_v2.nomos
```

### Lint for quality warnings

```bash
npx tsx cli/nomos.ts lint examples/lending_policy_v1.nomos
```

### Evaluate a decision via the hosted runtime

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

### Verify an artifact (Python)

```bash
# Ed25519 (production) — verify with the published public key, offline:
python verify/verify.py <artifact.nomos> --url https://nomosprotocol.com   # or --pubkey key.pem
# Legacy HMAC example artifacts:
python verify/verify.py examples/lending_policy_v1.nomos \
  --key deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
```

(Ed25519 verification needs `pip install cryptography`; the Node verifier `verify/verify.ts` is zero-dependency.)

---

## Confidence Tiers

| Tier | ARI gate | Meaning |
|------|----------|---------|
| `DECLARED` | none | Rules extracted from policy documents only — no behavioral data required |
| `VALIDATED` | none | Rules triangulated against behavioral decision logs |
| `CERTIFIED` | none | Statistical validation passed; contradiction-free |
| `PROVEN` | ≥ 0.60 | ARI ≥ 60 confirmed; eligible for Exchange listing |
| `SOVEREIGN` | ≥ 0.75 | Highest tier; ARI ≥ 75, admin-verified, autonomous band confirmed |

---

## Multi-Agent Governance (SPEC-002)

NOMOS-SPEC-002 extends the artifact format with an optional `agents` manifest. This lets you embed agent authority and constraints directly inside the sealed artifact — so a runtime can enforce them without any external policy store.

```json
"agents": {
  "manifest_version": "1.0",
  "agents": [
    {
      "agent_id": "loan-review-agent",
      "display_name": "Loan Review Agent",
      "permissions": ["READ_RULES", "EVALUATE"],
      "cannot_call": ["SEAL", "MODIFY_RULES"],
      "constraints": [
        { "field": "risk_score", "operator": "lt", "value": 0.6 },
        { "field": "jurisdiction", "operator": "eq", "value": "US" }
      ],
      "audit_level": "full"
    }
  ]
}
```

### Constraints DSL

The `constraints` array is evaluated by the guard before rule evaluation (Phase 5). Each constraint specifies a field from the incoming request, an operator, and a threshold.

| Operator | Meaning |
|----------|---------|
| `lt` | less than |
| `lte` | at most (≤) |
| `gt` | greater than |
| `gte` | at least (≥) |
| `eq` | equals (any type) |
| `neq` | not equal (any type) |

Semantics:
- **Missing field** → skip (partial payloads don't fail)
- **Type mismatch** on numeric operators → skip
- **Violation in enforce mode** → `block`
- **Violation in advisory mode** → `escalate`

See `spec/NOMOS-SPEC-002.md §5.6` for the full specification.

---

## Seal Integrity

Every `.nomos` artifact carries a `seal` block. Ed25519 is the default, publicly verifiable form:

```json
"seal": {
  "status": "sealed",
  "canonicalization": "JCS",
  "signature_algorithm": "Ed25519",
  "kid": "<public-key-id>",
  "hash": "<sha256-of-canonical-payload>",
  "signed_by": { "name": "...", "org_id": "...", "role": "...", "timestamp": "..." },
  "signature": "<base64-ed25519-signature>"
}
```

The seal is computed over the artifact body canonicalized per [RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785), excluding the `seal` and `attestations` fields themselves. Any modification to any other field — including whitespace — produces a different hash and invalidates the signature. Verify offline with the publisher's public key at `/.well-known/nomos-signing-keys` — no secret required. Legacy `HMAC-SHA256` seals (symmetric, verifiable only by the issuer) remain valid but are not third-party verifiable.

See `spec/NOMOS-SPEC-001.md §8` for the full sealing procedure.

---

## Temporal Validity & Staleness (SPEC-003)

NOMOS-SPEC-003 lets a rule declare the window during which it's actually in force, and gives a runtime a way to say "this artifact hasn't been re-validated in a while" without blocking anything.

```json
{
  "id": "cross_border_threshold",
  "valid_from": "2026-01-01T00:00:00Z",
  "valid_until": "2026-12-31T23:59:59Z",
  "when": "...",
  "then": [ ... ]
}
```

A rule outside its window is skipped and traced in the audit record as `expired` — it's never silently ignored. Execution requests can also supply `execution_at`, replaying a decision as if it were evaluated at that historical instant — the same sealed artifact and inputs always produce the same verdict for a given point in time.

When an artifact has accumulated enough executions since it was last triangulated against real behavioral data, the runtime response carries a `staleness_advisory` — informational only, never a block:

```json
"staleness_advisory": {
  "triangulated_at": "2026-05-30T09:41:00Z",
  "decisions_since_triangulation": 503,
  "threshold": 500,
  "recommendation": "consider_retriangulation"
}
```

See `spec/NOMOS-SPEC-003.md` for the full specification.

---

## Composition & Attestation (SPEC-004)

NOMOS-SPEC-004 adds two independent capabilities: building an artifact from a shared base, and letting a third party co-sign one.

**Composition.** A child artifact declares `extends` and carries only its overlay — the rules it overrides, adds, or removes on top of a base:

```json
{
  "extends": { "artifact_id": "base_policy", "version": "2.0.0", "seal_hash": "..." },
  "overlay": {
    "decisions": [ { "id": "min_experience", "when": "...", "then": [ ... ] } ],
    "removed": ["some_base_rule_id"]
  }
}
```

Base and overlay resolve into one self-contained sealed artifact at build time — a runtime never needs the base to evaluate the child. When the base is updated, each child can re-compose against the new version with its overlay re-applied, so a shared rule changes once and propagates everywhere.

**Attestation.** A party other than the issuer signs a sealed version with their own key, over its seal hash:

```json
"attestations": [
  {
    "attester": { "name": "...", "org_id": "...", "role": "regulator" },
    "statement": "Reviewed and approved for AY2026",
    "artifact_hash": "<must equal seal.hash>",
    "algorithm": "Ed25519",
    "kid": "...",
    "signature": "...",
    "attested_at": "..."
  }
]
```

An attestation binds to one exact version — its `artifact_hash` must match the artifact's `seal.hash`, so it can't be replayed onto a different version — and is excluded from the seal-hash computation, so adding or revoking one never invalidates the seal.

See `spec/NOMOS-SPEC-004.md` for the full specification.

---

## Versioning

This repository tracks the NOMOS artifact format specification. Backward-incompatible changes increment the spec version (NOMOS-SPEC-002, etc.). The `spec_version` field inside every artifact records which version it was sealed against.

| Spec | Status | Summary |
|------|--------|---------|
| NOMOS-SPEC-001 | Active | Core rules, sealing, execution, conflict resolution |
| NOMOS-SPEC-002 | Active | Multi-agent manifest, guard phases, constraints DSL |
| NOMOS-SPEC-003 | Active | Temporal validity, staleness signalling, deterministic replay |
| NOMOS-SPEC-004 | Active | Composable artifacts (`extends`), third-party attestations |

---

## License

The NOMOS Protocol specification and schemas are released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implementations may be proprietary.

---

## Links

- Protocol site: [nomos.nomosprotocol.com](https://nomos.nomosprotocol.com)
- Hosted runtime: [nomosprotocol.com](https://nomosprotocol.com)
- Protocol Spec: [nomosprotocol.com/spec](https://nomosprotocol.com/spec)
- API Reference: [nomosprotocol.com/docs](https://nomosprotocol.com/docs)
- TypeScript SDK: [@nomosprotocol/sdk on npm](https://www.npmjs.com/package/@nomosprotocol/sdk)
- Studio: [nomosprotocol.com/studio](https://nomosprotocol.com/studio)
- Exchange: [nomosprotocol.com/exchange](https://nomosprotocol.com/exchange)
- MCP Server: [smithery.ai/servers/allan/nomos](https://smithery.ai/servers/allan/nomos)
