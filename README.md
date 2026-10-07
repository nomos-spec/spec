# NOMOS Protocol — Open Specification

[![Spec 001](https://img.shields.io/badge/spec-NOMOS--SPEC--001-blue)](spec/NOMOS-SPEC-001.md)
[![Spec 002](https://img.shields.io/badge/spec-NOMOS--SPEC--002-green)](spec/NOMOS-SPEC-002.md)
[![Spec 003](https://img.shields.io/badge/spec-NOMOS--SPEC--003-orange)](spec/NOMOS-SPEC-003.md)
[![Spec 004](https://img.shields.io/badge/spec-NOMOS--SPEC--004-blueviolet)](spec/NOMOS-SPEC-004.md)
[![Spec 005](https://img.shields.io/badge/spec-NOMOS--SPEC--005-yellow)](spec/NOMOS-SPEC-005.md)
[![Spec 006](https://img.shields.io/badge/spec-NOMOS--SPEC--006-red)](spec/NOMOS-SPEC-006.md)
[![Spec 007 Draft](https://img.shields.io/badge/spec-NOMOS--SPEC--007%20(Draft)-lightgrey)](spec/NOMOS-SPEC-007.md)
[![Spec 008 Draft](https://img.shields.io/badge/spec-NOMOS--SPEC--008%20(Draft)-lightgrey)](spec/drafts/NOMOS-SPEC-008.md)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Validate](https://github.com/nomos-spec/spec/actions/workflows/validate.yml/badge.svg)](https://github.com/nomos-spec/spec/actions/workflows/validate.yml)
[![IANA Media Type](https://img.shields.io/badge/IANA-application%2Fvnd.nomos%2Bjson-brightgreen)](https://www.iana.org/assignments/media-types/application/vnd.nomos+json)

The **NOMOS Protocol** defines an open, vendor-neutral format for packaging governance policies as sealed, machine-executable artifacts.

A `.nomos` file is a JSON document containing extracted policy rules, confidence metadata, and a cryptographic seal — signed with Ed25519 by default, so anyone can verify an artifact is authentic and unmodified offline, with the publisher's public key alone, no server call and no shared secret. Any compliant runtime can load a `.nomos` artifact and evaluate decisions against it — deterministically, without calling an AI model at runtime.

NOMOS is one implementation of **[computable authority](https://computableauthority.com)** — the discipline of making institutional policy directly executable by AI systems, rather than interpreted after the fact.

Agents increasingly act on behalf of organisations — a bank, a hospital, a ministry, a supplier. A service an agent calls needs more than "this is an agent": it needs to know who the agent acts for, what it is allowed to do, and whether it can check that without calling anyone. NOMOS-SPEC-001 through 008 specify that, end to end: the institution's rules as a sealed artifact (001–006), the chain of certificates that lets a stranger recognize the issuer (007), and the **Act** (008) — a self-verifying package that binds one exact action to those rules, to signed facts from authorized witnesses, and to human consents, so the system that would make the change verifies it locally and commits exactly that change or nothing.

---

## Why

Governance policies live in PDFs. AI agents making decisions live in code. NOMOS is the translation layer: a compile step that converts natural-language policy into structured, auditable rules that machines can enforce without interpretation.

Think of a `.nomos` file the way you think of a `.pdf` file — except instead of capturing a document's visual layout for portable rendering, it captures an organisation's decision logic for portable execution. The meaning is collapsed into structure before runtime begins.

A `.nomos` artifact now moves through four distinct moments:

**Compile-time**: A policy document is uploaded to NOMOS Studio. Rules are extracted and verified — optionally composed from a shared base artifact (SPEC-004). The result is sealed.

**Runtime**: Your system calls the NOMOS Runtime API (or runs the CLI locally). Rules are evaluated deterministically, respecting any temporal bounds (SPEC-003). Every verdict comes with an audit hash.

**Attest** *(optional, post-seal)*: An independent party — a regulator, an auditor — co-signs the exact sealed version with their own key (SPEC-004), without altering the artifact or its seal.

**Act** *(at the point of change)*: An agent presents an Act to the system that would make the change — a ledger, a registry, an API. That relying party verifies the issuer's chain (SPEC-007), the facts as signed testimony, any required consents, and the rules over exactly those facts (SPEC-008). A fact the Act does not establish is unknown, never false; nothing commits while an unknown fact could still change the outcome.

---

## Repository Contents

| Path | Description |
|------|-------------|
| `spec/NOMOS-SPEC-001.md` | Core protocol specification — rules, sealing, execution |
| `spec/NOMOS-SPEC-002.md` | Multi-agent extension — agents manifest, guard phases, constraints DSL |
| `spec/NOMOS-SPEC-003.md` | Temporal validity, staleness signalling, deterministic replay |
| `spec/NOMOS-SPEC-004.md` | Composable artifacts (`extends`) + third-party attestations |
| `spec/NOMOS-SPEC-005.md` | Public query extension — keyless authority queries, permanent transcripts |
| `spec/NOMOS-SPEC-006.md` | Artifact revocation — detached issuer-signed statements, signed revocation list, `max_age` |
| `spec/NOMOS-SPEC-007.md` | **Draft.** Chain-of-trust key certificates — recognizing an artifact's issuer with no prior relationship and no call home, with enforced delegation scope |
| `schema/artifact.schema.json` | JSON Schema for `.nomos` artifact files |
| `schema/rule.schema.json` | JSON Schema for a single rule object |
| `schema/revocation-statement.schema.json` | JSON Schema for a NOMOS-SPEC-006 artifact revocation statement |
| `schema/revocation-list.schema.json` | JSON Schema for a NOMOS-SPEC-006 revocation list |
| `schema/key-certificate.schema.json` | JSON Schema for a NOMOS-SPEC-007 key certificate |
| `schema/chain-verification-request.schema.json` | JSON Schema for a NOMOS-SPEC-007 `POST /verify` request |
| `schema/chain-verification-response.schema.json` | JSON Schema for a NOMOS-SPEC-007 `POST /verify` response |
| `schema/chain-revocation-statement.schema.json` | JSON Schema for a NOMOS-SPEC-007 chain-key revocation statement |
| `schema/chain-revocation-list.schema.json` | JSON Schema for a NOMOS-SPEC-007 chain-key revocation list |
| `prototype/chain-of-trust/` | NOMOS-SPEC-007's pure reference implementation — key certificates, chain verification, a CLI verifier, a minimal HTTP receiver/presenter pair |
| `chain-of-trust-vectors/` | NOMOS-SPEC-007 fixed interop test vectors — for a second implementer to check their verifier against |
| `spec/drafts/NOMOS-SPEC-008.md` | **Draft.** Act Binding — an action bound to sealed rules, signed testimony and human consents, verified by the relying party that would commit it |
| `spec/drafts/NOMOS-SPEC-007-rev-1.8.0.md` | **Draft revision.** SPEC-007 1.8.0 — statement keys (witness `claim`, approver `consent` scopes) and target-first chain resolution |
| `spec/drafts/NOMOS-SPEC-001-amendment-2.2.0.md` | **Draft amendment.** SPEC-001 2.2.0 — unmatched outcome, declared fact sources, consent counts |
| `act-vectors/` | NOMOS-SPEC-008 reference verifier (`act_verify.py`), deterministic generator, and 23 test vectors |
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

## Chain of Trust & Act Binding (SPEC-007, SPEC-008)

Together these answer the question a service asks when an agent arrives acting for an organisation: *on whose authority, to do what, and can I check it myself?*

**SPEC-007 — recognizing the issuer.** A key certificate lets one key certify another to sign, within a scope, until an expiry. A verifier pins its own root and resolves the chain offline — no prior relationship with the issuer, no call home. Revision 1.8.0 (draft) extends the same certificates to the keys that state facts (`claim` scope, for witnesses such as a credit bureau) and the keys that approve (`consent` scope, for human approvers), and resolves chains target-first so the verdict never depends on the order certificates are presented in.

**SPEC-008 — binding the action.** A verdict computed over caller-supplied facts is advice; nothing ties it to the change made later. An Act closes four gaps an agent could otherwise exploit without breaking any cryptography:

| Gap | How the Act closes it |
|-----|-----------------------|
| Skipping the check | The relying party — the system that would make the change — demands and verifies the Act itself |
| Lying to the check | Each fact comes from the channel its input declares: the action, the relying party's own state, or signed testimony from a witness whose key is certified for that claim — and has the type its input declares, so a wrong-typed value cannot make a deny rule fall silent |
| Changing the action after the check | Consents are signed over the Act's binding digest; a changed amount invalidates them |
| Withholding a fact | Evaluation is three-valued: a missing fact is undecided, never false, and the verdict is `INCOMPLETE` while an outranking block or escalate rule is undecided; `exists()` treats absence as decided only for the action and the relying party's own state |

An agent is free to bypass every NOMOS component. Its act still cannot take effect, because the only system able to make the change is the one that demands the proof.

```bash
cd act-vectors
pip install cryptography
python3 check.py vectors.json        # 25 passed: 23 vectors + 2 non-finite cases
```

See `spec/drafts/NOMOS-SPEC-008.md` for the full specification and `act-vectors/README.md` for every case.

---

## Versioning

This repository tracks the NOMOS artifact format specification. Backward-incompatible changes to a published spec require a new spec number ([DEPRECATION.md](DEPRECATION.md)); new capabilities are published as new numbered extensions. Every artifact carries a fixed `nomos_version` (currently `"1.0.0"`) identifying the base container format (NOMOS-SPEC-001 §3.2); extensions like NOMOS-SPEC-002's `agents` manifest are detected structurally, by the presence of their own field, not by a separate per-extension version marker.

| Spec | Status | Summary |
|------|--------|---------|
| NOMOS-SPEC-001 | Active | Core rules, sealing, execution, conflict resolution |
| NOMOS-SPEC-002 | Active | Multi-agent manifest, guard phases, constraints DSL |
| NOMOS-SPEC-003 | Active | Temporal validity, staleness signalling, deterministic replay |
| NOMOS-SPEC-004 | Active | Composable artifacts (`extends`), third-party attestations |
| NOMOS-SPEC-005 | Draft | Public query extension — keyless authority queries, permanent transcripts |
| NOMOS-SPEC-006 | Active | Artifact revocation — detached issuer-signed statements, signed revocation list |
| NOMOS-SPEC-007 | Draft | Chain-of-trust key certificates — an independent system recognizing an artifact's issuer with no prior relationship and no call home, with enforced delegation scope |
| NOMOS-SPEC-008 | Draft | Act Binding — an exact action bound to sealed rules, signed testimony and human consents; verified by the relying party; three-valued evaluation with an `INCOMPLETE` verdict |

Proposed revisions awaiting promotion live in [`spec/drafts/`](spec/drafts/): NOMOS-SPEC-001 amendment 2.2.0 and NOMOS-SPEC-007 revision 1.8.0, both required by NOMOS-SPEC-008.

NOMOS-SPEC-007 and NOMOS-SPEC-008 are built and running.

- **SPEC-007:** the pure reference implementation in
  [`prototype/chain-of-trust/`](prototype/chain-of-trust/) and the hosted platform's verifier
  (`POST /api/v1/chain-of-trust/verify`) both pass all 14 vectors in
  [`chain-of-trust-vectors/`](chain-of-trust-vectors/).
- **SPEC-008:** the Python reference verifier in [`act-vectors/`](act-vectors/) and the
  platform's TypeScript verifier both pass all 23 vectors. The platform's budget ledger accepts a
  verified Act as the authority for a reservation.

Both are published as Drafts because a standard is promoted on independent implementation —
[§8 of SPEC-007](spec/NOMOS-SPEC-007.md#8-conformance-and-implementation-status) and §10 of
SPEC-008 set out the conformance requirements.

**Second-party implementations are invited.** If you build agents or the services they call,
implement SPEC-007 or SPEC-008 against the vectors and open an issue, or email
allan@nomosprotocol.com.

---

## License

The NOMOS Protocol specification and schemas are released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implementations may be proprietary.

---

## Links

- Computable Authority (the discipline NOMOS implements): [computableauthority.com](https://computableauthority.com)
- Protocol site: [nomos.nomosprotocol.com](https://nomos.nomosprotocol.com)
- Hosted runtime: [nomosprotocol.com](https://nomosprotocol.com)
- Protocol Spec: [nomosprotocol.com/spec](https://nomosprotocol.com/spec)
- API Reference: [nomosprotocol.com/docs](https://nomosprotocol.com/docs)
- TypeScript SDK: [@nomosprotocol/sdk on npm](https://www.npmjs.com/package/@nomosprotocol/sdk)
- Studio: [nomosprotocol.com/studio](https://nomosprotocol.com/studio)
- Exchange: [nomosprotocol.com/exchange](https://nomosprotocol.com/exchange)
- MCP Server: [smithery.ai/servers/allan/nomos](https://smithery.ai/servers/allan/nomos)
