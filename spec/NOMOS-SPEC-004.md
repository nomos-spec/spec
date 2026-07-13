# NOMOS-SPEC-004: Composable Artifacts and Third-Party Attestations

**Status:** Active
**Version:** 1.4.0
**Extends:** NOMOS-SPEC-001 v1.0.0, NOMOS-SPEC-002 v1.1.0, NOMOS-SPEC-003 v1.3.1
**Published:** 2026-07-13
**Authors:** SafeHaven LLC / NOMOS Protocol Working Group
**spec_version string:** `"NOMOS-SPEC-004"`

---

## Abstract

Two capabilities are specified here, each optional and backward compatible with
the v1.0 artifact.

**Composable artifacts (`extends`).** In practice the same rule — "a teacher
needs a Bachelor's degree", "escalate cross-border transactions over
AED 10,000" — is copied across many artifacts. When the rule changes, every
copy must be found and edited by hand, and copies drift. This document defines
composition: a **base** artifact owns the shared rules, and a **child** artifact
declares `extends` and carries only its own **overlay** — the rules it
overrides, adds, or removes. The child's effective rule set is the base merged
with the overlay, resolved at **build time** into a single self-contained sealed
artifact. The runtime evaluates it unchanged, and it verifies offline without
the base. Lineage is recorded (not resolved) in a `composition` block.

**Third-party attestations (`attestations`).** A seal proves the issuing
authority produced an artifact and that it has not changed. It does not let an
*independent* party — a regulator, an auditor, the governing body — record that
they reviewed and stand behind a specific version. An attestation is a detached
signature, made with the attester's **own** key, over the artifact's seal hash.
It binds to exactly one version, travels with the file, is added *after* sealing
without disturbing the seal, and is verified with the attester's public key.

Neither feature changes how a sealed artifact evaluates. Composition is a
pre-seal transform; attestation is a post-seal annotation.

---

## 1. Composition

### 1.1 The `extends` overlay

A child artifact is produced from a base artifact and an **overlay**. The
overlay is the child's only original content:

```jsonc
{
  "decisions": [ /* SpecDecision[] — auto-classified against the base by id */ ],
  "removed":   [ "base_decision_id", ... ],   // base rules to drop
  "variables": { /* derived variables to add/override on the base's */ }
}
```

### 1.2 Merge algorithm (normative)

Given `base.logic.decisions` (ordered) and an overlay, a conformant composer
MUST produce the merged decision list deterministically as follows:

1. Index the overlay's `decisions` by `id`. Build the set `removed`.
2. Walk `base.logic.decisions` **in order**. For each base decision `b`:
   - if `b.id ∈ removed` → **drop** it (record under `removed`);
   - else if an overlay decision shares `b.id` → emit the **overlay** decision
     in `b`'s position (record under `overridden`);
   - else → emit `b` unchanged (record under `inherited`).
3. Append overlay decisions whose `id` has **no** base counterpart, in overlay
   order (record under `local`).
4. `logic.variables` = base variables merged with, and overridden by, overlay
   variables.

A `removed` id not present in the base is a no-op and MUST be recorded as a
warning, not an error. The algorithm MUST NOT depend on wall-clock time; given
the same base, overlay, and a pinned `composed_at`, output MUST be byte-identical.

### 1.3 The `composition` provenance block

A composed artifact carries an optional top-level `composition` object recording
what composition did. It is written **before** sealing, so it is covered by the
seal.

```jsonc
{
  "extends": { "artifact_id": "khda_teacher_base", "version": "2.0.0", "seal_hash": "…" },
  "parent_rule_count": 3,
  "inherited":  ["min_qualification"],
  "overridden": ["min_experience"],
  "removed":    ["police_clearance"],
  "local":      ["subject_specialization"],
  "composed_at": "2026-07-13T00:00:00Z",
  "warnings": []
}
```

`extends.seal_hash` pins the exact base version that was inherited.

### 1.4 Self-containment and re-composition

The sealed child is **self-contained**: its `logic.decisions` are the flattened
result, so a runtime needs nothing but the child, and a verifier needs nothing
but the child (§1.6). The base is a build input, not a runtime dependency.

"Change the shared rule once, everywhere" is therefore realised by
**re-composition**, not live indirection: when the base advances to a new
version, each child is re-composed against the new base **with its overlay
re-applied**. The updated base rules flow in; the child's overrides, additions,
and removals survive. A producer SHOULD surface a "base updated — re-compose"
signal analogous to a fork's upstream-drift indicator.

### 1.5 Cross-tree contradiction detection

Because composition flattens base and overlay into one decision set, a producer
MUST be able to run its contradiction analysis over the **merged** set before
sealing, so that a child override or addition that conflicts with an *inherited*
base rule is caught at composition time. A conflict whose participating rules
span both the inherited base and the child's contribution is a **cross-tree**
conflict and SHOULD be reported distinctly from conflicts wholly within the base.

### 1.6 Verification

A composed artifact is an ordinary sealed artifact. The seal covers the
flattened `logic` and the `composition` block. Verification is unchanged from
NOMOS-SPEC-001 §8 — recompute the JCS/SHA-256 hash and check the signature. No
access to the base is required.

---

## 2. Attestations

### 2.1 Placement — outside the seal

Attestations are added **after** sealing by parties **other** than the sealing
authority. They live in a top-level `attestations` array, sibling to `seal`.

> **Normative:** the seal-hash computation MUST exclude **both** `seal` and
> `attestations`. The seal covers the artifact minus these two fields. This is
> what allows an attestation to be appended (or removed) without invalidating
> the seal. Producers and verifiers that predate this document computed the hash
> excluding only `seal`; since a v1.0 artifact has no `attestations` field, the
> two computations coincide for all existing artifacts — the change is backward
> compatible.

### 2.2 The attestation object

```jsonc
{
  "attester":   { "name": "KHDA", "org_id": "27", "role": "regulator" },
  "statement":  "Reviewed and approved for AY2026",
  "artifact_hash":    "a3f9c1d2e4b5…",   // MUST equal the artifact's seal.hash
  "artifact_version": "1.2.0",
  "algorithm":  "Ed25519",
  "kid":        "…",                     // attester public-key id
  "signature":  "…",                     // base64 Ed25519 over the canonical payload
  "attested_at":"2026-07-13T00:00:00Z",
  "revoked_at": null
}
```

### 2.3 Signed payload (normative)

The signature is over `JCS({ artifact_hash, artifact_version, attester,
statement, attested_at })` — and nothing else. `algorithm`, `kid`, `signature`,
and `revoked_at` describe or annotate the signature and MUST NOT be part of the
signed message. Signer and verifier MUST reconstruct these bytes identically; a
producer MUST persist the exact `attested_at` string that was signed.

### 2.4 Binding and verification

An attestation is **bound** to a version iff `attestation.artifact_hash` equals
that artifact's `seal.hash`. A verifier MUST check **both**:

1. **signature** — `Ed25519.verify(payload, signature, attester_public_key)`;
2. **binding** — `artifact_hash == seal.hash`.

The binding check prevents replaying a genuine attestation onto a different
version. A verifier resolves the attester's public key by `kid`, discovered the
same way as seal keys (NOMOS-SPEC-001 §8.2): `GET /.well-known/nomos-signing-keys`
returns a key set; org-scoped attester keys carry an `org_id`.

### 2.5 Revocation

An attester MAY withdraw an attestation by setting `revoked_at`. A revoked
attestation remains cryptographically genuine (its signature still verifies) but
MUST be treated as not valid for the purpose of relying on it. Producers SHOULD
retain revoked attestations in an append-only ledger.

### 2.6 Trust in the key

Verification proves the holder of the attester key signed the version. Binding
that key to a real-world regulator is a separate, deployment-level concern —
today via TLS/DNS on the `.well-known` host, with a transparency-log anchor as a
stronger future option (NOMOS-SPEC-001 §10). Whether the attester holds its own
key or a platform custodies it on its behalf does not change the format or the
verification: only the public key is needed to verify.

---

## 3. Conformance

A producer or consumer MAY implement either feature independently; both are
optional. If `composition` is present, the merged `logic` MUST be consistent
with §1.2 against the referenced base. If `attestations` is present, every entry
MUST verify under §2.4 or be reported as invalid; a consumer MUST NOT treat an
unbound or signature-invalid attestation as an endorsement. A producer that
supports attestations MUST exclude `attestations` from the seal hash (§2.1).

## 4. Security Considerations

- **Composition does not launder authority.** A child that `extends` a base
  still stands on its own seal; inheriting a base rule is not a claim that the
  base's authority signed the child. The `composition.extends.seal_hash` records
  which base version was the input, for audit.
- **Attestations are additive, not gating.** Presence of an attestation does not
  change evaluation; absence does not block it. A relying party decides how much
  an attestation is worth.
- **Replay.** The binding check (§2.4) is mandatory precisely because a signed
  attestation is portable; without it, a valid attestation for version A could
  be presented alongside version B.
