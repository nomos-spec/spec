# NOMOS-SPEC-006: Artifact Revocation

**Status:** Draft  
**Version:** 1.6.0  
**Extends:** NOMOS-SPEC-001 v2.1.0, NOMOS-SPEC-004 v1.4.0  
**Published:** 2026-08-25  
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group

---

## Abstract

A seal (NOMOS-SPEC-001 §8) proves an artifact was produced by a given issuer and
has not been altered since. It says nothing about whether that issuer still
stands behind it *today*. Nothing in NOMOS-SPEC-001–005 lets an issuer say "this
specific sealed version should no longer be relied upon" — not a new version
superseding it, not an attestation being withdrawn, but the artifact's own
validity being pulled by the party that issued it: a compromised signing key, an
artifact sealed from corrupted source data, a legal or regulatory order to
withdraw a specific ruleset.

NOMOS-SPEC-003 §6's staleness signal is adjacent but not this: it is advisory
drift-since-triangulation, computed by the runtime, and it never affects the
verdict. NOMOS-SPEC-004 §2.5 is also adjacent but not this: it lets a *third
party* withdraw its own endorsement of a version it does not own; the artifact
itself, and the issuer's authority behind it, are untouched. Neither gives an
issuer a way to say "this artifact is no longer authoritative."

This document specifies that mechanism as a **detached signed statement** — not
a mutation of the sealed artifact — for the same reason NOMOS-SPEC-004
attestations are detached: the artifact's seal must never need to change after
sealing. It defines the statement (§3), a signed, dated aggregation of
statements for offline bulk-checking (§4, the CRL-equivalent), normative
verifier behavior including the honest handling of an unreachable or missing
revocation source (§5), and a cache-freshness hint for callers that hold a
verdict in memory across multiple decisions (§6).

Revocation is **issuer-only** in this version: only the key that sealed a
version may revoke it, mirroring NOMOS-SPEC-004 §2.5's attester-revokes-its-own
-attestation model exactly, so this document introduces no new authority
concept. Whether a governing body other than the original issuer should ever be
able to revoke — an authority-of-last-resort case — is out of scope for v1.6.0
and left for a future spec.

---

## Table of Contents

1. Terminology and Scope
2. Motivation
3. The Revocation Statement
4. The Revocation List
5. Verifier Behavior
6. Cache Freshness for Query Responses
7. Relationship to Deprecation (Non-Normative)
8. Conformance
9. Security Considerations
10. Examples

---

## 1. Terminology and Scope

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**,
**RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be
interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

**Revocation statement** — a detached, signed object asserting that one
specific sealed artifact version should no longer be relied upon (§3).

**Revocation list** — a signed, dated aggregation of revocation statements,
published for bulk and offline checking (§4).

**Issuer key** — the Ed25519 key that produced the `seal` on the artifact
version being revoked, identified by `kid` per NOMOS-SPEC-001 §8.4.

This document does not use the field name `revoked_at`. NOMOS-SPEC-004 §2.3
already defines `revoked_at` as an **unsigned** annotation added to an
already-signed attestation object. The revocation statement defined here is a
freshly signed document whose timestamp **is** part of the signed payload; using
the same field name for an opposite signing treatment in a sibling spec is a
predictable source of implementation error. This document uses `issued_at`
throughout, matching the naming pattern of `attested_at` in NOMOS-SPEC-004
§2.2.

---

## 2. Motivation

An artifact's seal answers *"did the named issuer produce this, unaltered?"* A
relying party executing decisions against a sealed artifact, or an offline
verifier checking one months later, is really asking a second question the
protocol has not answered until now: *"does the issuer still stand behind it?"*

Today that second question has no protocol-level answer. A Registry
implementation can mark a version `deprecated` in its own database, but nothing
about that state is signed, portable, or checkable by a verifier that only has
the `.nomos` file and no access to the issuing platform. An attester can revoke
its own attestation, but the artifact's own seal remains, unqualified, exactly
as trustworthy-looking as it was the day it was sealed — even if the issuer
has since discovered the signing key was compromised, or that the artifact was
sealed from corrupted behavioral data, or has been ordered by a regulator to
withdraw it.

This matters most for the case NOMOS-SPEC-005 exists to serve: a public,
keyless query against a published authority artifact, potentially cached by
the calling SDK, potentially verified fully offline months after sealing. A
protocol whose only answer to "has this been pulled?" is "ask the platform
directly, if you can reach it" does not serve the offline case at all, and
serves the online case no better than a database lookup that was never part of
the spec.

---

## 3. The Revocation Statement

### 3.1 Placement

A revocation statement is never embedded in, and never mutates, the artifact it
revokes. It is a standalone object, produced once by the issuer at the moment
of revocation. It MAY be handed to a specific relying party directly, and
SHOULD also be published in the issuer's revocation list (§4).

### 3.2 The revocation statement object

```jsonc
{
  "artifact_id":      "khda_teacher_licensing",
  "artifact_version": "1.2.0",
  "artifact_hash":    "a3f9c1d2e4b5…",   // MUST equal that version's seal.hash
  "reason":           "Signing key rotated after suspected compromise; all versions sealed under kid dGVzdC1r are withdrawn pending re-seal.",
  "algorithm":        "Ed25519",
  "kid":              "…",               // the ISSUER key that sealed the artifact — not a new revocation-specific key
  "signature":        "…",               // base64 Ed25519 over the canonical payload, §3.3
  "issued_at":        "2026-08-25T00:00:00Z"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `artifact_id` | string | REQUIRED | The artifact family being revoked. |
| `artifact_version` | string | REQUIRED | The exact version being revoked. Revocation is per-version; revoking `1.2.0` says nothing about `1.3.0`. |
| `artifact_hash` | string | REQUIRED | MUST equal the `seal.hash` of the version named above (binding check, §3.4). |
| `reason` | string | REQUIRED | Free-text, human-readable. This document does not mandate a closed enum; a deployment that needs machine-routed reasons MAY adopt its own controlled vocabulary as a documented convention, the same latitude NOMOS-SPEC-004 §2.2's `statement` field takes. |
| `algorithm` | string | REQUIRED | `"Ed25519"` in this version. |
| `kid` | string | REQUIRED | The key id of the **issuer** key that sealed the artifact being revoked, resolvable at `/.well-known/nomos-signing-keys` per NOMOS-SPEC-001 §8.4. |
| `signature` | string | REQUIRED | base64 Ed25519 signature over the canonical payload (§3.3). |
| `issued_at` | string (ISO 8601 UTC) | REQUIRED | When the statement was signed. Part of the signed payload — see §1's note on why this is not called `revoked_at`. |

### 3.3 Signed payload (normative)

The signature is over `JCS({ artifact_id, artifact_version, artifact_hash,
reason, issued_at })` — and nothing else. `algorithm`, `kid`, and `signature`
describe or annotate the signature and MUST NOT be part of the signed message.
A producer and a verifier MUST reconstruct these bytes identically.

### 3.4 Binding (normative)

A revocation statement is **bound** to a version iff `statement.artifact_hash`
equals that version's `seal.hash`. A verifier MUST check both:

1. `statement.artifact_hash == artifact.seal.hash` for the version being
   checked (binding).
2. The Ed25519 signature verifies against the public key resolved by
   `statement.kid` (authenticity).

An unbound statement (right `artifact_id`, wrong `artifact_hash`) MUST be
treated as not applicable to the version being verified, not as a revocation of
it. This is the same defense NOMOS-SPEC-004 §2.4 requires for attestations, for
the same replay reason: without it, a statement genuinely revoking version
`1.2.0` could be misapplied to `1.3.0`.

### 3.5 Only the issuer may revoke

`statement.kid` MUST resolve to the same key that produced `artifact.seal` on
the version being revoked. A verifier MUST reject a statement signed by any
other key — including a third-party attester's key from NOMOS-SPEC-004 — as not
a valid revocation, regardless of how well-intentioned. An attester who
disagrees with an artifact's continued validity has exactly one protocol-level
lever: revoke their own attestation (NOMOS-SPEC-004 §2.5). This version of the
protocol defines no mechanism for anyone other than the original issuer to
revoke an artifact.

---

## 4. The Revocation List

### 4.1 Purpose

The statement (§3) is the authoritative unit but does not solve discovery: a
verifier holding only a `.nomos` file has no way to learn a statement exists.
The revocation list is a published, signed aggregation an issuer maintains so
verifiers — online or offline — can check "has anything I might be holding been
revoked?" in one fetch.

### 4.2 Publication

A conformant issuer that supports revocation MUST publish its current list at:

```
GET /.well-known/nomos-revocations
```

sibling to the signing-keys endpoint defined in NOMOS-SPEC-001 §8.4.

### 4.3 The list object

```jsonc
{
  "generated_at": "2026-08-25T00:00:00Z",
  "algorithm":    "Ed25519",
  "kid":          "…",
  "statements":   [ /* zero or more revocation statement objects, §3.2, verbatim */ ],
  "signature":    "…"   // base64 Ed25519 over JCS({ generated_at, statements })
}
```

| Field | Type | Description |
|---|---|---|
| `generated_at` | string (ISO 8601 UTC) | When this list was assembled. Part of the signed payload. This is the freshness anchor §5 verifiers reason about — there is no separate `next_update` field in this version; see §9.3. |
| `statements` | array | Every currently-active revocation statement (§3.2) known to the issuer, verbatim, in any order. |
| `kid` / `signature` | — | Signs the list as a whole: `JCS({ generated_at, statements })`. This is in addition to, not instead of, each individual statement's own embedded signature — the list signature attests *completeness and currency as of `generated_at`*; each statement's own signature independently attests *authenticity of that one revocation* and remains verifiable even if extracted from the list. |

A list with an empty `statements` array is a normal, well-formed response: it
asserts "nothing has been revoked, as of `generated_at`," and MUST be signed
like any other list.

### 4.4 Scope

The list published by a given `/.well-known/nomos-revocations` endpoint covers
only artifacts sealed by keys belonging to that deployment. A verifier checking
an artifact from a different issuer MUST fetch that issuer's own list — there
is no cross-issuer aggregation in this version.

---

## 5. Verifier Behavior

### 5.1 When a revocation source is available

A verifier that can reach either a specific revocation statement (§3) or a
revocation list (§4) covering the artifact's issuer MUST:

1. Check binding and authenticity per §3.4.
2. If a bound, authentic statement exists for the exact `artifact_hash` being
   verified, report the artifact as **REVOKED** — a distinct result from
   `verified: false`. Revocation is not the same finding as a tampered or
   forged seal; a verifier MUST report which of the two occurred.
3. If checking a list, verify the list's own signature (§4.3) before trusting
   its contents. An individually-valid statement extracted from a list whose
   own signature does not verify MUST still be honored if it independently
   passes §3.4 — a corrupted list transport must not hide a genuine
   revocation — but the list as a whole MUST be reported as untrusted.

### 5.2 When no revocation source is available

Offline verification (NOMOS-SPEC-001 §8.5's `scripts/verify-nomos.mjs` model:
no network call, artifact and public key only) is a first-class use case this
protocol has always supported, and revocation checking MUST NOT break it by
becoming a silent hard requirement.

A verifier that has no revocation statement or list available MUST:

- Continue to report the seal's `hash_match` and `signature_valid` results
  exactly as NOMOS-SPEC-001 §8.5 defines them, unaffected by the absence of a
  revocation check.
- Print or return an explicit, unmissable notice that revocation was **not
  checked** and that the artifact's current standing with its issuer is
  therefore unknown — not merely omit a `revoked` field silently. A verifier
  MUST NOT represent an unchecked artifact as equivalent to one confirmed
  not-revoked.

This is a deliberate **fail-open-but-loud** design. A verifier that instead
fails closed whenever the revocation list is unreachable turns a transient
network problem, or the more common case of a genuinely offline verification
context, into a hard block on results that NOMOS-SPEC-001 already fully
supports verifying. The cost is pushed onto honesty of reporting instead: a
verifier MAY proceed, but MUST NOT claim more than it checked.

### 5.3 Reference implementation

`verify/verify.ts` in this repository extends its existing hash/signature
checks with an optional `--revocations <file>` flag accepting a downloaded
list (§4.3). Supplying it performs the check in §5.1; omitting it triggers the
§5.2 notice. This is the reference for the wording above, not a separate
requirement.

---

## 6. Cache Freshness for Query Responses

### 6.1 The gap this closes

NOMOS-SPEC-005 §1's public query response, and NOMOS-SPEC-001 §7's execution
response, are point-in-time: correct when issued, silent on how long a caller
holding the verdict in memory (an SDK cache, a gateway) may keep trusting it
without re-checking whether the underlying artifact has since been revoked.
NOMOS-SPEC-003 §6's `staleness_advisory` is not this signal — it reports drift
since triangulation, not revocation risk, and is silent for artifacts with no
triangulation baseline.

### 6.2 `max_age` (RECOMMENDED)

A NOMOS-SPEC-006-conformant query or execution response MAY include:

| Field | Type | Description |
|---|---|---|
| `max_age` | integer (seconds) | RECOMMENDED maximum time a caller SHOULD hold this verdict before re-querying or re-checking the issuer's revocation list. Absent `max_age`, callers SHOULD apply a conservative default (RECOMMENDED: 300 seconds) rather than caching indefinitely. |

`max_age` is advisory, like `staleness_advisory` — it MUST NOT be required for
conformance, and its absence is not an error. A runtime unable to derive a
meaningful value (no revocation-checking configured at all) SHOULD omit the
field entirely rather than emit a fixed value that implies a guarantee it is
not making.

This field is specified here rather than in NOMOS-SPEC-005 because its meaning
is defined entirely in terms of revocation risk; a runtime that does not
implement §3–5 has nothing to compute it from. Adding it to the
`public-query-response` and `execution-response` schemas is a schema change
tracked separately from this document (§8.1).

---

## 7. Relationship to Deprecation (Non-Normative)

Two unrelated things share the word "deprecation" across this protocol family,
and neither is revocation:

**Spec-version deprecation** (`DEPRECATION.md`) governs when a *specification
document itself* — e.g. NOMOS-SPEC-001 as a whole — moves toward end of life.
Its Principle 1 is explicit: "Sealed artifacts are forever valid... Deprecation
of a spec version never invalidates existing sealed artifacts." Revocation as
defined in this document is orthogonal: an artifact sealed under a fully
Active, fully supported spec version can still be individually revoked by its
issuer, and a spec version reaching end of life revokes nothing.

**Registry-level version deprecation** — an implementation-layer state (for
example, a Registry marking a `policyVersions` row `deprecated` when a newer
version of the same policy is activated) has no normative definition in this
spec family at all; it is a local lifecycle convenience, not a protocol
concept. A version in that state remains genuinely valid for verifying
decisions made under it unless separately, explicitly revoked per §3. A
Registry implementation MAY choose to auto-generate a revocation statement when
a version is superseded, but this document does not require or recommend that
— routine version supersession and "this should not have been relied upon" are
different claims, and collapsing them would make every ordinary version bump
indistinguishable from a security incident.

---

## 8. Conformance

A producer or verifier MAY implement revocation independently of every other
capability in this document; all of §3–6 are optional relative to
NOMOS-SPEC-001 baseline conformance.

1. **Statement correctness**: a produced revocation statement MUST satisfy
   §3.2–3.4 — correct field set, correct signed payload, `kid` resolving to the
   artifact's own issuer key.
2. **List signing**: a published revocation list MUST satisfy §4.3 — signed as
   a whole over `JCS({ generated_at, statements })`, with each contained
   statement independently valid per §3.
3. **Verifier reporting**: a verifier claiming NOMOS-SPEC-006 conformance MUST
   implement both branches of §5 — checking against an available source (§5.1)
   and the fail-open-but-loud notice when none is available (§5.2). A verifier
   that silently omits revocation checking without the §5.2 notice MUST NOT
   claim conformance to this document.
4. **No third-party revocation**: a verifier MUST reject a revocation statement
   whose `kid` does not resolve to the artifact's own issuer key (§3.5).

### 8.1 Known follow-on work

This document specifies the mechanism and normative verifier behavior. It does
not itself amend `schema/artifact.schema.json`, `schema/public-query-response
.schema.json`, or `schema/execution-response.schema.json` to add `max_age`
(§6.2), nor does it add the new `schema/revocation-statement.schema.json` and
`schema/revocation-list.schema.json` files implied by §3.2 and §4.3. Those are
tracked as separate, reviewable changes once this document's normative text is
accepted, consistent with how NOMOS-SPEC-004's schema additions followed its
own text.

---

## 9. Security Considerations

### 9.1 Issuer key compromise is now higher-stakes

Prior to this document, a compromised issuer signing key could be used to
forge new sealed artifacts. With revocation added, the same compromised key can
also be used to falsely revoke an issuer's legitimate artifacts, or — if the
attacker instead suppresses the legitimate issuer's ability to publish — to
prevent a real revocation from reaching verifiers. The key-protection guidance
in NOMOS-SPEC-001 §8 (secrets manager, never embedded in code or the artifact)
applies with correspondingly higher stakes once that key also carries
revocation authority.

### 9.2 Revocation is not deletion

A revoked artifact's historical decisions remain in the audit trail exactly as
they were. Revocation is forward-looking guidance to verifiers evaluating the
artifact's current standing — it does not, and cannot, retroactively alter what
a decision engine actually did at the time it acted under the artifact.
Confusing the two invites a false sense that revocation "undoes" past
decisions; it does not.

### 9.3 A withheld list is a real, disclosed gap

Signing the list (§4.3) proves it was produced by the issuer and has not been
altered in transit. It does **not** prove the list is complete or current — a
compromised or coerced host could serve an old, genuinely-signed list that
simply predates a real revocation, and a verifier checking only "does the
signature verify" would not detect this. `generated_at` gives a verifier the
input needed to apply its own staleness policy (e.g. "reject a list older than
24 hours"), but this document does not mandate a specific maximum, and does not
define a `next_update` commitment the way X.509 CRLs do. This is a real,
disclosed gap in this version, not a solved problem — see NOMOS-SPEC-001 §11's
Idempotency Gap for the precedent of naming a known limitation plainly rather
than implying it is handled.

### 9.4 Binding prevents cross-version replay

§3.4's binding check exists for the same reason NOMOS-SPEC-004 §2.4's does: an
`artifact_id`-only match (ignoring `artifact_hash`) would let a revocation
statement genuinely issued for one version be misapplied — accidentally or
maliciously — to a different version of the same artifact family.

---

## 10. Examples

### 10.1 A revocation statement — compromised key

```json
{
  "artifact_id": "khda_teacher_licensing",
  "artifact_version": "1.2.0",
  "artifact_hash": "a3f9c1d2e4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1",
  "reason": "Signing key suspected compromised 2026-08-24. All versions sealed under this kid are withdrawn pending re-seal under a rotated key.",
  "algorithm": "Ed25519",
  "kid": "dGVzdC1rZXktaWQ",
  "signature": "MEUCIQDx3f8k…",
  "issued_at": "2026-08-25T00:00:00Z"
}
```

### 10.2 A revocation list with one entry

```json
{
  "generated_at": "2026-08-25T00:05:00Z",
  "algorithm": "Ed25519",
  "kid": "dGVzdC1rZXktaWQ",
  "statements": [
    {
      "artifact_id": "khda_teacher_licensing",
      "artifact_version": "1.2.0",
      "artifact_hash": "a3f9c1d2e4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1",
      "reason": "Signing key suspected compromised 2026-08-24. All versions sealed under this kid are withdrawn pending re-seal under a rotated key.",
      "algorithm": "Ed25519",
      "kid": "dGVzdC1rZXktaWQ",
      "signature": "MEUCIQDx3f8k…",
      "issued_at": "2026-08-25T00:00:00Z"
    }
  ],
  "signature": "MEQCIF7a2b9c…"
}
```

### 10.3 An empty list — nothing revoked

```json
{
  "generated_at": "2026-08-25T00:05:00Z",
  "algorithm": "Ed25519",
  "kid": "dGVzdC1rZXktaWQ",
  "statements": [],
  "signature": "MEQCIB1d4e7f…"
}
```

### 10.4 Offline verification with no revocation source

```
$ node verify-nomos.mjs khda_teacher_licensing_v1.2.0.nomos --pubkey issuer.pem

[OK] Payload hash matches: a3f9c1d2e4b5c6d7...
[OK] Signature valid (Ed25519, kid: dGVzdC1rZXktaWQ)
[WARN] Revocation not checked — no --revocations file supplied and no network
       fetch was attempted. This artifact's current standing with its issuer
       is UNKNOWN. Seal integrity does not imply the issuer still stands
       behind this version. Supply --revocations <file> to check against a
       downloaded list.

VALID (seal only — revocation unchecked)
```
