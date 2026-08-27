# NOMOS-SPEC-007: Chain-of-Trust Key Certificates

**Status:** Draft
**Version:** 1.7.0
**Extends:** NOMOS-SPEC-001 v2.1.0
**Published:** 2026-08-27
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group

---

## Abstract

Every trust mechanism NOMOS-SPEC-001 through NOMOS-SPEC-006 define resolves a key the same
way: a flat lookup, published from one place — `/.well-known/nomos-signing-keys` for seals
(NOMOS-SPEC-001 §8.4), an org's own published key for an attestation (NOMOS-SPEC-004), the
artifact's own issuer key for a revocation (NOMOS-SPEC-006 §3.5). That is sufficient when the
relying party already knows to ask a specific deployment. It does not generalize to a foreign
system that has never heard of that deployment and has no reason to call it.

[Paper 5 — "Bounded Contextual Authority"](https://www.nomosprotocol.com/paper-5) names this gap
precisely (its R-08 finding): none of the existing mechanisms let an **independent system with no
prior relationship to the issuer** recognize that issuer, live, at the moment of an action,
without a call home. This document specifies the primitive that closes it — a **key
certificate**: one key certifying that another key is authorized to sign, within an optional
scope and until an expiry, chained back to a root the relying party has independently decided to
trust. The verification is resolved entirely from the presented material and one pinned public
key; no directory lookup, no prior registration of the artifact, no network call is required to
reach a verdict.

This is deliberately the same delegation pattern a browser uses against its pinned root
certificate store, adapted to NOMOS's existing primitives: Ed25519 signatures, RFC 8785 JSON
Canonicalization (JCS), and the same detached-statement discipline NOMOS-SPEC-004 (attestation)
and NOMOS-SPEC-006 (revocation) already established — an artifact's own seal never changes as a
result of anything defined here.

A key certificate answers a structurally different question than a NOMOS-SPEC-004 attestation.
An attestation is additive and advisory: its presence or absence never gates evaluation
(NOMOS-SPEC-004 §4). A key certificate is the opposite — it is exactly the mechanism that
determines whether an issuer is recognized **at all**. Conflating an advisory and a gating trust
semantic in one object type, despite their identical cryptographic shape, would be a real design
defect; this document defines a deliberate sibling object instead of a `subject` discriminator on
the attestation object.

**Status of this document.** This is a Draft, published with a complete, tested reference
implementation, specifically to invite the thing a Draft is for: independent implementation and
scrutiny before anything here is claimed as interoperable infrastructure. §8 states plainly what
is and is not yet true. In particular: **this specification has exactly one implementation
(the reference one). No claim of interoperability is made or should be inferred until a second,
independent implementation exists.**

---

## Table of Contents

1. Terminology and Scope
2. Motivation
3. The Key Certificate
4. Chain Verification
5. Key Revocation
6. The Verification Request/Response
7. Combining Chain Verification with Rule Evaluation
8. Conformance and Implementation Status
9. Relationship to Root Governance (Non-Normative)
10. Security Considerations
11. Examples

---

## 1. Terminology and Scope

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, **RECOMMENDED**,
**MAY**, and **OPTIONAL** in this document are to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

**Key certificate** — a detached, Ed25519-signed statement that one key (the *parent*) certifies
another key (the *child*) as authorized to sign, until an expiry (§3).

**Chain** — an unordered set of key certificates presented alongside a sealed artifact, intended
to connect the artifact's own signing key back to a root the relying party trusts (§4).

**Root key** — the public key a relying party has independently and out-of-band decided to
trust as the anchor for a given verification. This document defines no default root of any
kind, anywhere. See §9 for why that is a deliberate scope boundary, not an oversight.

**Relying party** — the system deciding whether to honor a presented artifact and chain. Not
necessarily the artifact's original issuer, and by construction has no prior relationship to it.

**Presenter** — the system or agent holding a sealed artifact and a chain, offering both to a
relying party.

This document specifies the certificate object (§3), the algorithm a relying party uses to
resolve a presented chain to a verdict (§4), a revocation mechanism for a certified key (§5), and
a minimal HTTP request/response shape for presenting a chain (§6). §7 specifies how chain
verification composes with rule evaluation so that a successful verdict answers "is this action
permitted," not only "is this artifact's issuer recognized." All of it is **additive**: nothing
in NOMOS-SPEC-001–006 changes, and a runtime implementing only those documents remains fully
conformant without any part of this one.

---

## 2. Motivation

Consider an AI agent that receives a sealed `.nomos` artifact from a counterparty it has never
dealt with before — another organization's agent, a marketplace listing, a message attachment.
The agent's own runtime has no record of this artifact and no relationship with whoever sealed
it. Two questions need answering before the agent can act on it: is this artifact genuinely from
who it claims to be from, and does it actually authorize the action in question?

Every existing NOMOS mechanism answers a version of the first question only by first establishing
*where to look* — a `/.well-known/nomos-signing-keys` endpoint belonging to a specific,
already-known deployment. An artifact arriving cold, from an issuer the relying party has never
configured a lookup for, cannot be resolved that way at all. The relying party's only options
today are: trust it unconditionally (unacceptable), reject everything unfamiliar (defeats the
purpose of a portable artifact), or call back to some central NOMOS registry to ask "do you know
this issuer?" — which reintroduces exactly the mediated, always-online dependency a portable,
offline-verifiable artifact (NOMOS-SPEC-001 §8.5) was designed to avoid.

A certificate chain resolves this the way a public-key infrastructure resolves it for TLS: the
relying party does not need to know the leaf issuer in advance, only a root it has decided to
trust, plus a chain of certificates connecting the two. This document specifies exactly that
primitive for NOMOS artifacts — nothing more. It does not specify who should operate a shared
root (§9), which is named explicitly as unresolved rather than silently assumed away.

---

## 3. The Key Certificate

### 3.1 The certificate object

```jsonc
{
  "parent_kid":            "V3HqL9zM2Nk4pQrT",
  "child_kid":              "8kR2Xw5dF7hJmN1s",
  "child_public_key_pem":  "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "scope":                  "industry:financial/lending",
  "issued_at":              "2026-08-27T00:00:00Z",
  "expires_at":             "2027-08-27T00:00:00Z",
  "algorithm":              "Ed25519",
  "signature":              "MEUCIQD…"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `parent_kid` | string | REQUIRED | Key id of the CERTIFYING key (a root or an intermediate), computed per NOMOS-SPEC-001 §8.4's convention: `base64url(SHA-256(SPKI DER))`, first 16 characters. |
| `child_kid` | string | REQUIRED | Key id of the key being certified. MUST equal `computeKid(child_public_key_pem)` — a verifier MUST NOT trust a `child_kid` that does not match the material actually carried in this same certificate (§4.2). |
| `child_public_key_pem` | string | REQUIRED | The certified key's own public key material, carried inline. There is no central directory to resolve it from — that absence is the entire point of a chain that verifies without calling home. |
| `scope` | string | OPTIONAL | The delegation's limits, enforced per §3.4. Absent means unrestricted. |
| `issued_at` | string (ISO 8601 UTC) | REQUIRED | When this statement was signed. Part of the signed payload. |
| `expires_at` | string (ISO 8601 UTC) | REQUIRED | When this certificate stops being valid. Part of the signed payload. A certificate has no revocation mechanism of its own short of expiry, other than key revocation (§5). |
| `algorithm` | string | REQUIRED | `"Ed25519"` in this version. |
| `signature` | string | REQUIRED | base64 Ed25519 signature over the canonical payload (§3.2), produced with the **parent's** private key. |

This document does not use `revoked_at`. NOMOS-SPEC-004 §2.3 already defines `revoked_at` as an
**unsigned** annotation added to an already-signed object; a key certificate's `issued_at` is
itself signed content, the same treatment NOMOS-SPEC-006 §1 gives its own `issued_at` — checked
against that prior naming collision before reuse here, not assumed safe.

### 3.2 Signed payload (normative)

The signature is over `JCS({ parent_kid, child_kid, child_public_key_pem, scope, issued_at,
expires_at })`, where `scope` is `null` when absent — and nothing else. `algorithm` and
`signature` describe or carry the signature and MUST NOT be part of the signed message. A
producer and a verifier MUST reconstruct these bytes identically; see NOMOS-SPEC-001 §8.2 for the
canonicalization algorithm (RFC 8785 JCS) this reuses without modification.

### 3.3 Verifying one certificate (normative)

Given a certificate and a caller-supplied parent public key, a verifier MUST:

1. Recompute `child_kid` from `child_public_key_pem` and reject the certificate if it does not
   match the certificate's own `child_kid` field.
2. Verify the Ed25519 signature over the payload in §3.2 against the supplied parent public key.
3. Reject the certificate if `now > expires_at` or `now < issued_at`.

This check resolves nothing about trust by itself — it only establishes that *this one*
certificate is a genuine, unexpired statement by whoever holds the named parent's private key.
§4 defines how a sequence of these becomes an actual trust decision.

---

### 3.4 Scope (normative)

A certificate's `scope` states the limits of the delegation. It is part of the signed payload
(§3.2), so it cannot be altered without invalidating the certificate.

**Grammar.** A scope is a space-separated set of `dimension:value` terms, ALL of which must hold.
A dimension MUST NOT appear more than once. An absent or empty scope means UNRESTRICTED. A
verifier MUST reject a malformed scope rather than ignoring the unparseable terms — a partially
parsed scope would grant more than its author wrote.

**Dimensions.** This version defines exactly two, both matched against fields the artifact itself
declares:

| Dimension | Matched against | Comparison |
|---|---|---|
| `artifact` | `meta.artifact_id` | Exact equality only. Never a prefix or glob. |
| `industry` | `meta.industry` | Hierarchical, `/`-delimited: `financial` contains `financial/lending`. A match MUST fall on a segment boundary, so `financial` does NOT contain `financial-services`. |

`jurisdiction` is deliberately absent. Real artifacts carry jurisdictions as free prose ("State of
California", "NHS England"); a matcher over free prose would pass silently when an issuer writes a
variant spelling, which is worse than not enforcing it. Jurisdiction scoping awaits a normalized
identifier — see §8.2.

**Fail closed, in two directions (normative).**

1. If a scope constrains a dimension the artifact does not declare, the artifact is OUT of scope.
   "You were authorized only for financial services, and this artifact does not say what it
   covers" is not a pass.
2. If a scope constrains a dimension the verifier does not recognize, the artifact is OUT of
   scope. A verifier MUST NOT skip a constraint it cannot evaluate. This mirrors X.509's critical
   extension rule: silently ignoring an unknown constraint would make every dimension added by a
   future revision unenforceable against existing verifiers.

**Narrowing is monotonic (normative).** The effective scope of a chain is the accumulation of
every certificate's scope along it — the union of their terms, which is the intersection of the
artifact sets they denote. Accumulation, not replacement, is what prevents a later certificate
shedding an earlier constraint by simply not mentioning it.

A certificate MAY constrain a dimension its parent leaves unconstrained, and MAY narrow a
dimension its parent constrains. It MUST NOT widen one. A verifier encountering a widening
certificate MUST fail the path with `OUT_OF_SCOPE` rather than silently intersecting it: a
certificate that grants more than its issuer holds is a misissuance the relying party needs to
see, and X.509 name constraints set the precedent of failing the path rather than repairing it.

Omitting a narrowing certificate is not an escape route: the walk (§4.2) links certificates by
kid, so a chain missing a link simply fails to resolve (`ISSUER_NOT_RECOGNIZED`) rather than
resolving under the broader parent grant.

**Ordering.** Scope MUST be evaluated only against a certificate whose signature has already
verified (§3.3). An unverified certificate's scope string is attacker-supplied text.

---

## 4. Chain Verification

### 4.1 Inputs

A relying party evaluating a presented chain has three inputs: the sealed artifact being
presented, the chain (a set of key certificates, §3), and a root public key the relying party has
independently pinned. The root key is never part of the presented material — see §9.

### 4.2 The walk (normative algorithm)

Let `target_kid` be the `kid` on the presented artifact's own `seal` (NOMOS-SPEC-001 §8.4). A
verifier MUST resolve the chain as follows:

1. Compute `root_kid` from the pinned root public key. Set `current_kid = root_kid`,
   `current_key = <pinned root public key>`, and an empty `visited` set.
2. While `current_kid != target_kid`:
   a. If `current_kid` is already in `visited`, halt with **ISSUER_NOT_RECOGNIZED** (reason:
      `cycle`) — the chain does not terminate.
   b. Add `current_kid` to `visited`.
   c. Find a certificate in the remaining chain whose `parent_kid == current_kid`. If none
      exists, halt with **ISSUER_NOT_RECOGNIZED** (reason: `no_certificate_for_root` if
      `current_kid == root_kid`, else `chain_broken`).
   d. Verify that certificate per §3.3 against `current_key`. If it fails, halt with
      **ISSUER_NOT_RECOGNIZED**, carrying the specific reason (`bad_signature` / `expired` /
      `not_yet_valid`).
   e. Set `current_kid = certificate.child_kid`, `current_key = certificate.child_public_key_pem`.
3. Verify the artifact's own seal (NOMOS-SPEC-001 §8) against `current_key`. A hash mismatch or
   signature failure here is **SEAL_INVALID**, never `ISSUER_NOT_RECOGNIZED` — see §4.4.
4. Otherwise, the verdict is **ALLOWED**.

### 4.3 Order independence (normative invariant)

The chain presented in a request is a **set**, not a sequence. A verifier MUST resolve it by
searching the full remaining set for the certificate matching the currently-resolved key at each
step (§4.2c) — **never** by array position. A relying party presented the same certificates in
any order MUST reach an identical verdict. This is a structural requirement, not a style
preference: a wire format whose verdict depended on transmission order would smuggle in an
implicit "as-transmitted sequence = as-intended chain" assumption that does not belong in this
primitive. The reference implementation verifies this empirically — a forward and a reversed
presentation of the same chain produce byte-identical verdicts (§8.3).

### 4.4 The four (or five) outcomes are not interchangeable

A conformant verifier MUST distinguish:

- **ALLOWED** — the chain resolves to the pinned root and the artifact's seal verifies against
  the resolved key. (When combined with rule evaluation per §7, a successful chain resolution
  instead yields `AUTHORIZED` / `DENIED` / `ESCALATED` — see §7.2.)
- **ISSUER_NOT_RECOGNIZED** — the chain does not connect the artifact's signer back to the
  pinned root. Re-presenting with a different or more complete chain may resolve this.
- **KEY_REVOKED** — the chain resolves cryptographically, but a key on the resolved path (root,
  an intermediate, or the leaf itself) has been revoked by its own parent (§5). Re-presenting the
  same chain will never resolve this; a different, unrevoked chain to the same artifact might.
- **OUT_OF_SCOPE** — the chain resolves and no key on it is revoked, so the issuer IS recognized,
  but the delegation did not cover this artifact (§3.4), or a certificate on the path tried to
  widen its own grant. Only a broader, validly-issued delegation resolves this; re-presenting the
  same authority differently never will. MUST NOT be collapsed into ISSUER_NOT_RECOGNIZED — that
  would tell a caller its issuer is unknown when the issuer is known and simply wasn't authorized
  here.
- **SEAL_INVALID** — the chain resolves fully and no key on it is revoked, but the artifact
  itself fails its own seal check (NOMOS-SPEC-001 §8) — tampered after sealing. Re-presenting
  will never help; the artifact itself is bad.
- **MALFORMED** — the request was not well-formed enough to evaluate (missing fields, wrong
  types, an oversized chain, an unsealed artifact). A client-side defect, not a trust finding.

Collapsing any of these into another is a nonconformant implementation. A caller needs to react
differently to each: `ISSUER_NOT_RECOGNIZED` is fixed by presenting more or better certificates,
`OUT_OF_SCOPE` only by obtaining a broader delegation, and none of the others by anything the
presenter can do.

### 4.5 Bounds (normative)

A verifier MUST reject a presented chain longer than **20 certificates** without attempting to
walk it, returning `MALFORMED`. No legitimate chain in this protocol's intended use is anywhere
near this deep; the bound exists to cap the worst-case O(n²) cost of the search in §4.2c against
a pathologically large input, independent of and in addition to whatever request-body size limit
the transport enforces.

---

## 5. Key Revocation

Distinct from NOMOS-SPEC-006, which withdraws an **artifact's** validity, signed by the same key
that sealed it. This section withdraws a **key's** standing to sign at all, signed by that key's
own parent — the root or intermediate that certified it in the first place. This mirrors
NOMOS-SPEC-006 §3.5's issuer-only model one level down: no new authority concept is introduced,
only the one that already certified the key being revoked.

### 5.1 The revocation statement

```jsonc
{
  "revoked_kid": "8kR2Xw5dF7hJmN1s",
  "reason":      "Intermediate key suspected compromised 2026-08-26.",
  "algorithm":   "Ed25519",
  "kid":         "V3HqL9zM2Nk4pQrT",
  "signature":   "MEQCIF…",
  "issued_at":   "2026-08-27T00:00:00Z"
}
```

| Field | Type | Description |
|---|---|---|
| `revoked_kid` | string | The kid of the key being revoked. |
| `reason` | string | Free-text, human-readable. No closed enum mandated, matching NOMOS-SPEC-006 §3.2's `reason` field. |
| `algorithm` | string | `"Ed25519"`. |
| `kid` | string | The kid of the **parent** key that certified `revoked_kid` — the only key permitted to revoke it. |
| `signature` | string | base64 Ed25519 signature over `JCS({ revoked_kid, reason, issued_at })`. |
| `issued_at` | string (ISO 8601 UTC) | Signed content, same treatment as NOMOS-SPEC-006 §3's `issued_at`. |

A verifier MUST reject a revocation statement whose `kid` does not resolve to the actual parent
that certified `revoked_kid` in some certificate the verifier can check — a statement is only
authoritative over the key its own signer actually has standing over.

### 5.2 Cascade (normative)

Revocation MUST be checked by **kid**, at every hop of the walk in §4.2 — not only against the
chain's terminal target. A relying party checking a revoked key only when it happens to be the
final target would miss every OTHER path a presenter might construct through that same revoked
key via a different set of certificates. A revoked intermediate key MUST be treated as revoked on
every chain that would otherwise resolve through it, regardless of which specific certificate
object carries it into a given presentation.

### 5.3 The revocation list

A deployment supporting revocation SHOULD publish a signed, dated aggregate of current chain-key
revocation statements, mirroring NOMOS-SPEC-006 §4's revocation list exactly in structure and
purpose:

```jsonc
{
  "generated_at": "2026-08-27T00:05:00Z",
  "algorithm":    "Ed25519",
  "kid":          "…",
  "statements":   [ /* zero or more revocation statement objects, §5.1, verbatim */ ],
  "signature":    "…"
}
```

Reference deployment: `GET /.well-known/nomos-chain-revocations`, `Cache-Control: public,
max-age=60` — short-lived, matching NOMOS-SPEC-006 §4.2's sibling endpoint's freshness treatment,
since revocation is time-sensitive in a way most other cached protocol responses are not.

---

## 6. The Verification Request/Response

### 6.1 Envelope (normative)

```jsonc
POST /verify
Content-Type: application/json

{
  "version":              "1",
  "artifact":              { /* sealed .nomos artifact */ },
  "key_certs":             [ /* key certificate objects, §3, any order */ ],
  "root_public_key_pem":  "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "facts":                 { /* optional — see §7 */ },
  "action":                "optional human-readable label"
}
```

| Field | Required | Description |
|---|---|---|
| `version` | REQUIRED | Wire envelope version. A verifier MUST reject any value it does not recognize with `MALFORMED`, rather than guess at an unfamiliar shape. This document defines version `"1"`. |
| `artifact` | REQUIRED | The sealed artifact being presented. |
| `key_certs` | REQUIRED | The chain, §4. MAY be empty if the artifact's own signing key equals the pinned root. |
| `root_public_key_pem` | REQUIRED | The root the CALLER (the relying party's own configuration) has decided to trust. MUST NOT be sourced from anything in the request body — see §9. |
| `facts` | OPTIONAL | See §7. |
| `action` | OPTIONAL | Human-readable label for what is being asked, for the caller's own logging — has no normative effect on the verdict. |

### 6.2 Response and status mapping (normative)

| `decision` | HTTP status |
|---|---|
| `ALLOWED` / `AUTHORIZED` | 200 |
| `ESCALATED` | 202 |
| `ISSUER_NOT_RECOGNIZED` | 403 |
| `KEY_REVOKED` | 403 |
| `OUT_OF_SCOPE` | 403 |
| `DENIED` | 403 |
| `SEAL_INVALID` | 422 |
| `MALFORMED` | 400 |

HTTP status is a hint for generic middleware; `decision` in the response body is what a
conformant caller MUST branch on. Collapsing any two of these into the same wire-level status is
permitted (several already share 403); collapsing them in the **body's** `decision` field is not.

---

## 7. Combining Chain Verification with Rule Evaluation

### 7.1 The gap this closes

Chain verification alone (§4) answers "is this artifact's issuer recognized and its seal
intact" — authenticity, not permission. Stopping there leaves a relying party needing a second,
separate call to actually evaluate the artifact's rules once it decides to trust the issuer,
reintroducing a step this document exists to remove. §7 specifies the composition: once, and
only once, §4 resolves to a recognized, unrevoked issuer, the artifact's own rules (NOMOS-SPEC-001
§6-7) MAY be evaluated against caller-supplied facts, in the same request.

### 7.2 Behavior (normative)

If `facts` (§6.1) is omitted, a verifier's response is exactly the chain-authenticity verdict
defined in §4.4 — this composition is purely additive and changes nothing about §4's behavior on
its own.

If `facts` is present:

1. A verifier MUST first resolve the chain per §4. If the result is anything other than
   `ALLOWED`, that result MUST be returned as-is — rule evaluation MUST NOT be attempted, and
   MUST NOT be used to produce a verdict, when the issuer itself was not established. This
   ordering is not an optimization; it is the entire point of §7: "the rules say no" and "we
   never established who's asking" MUST remain distinguishable claims a caller can react to
   differently (see §10.1).
2. Only once §4 yields `ALLOWED`, the artifact's own rules MUST be evaluated against `facts`
   using the same evaluation semantics NOMOS-SPEC-001 §6-7 define for an authenticated request —
   no separate rule-evaluation dialect for this rail.
3. The verdict is normalized to `AUTHORIZED` (the evaluation's `auto_approved` outcome),
   `DENIED` (`auto_rejected`), or `ESCALATED` (insufficient data to decide), replacing the
   `ALLOWED` decision in the response.

### 7.3 Response shape when `facts` was supplied

```jsonc
{
  "decision":       "AUTHORIZED",
  "reason":         "Rule \"deny-low-credit\" did not match. The authority permits this action.",
  "rule":           "catch-all",
  "missing_inputs": [],
  "obligations":    []
}
```

`missing_inputs` (populated on `ESCALATED`) and `obligations` (notify/log/flag-style duties that
may accompany any of the three outcomes, including `AUTHORIZED`) follow the same meaning
NOMOS-SPEC-005 §1 already defines for the public-query response — one vocabulary, not a second
one introduced here.

---

## 8. Conformance and Implementation Status

### 8.1 What conformance requires

A producer or verifier MAY implement this document independently of every other capability
described here beyond §3-4, which are the normative core.

1. **Certificate correctness** (§3): a produced certificate MUST satisfy §3.1-3.2 — correct
   field set, correct signed payload.
2. **Chain resolution** (§4): a verifier claiming conformance MUST implement the walk in §4.2
   exactly, including the order-independence invariant (§4.3) and the five distinguishable
   outcomes (§4.4). A verifier that collapses any two of §4.4's outcomes into one MUST NOT claim
   conformance to this document.
3. **Scope** (§3.4): a verifier claiming conformance MUST enforce scope as specified — including
   both fail-closed directions (undeclared dimension, unrecognized dimension) and monotonic
   narrowing. A verifier that stores or displays `scope` without enforcing it MUST NOT claim
   conformance; that is precisely the state this document's first draft described.
4. **Revocation** (§5) and **rule-evaluation composition** (§7) are each independently OPTIONAL
   relative to §3-4 baseline conformance, in the same layered sense NOMOS-SPEC-006 treats its own
   §3-6 as optional relative to NOMOS-SPEC-001.

### 8.2 Known gaps (disclosed, not hidden)

Matching NOMOS-SPEC-001 §11's and NOMOS-SPEC-006 §9.3's precedent of naming a real limitation
plainly rather than implying it is handled:

- **Single implementation.** This document is published alongside exactly one implementation —
  the reference one (§8.3). No interoperability claim is made. This Draft exists specifically to
  invite a second, independent one; until that exists, this remains a tested prototype with a
  spec number, not proven interoperable infrastructure.
- **Scope covers two dimensions, not every dimension.** §3.4 enforces `artifact` and `industry`.
  `jurisdiction` is deliberately excluded: real artifacts carry jurisdictions as free prose
  ("State of California", "NHS England"), and a matcher over free prose would pass silently on a
  variant spelling — a constraint that looks enforced but isn't is worse than one openly absent.
  Jurisdiction scoping awaits a normalized identifier, and this document does not claim it.
- **`industry` matching trusts the issuer's own declaration.** A scope constrains what the
  artifact SAYS it covers (`meta.industry`), not what it actually covers. Scope binds a delegation
  to a declaration; it cannot detect a mislabelled artifact.
- **No certificate-level revocation, only key-level.** §5 revokes a *key's* standing to sign
  entirely. Revoking one specific certificate while leaving the same key valid for other
  purposes is not specified in this version.
- **The `reason` field is overloaded by decision.** On `ISSUER_NOT_RECOGNIZED`, `reason` is one
  of a fixed set of short codes (§4.4); on `AUTHORIZED`/`DENIED`/`ESCALATED` (§7.3), the same
  field name carries a full human-readable sentence instead. This is a genuine naming wart in
  the reference implementation, disclosed here rather than smoothed over — a future revision
  should split these into distinct field names.
- **Root governance is out of scope of this document entirely.** See §9.

### 8.3 Reference implementation

- **Pure primitive** (§3-4), signer-agnostic, no persistence:
  [`prototype/chain-of-trust/`](https://github.com/nomos-spec/spec/tree/main/prototype/chain-of-trust)
  in this repository — `key-cert.ts`, `chain-verify-core.ts`, a standalone CLI verifier
  (`verify-chain.ts`), and a minimal `node:http` reference receiver/presenter pair
  (`receiver.ts` / `presenter.ts`) demonstrating §6's envelope over an actual socket. Order
  independence (§4.3) is verified empirically in `test.ts` (17 assertions), not just asserted
  from reading the code.
- **Production deployment**, including §5 revocation and §7 rule-evaluation composition:
  `nomosprotocol.com`'s `POST /api/v1/chain-of-trust/verify` (`@nomosprotocol/sdk`'s
  `nomos.can({ artifact, key_certs, root_public_key_pem, ...facts })`). This is the fuller
  implementation §5 and §7 describe; the pure prototype above covers §3-4 and §6's envelope
  without persistence or rule evaluation.
- **Test vectors**: [`chain-of-trust-vectors/`](https://github.com/nomos-spec/spec/tree/main/chain-of-trust-vectors)
  — seven fixed `{ artifact, key_certs, expected }` cases (a resolved chain, reversed-order
  equivalence, an uncertified issuer, an expired certificate, a tampered artifact, and two
  malformed inputs), confirmed self-consistent with the reference implementation
  (`check.ts`), specifically so a second implementer has something concrete to check their own
  verifier against rather than only prose to interpret.
- **Schemas**: `schema/key-certificate.schema.json`, `schema/chain-verification-request.schema.json`,
  `schema/chain-verification-response.schema.json`, `schema/chain-revocation-statement.schema.json`,
  `schema/chain-revocation-list.schema.json`.

---

## 9. Relationship to Root Governance (Non-Normative)

This document specifies how a relying party verifies a chain against a root **it has already
decided to trust**. It says nothing about who that root should be, how many roots should exist,
or how a relying party should decide which root(s) to pin in the first place — the R-09 question
Paper 5 names as a separate, unresolved design question. Deliberately: baking a specific
governance answer into this document would conflate a cryptographic primitive (this spec) with an
institutional decision (who operates trust infrastructure) that belongs to a different kind of
process entirely, involving parties well beyond this repository. Every example and reference
implementation in this document generates its own disposable, clearly-labeled test root — never a
production signing key, never a default anyone could mistake for a real trust anchor.

---

## 10. Security Considerations

### 10.1 Never collapse "not established" into "denied"

§4.4 and §7.2 both depend on this: an `ISSUER_NOT_RECOGNIZED` or `KEY_REVOKED` result MUST NOT be
represented to a caller as equivalent to a rule-evaluated `DENIED`. The two require different
caller action — re-presenting a different chain can fix the first; nothing about presentation
fixes the second, because the rules themselves said no. An implementation that merges these
vocabularies to simplify its own error handling produces a caller-facing defect, not a
simplification.

### 10.2 Scope binds a declaration, not a reality

§3.4 constrains what an artifact SAYS it covers. An issuer delegated `industry:financial` who
signs an artifact declaring `meta.industry: "financial"` while its rules actually govern something
else has not been stopped by scope — it has been stopped only from signing artifacts that *admit*
to being out of scope. Scope narrows delegation; it does not audit content. Treat it as the
analogue of an X.509 name constraint, which likewise binds what a certificate asserts rather than
what a server ultimately does.

The fail-closed rules exist because the alternative is worse: were an undeclared dimension to
pass, omitting `meta.industry` would become the standard way to escape every industry-scoped
delegation.

### 10.3 The root key is the whole trust boundary

Every property this document provides is only as strong as the relying party's own root-pinning
decision. A relying party that pins a root it does not actually control or trust, or that accepts
a root supplied by the presenting party itself (rather than its own out-of-band configuration),
has not gained anything from this protocol beyond what an unconditional accept would have given
it. §6.1's `root_public_key_pem` MUST come from the relying party's own configuration, never from
request content it does not independently control.

### 10.4 Key compromise cascades exactly as far as certification does

Compromising an intermediate key compromises every leaf certified under it, and revoking that
intermediate (§5) is the only way to sever all of those paths at once — §5.2's cascade-by-kid
requirement exists specifically so a relying party cannot be fooled by a presenter who
reconstructs a different certificate path to the same compromised key. The corresponding
key-protection guidance in NOMOS-SPEC-001 §8 (secrets manager, never embedded in code or an
artifact) applies with proportionally higher stakes the closer a key sits to the root.

### 10.5 A single implementation is a real, disclosed limitation

Restated from §8.2 because it is a security property, not just a maturity note: a specification
verified against only its own reference implementation has not yet demonstrated that its written
text — as opposed to one author's mental model of it — is sufficient to build an interoperable,
independently-correct verifier. Treat this document's algorithms as a strong starting point for
implementation, not as proven-unambiguous prose, until a second implementation exists.

---

## 11. Examples

### 11.1 A two-hop certificate chain

```json
[
  {
    "parent_kid": "rootKid00000001",
    "child_kid": "intermediateKid1",
    "child_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    "issued_at": "2026-08-27T00:00:00Z",
    "expires_at": "2027-08-27T00:00:00Z",
    "algorithm": "Ed25519",
    "signature": "MEUCIQD1a2b3c4…"
  },
  {
    "parent_kid": "intermediateKid1",
    "child_kid": "leafKid000000001",
    "child_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    "issued_at": "2026-08-27T00:00:00Z",
    "expires_at": "2027-08-27T00:00:00Z",
    "algorithm": "Ed25519",
    "signature": "MEQCIF5d6e7f8…"
  }
]
```

### 11.2 A chain that resolves and authorizes the action

```
POST /verify
{ "version": "1", "artifact": {...}, "key_certs": [...], "root_public_key_pem": "...",
  "facts": { "credit_score": 750 } }

→ 200 OK
{ "decision": "AUTHORIZED", "reason": "2 rules evaluated. No restriction fired.",
  "rule": "catch-all", "missing_inputs": [] }
```

### 11.3 A recognized issuer that wasn't delegated this artifact

```
POST /verify
{ "version": "1", "artifact": { "meta": { "industry": "healthcare", ... }, ... },
  "key_certs": [ { "scope": "industry:financial/lending", ... } ], "root_public_key_pem": "..." }

→ 403 Forbidden
{ "decision": "OUT_OF_SCOPE", "dimension": "industry",
  "effective_scope": "industry:financial/lending",
  "detail": "Scope permits industry \"financial/lending\"; this artifact declares \"healthcare\"." }
```

The chain is valid and the seal is intact. The issuer simply was not delegated authority here.

### 11.4 An unrecognized issuer

```
→ 403 Forbidden
{ "decision": "ISSUER_NOT_RECOGNIZED", "reason": "chain_broken",
  "detail": "Chain breaks after kid 40ZaXrnpntaoD4dn — no certificate continues it toward the artifact's signing key." }
```

### 11.5 A revoked key, reached via a different path than the one that was revoked

```
→ 403 Forbidden
{ "decision": "KEY_REVOKED", "revoked_kid": "intermediateKid1",
  "detail": "Key intermediateKid1 in this chain has been revoked by its own parent." }
```

### 11.6 A tampered artifact — chain resolves fine, seal does not

```
→ 422 Unprocessable Entity
{ "decision": "SEAL_INVALID", "detail": "Hash mismatch — payload modified after sealing." }
```
