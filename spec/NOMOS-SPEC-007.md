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
| `jurisdiction` | `meta.jurisdiction_codes` | ISO 3166 codes. A country contains its subdivisions: `US` contains `US-CA`; `US-CA` contains only itself. |

**`jurisdiction` reads `meta.jurisdiction_codes`, never `meta.jurisdictions` (normative).** The
latter is free prose intended for humans ("State of California", "NHS England") and MUST NOT be
used for authorization: matching it would pass silently on a variant spelling. A verifier MUST
reject any value in `meta.jurisdiction_codes` that is not a well-formed ISO 3166 alpha-2 country
or country-subdivision code, rather than falling back to string comparison.

**Every declared jurisdiction MUST be in scope (normative).** If an artifact declares
`["US-CA", "GB"]` under a `jurisdiction:US` delegation, it is OUT of scope. Requiring only an
overlap would let an artifact launder any jurisdiction by also declaring one in-scope code.

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

### 4.4 The outcomes are not interchangeable

A conformant verifier MUST distinguish:

- **ALLOWED** — the chain resolves to the pinned root and the artifact's seal verifies against
  the resolved key. (When combined with rule evaluation per §7, a successful chain resolution
  instead yields `AUTHORIZED` / `DENIED` / `ESCALATED` — see §7.2.)
- **ISSUER_NOT_RECOGNIZED** — the chain does not connect the artifact's signer back to the
  pinned root. Re-presenting with a different or more complete chain may resolve this.
- **KEY_REVOKED** — the chain resolves cryptographically, but a key on the resolved path (root,
  an intermediate, or the leaf itself) has been revoked by its own parent (§5). Re-presenting the
  same chain will never resolve this; a different, unrevoked chain to the same artifact might.
- **CERTIFICATE_REVOKED** — a certificate on the path was withdrawn by its issuer (§5.4), while
  the key it certified remains validly certified elsewhere. Distinct from KEY_REVOKED because the
  options differ: another certificate for the same key can still resolve this, whereas a revoked
  key is dead on every path.
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

### 5.4 Certificate revocation

§5.1 withdraws a KEY's standing to sign entirely. This withdraws ONE delegation while leaving the
key able to act under any other certificate it holds — the difference between "this key is
compromised" and "this particular grant was a mistake."

A certificate is identified by its **fingerprint**: SHA-256 over its canonical signed payload
(§3.2), hex-encoded. Content-derived deliberately — a certificate carries no id on the wire, so
any verifier holding one can compute this offline, exactly as NOMOS-SPEC-006 §3.4 binds a
revocation to `artifact_hash` rather than to a row. The fingerprint covers the signed payload and
not the signature, so re-signing the same delegation does not evade a revocation of it.

A certificate revocation is signed by that certificate's own PARENT — the same authority model as
§5.1, one level finer. A verifier MUST check each certificate's fingerprint against the revocation
set AFTER its signature verifies (an unverified certificate must never be probed for revocation
status) and BEFORE applying its scope (a revoked certificate must never narrow anything). The
outcome is `CERTIFICATE_REVOKED`, which a verifier MUST NOT report as `KEY_REVOKED`.

### 5.5 Freshness staples

§5.1-5.4 assume a verifier holds an authoritative revocation source — a live lookup, or a fetched
copy of §5.3's list. That assumption fails for exactly the relying party this document was written
for: an independent system with no prior relationship to the issuer, verifying a chain entirely
offline. Without a revocation source, such a verifier cannot say a key is unrevoked — only that it
was validly certified, which says nothing about whether that certification still holds. Leaving
that silently unaddressed would mean the primitive works right up until the one property (can I
trust this right now) a relying party most needs from it.

A freshness staple is the third option, alongside "have a live source" and "fetch the list
yourself": the PRESENTER periodically asks their own issuing parent for a short-lived "this key is
not revoked as of T" proof, signed by that parent, and attaches it to what they present. A
verifier with no revocation source of its own MAY use a valid staple to raise its confidence in one
kid's non-revoked status from `unchecked` to `staple` — a bounded, disclosed guarantee, never
silently promoted to `live`.

```jsonc
{
  "child_kid":   "8kR2Xw5dF7hJmN1s",
  "parent_kid":  "V3HqL9zM2Nk4pQrT",
  "as_of":       "2026-08-28T00:00:00Z",
  "valid_until": "2026-08-28T00:15:00Z",
  "algorithm":   "Ed25519",
  "signature":   "MEQCIF…"
}
```

| Field | Type | Description |
|---|---|---|
| `child_kid` | string | The kid this staple vouches for. |
| `parent_kid` | string | The signer. MUST be the same `parent_kid` that actually certified `child_kid` in some certificate the verifier is walking. |
| `as_of` | string (ISO 8601 UTC) | When this staple was signed. Signed content. |
| `valid_until` | string (ISO 8601 UTC) | When this staple stops being usable. Signed content. RECOMMENDED short — minutes to roughly an hour, not the years-long scale of a certificate's own `expires_at`. This document does not mandate an exact figure, matching §6.2's own treatment of `max_age` in NOMOS-SPEC-006. |
| `algorithm` | string | `"Ed25519"`. |
| `signature` | string | base64 Ed25519 signature over `JCS({ child_kid, parent_kid, as_of, valid_until })`. |

**Signed by the same key that could revoke the kid, never a platform-wide key (normative).** A
staple for `child_kid` MUST be signed by the exact key that holds `parent_kid` in a certificate
the verifier has independently validated as certifying `child_kid` — the same authority §5.1
already requires for a revocation statement. This is a deliberate rejection of a platform-signed
alternative: a deployment operator's own key vouching for freshness across every delegation in the
system would recreate, inside the one mechanism designed to avoid it, exactly the "everyone
depends on our server" dependency chain verification exists to remove. A staple therefore requires
no infrastructure beyond what §5.1 revocation already requires — it does not concentrate freshness
authority anywhere revocation authority doesn't already sit.

**The root is explicitly out of scope (normative).** Nothing certifies a root — it is the relying
party's own out-of-band pinned anchor (§4.1) — so nothing but the relying party's own decision to
un-pin it can ever answer "is my root still good." A verifier MUST NOT accept a staple whose
`child_kid` is the pinned root, and MUST NOT treat the root's own confidence as anything but
`unchecked` when no live source covers it, regardless of how many other kids on the path a staple
covers.

**Confidence is a tri-state, computed per kid and combined as the weakest link (normative):**

- `live` — the kid was checked against the verifier's own revocation source.
- `staple` — the verifier had no source of its own for this kid, but a valid, unexpired staple
  signed by the kid's actual certifying parent was presented and used instead.
- `unchecked` — neither was available. Fail-open, matching every other revocation check in this
  document (§10.1) — but never fail-**silent**: `unchecked` MUST be disclosed on the response,
  never collapsed into `live` or `staple`.

A verifier computes this once per kid on the resolved path (root included) and combines them by
taking the **weakest** result across the whole path — `unchecked` beats `staple` beats `live`. One
uncovered kid MUST pull the entire path's confidence down; a verifier MUST NOT report the best
result among several kids as if it applied to all of them.

**A verifier with its own revocation source MUST NOT consult staples at all (normative).** If a
verifier holds a revocation source — even an explicitly empty one, checked and found clean — every
kid's confidence is `live`, full stop. A staple can only ever raise confidence in a kid that would
otherwise be `unchecked`; it can never substitute for, override, or be checked against a real
source that already answered the question. This is what prevents a compromised or malicious
presenter from using its own staple to launder a "not revoked" past a verifier whose own list says
otherwise: if the verifier already knows, the presenter's staple is never even read.

**Reported on the response (normative).** An `ALLOWED` verdict (§6.2) MUST carry
`revocation_checked: "live" | "staple" | "unchecked"`. When §7 composes chain verification with
rule evaluation, `revocation_checked` MUST also be present on the resulting
`AUTHORIZED`/`DENIED`/`ESCALATED` response — composing to a real permission decision MUST NOT
silently drop the confidence disclosure the chain-authenticity result it is computed from already
carries; a caller deciding how much to trust an `AUTHORIZED` verdict needs this exactly as much as
it needs it on bare chain authenticity. A caller that requires a stronger guarantee than
`unchecked` or `staple` provide MAY decline to rely on the verdict and instead re-verify against a
live source of its own — the same choice §10.1 already reserves for every fail-open outcome in
this document.

**Scope of this version (disclosed, not hidden).** Staples cover KEY revocation (§5.1-5.2) only.
A revoked certificate (§5.4) is never staple-coverable — the two are different objects with
different authority models, and conflating them would let a stale "key not revoked" staple paper
over a specifically and deliberately withdrawn delegation. A verifier MUST check certificate
revocation independently of any staple, and MUST NOT let a staple suppress a `CERTIFICATE_REVOKED`
result.

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
  "freshness_staples":     [ /* optional — freshness staple objects, §5.5 */ ],
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
| `freshness_staples` | OPTIONAL | See §5.5. Only ever consulted by a verifier with no revocation source of its own; a verifier that holds one ignores this field entirely. |
| `facts` | OPTIONAL | See §7. |
| `action` | OPTIONAL | Human-readable label for what is being asked, for the caller's own logging — has no normative effect on the verdict. |

### 6.2 Response and status mapping (normative)

| `decision` | HTTP status |
|---|---|
| `ALLOWED` / `AUTHORIZED` | 200 |
| `ESCALATED` | 202 |
| `ISSUER_NOT_RECOGNIZED` | 403 |
| `CERTIFICATE_REVOKED` | 403 |
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
- **Scope binds what an artifact DECLARES, not what it governs.** A scope constrains
  `meta.industry` / `meta.jurisdiction_codes` / `meta.artifact_id`, not the actual content of the
  rules. This is a property of the mechanism rather than an omission — X.509 name constraints bind
  what a certificate asserts in exactly the same way — but it is stated plainly because a reader
  could otherwise assume scope audits content. It does not.
- **Adopting `jurisdiction` scope imposes a declaration requirement.** An issuer who scopes by
  jurisdiction forces every artifact signed under that delegation to carry
  `meta.jurisdiction_codes`; artifacts declaring only the free-prose `meta.jurisdictions` will
  fail closed. That is the intended trade, named here so it is not a surprise.
- **Root governance is out of scope of this document entirely.** See §9.

### 8.3 Reference implementation

The split below is deliberate, not incidental: it is the difference between checking a caller-
supplied set at walk time (needs nothing but the set) and producing, signing, or persisting the
statements that populate that set (needs key custody). Stated precisely rather than as a blanket
"production has §5, prototype doesn't" — that framing stopped being accurate once walk-time
revocation checks landed in the prototype, and restating it precisely here is part of this
change, not a separate cleanup.

- **Pure primitive** (§3-4, §6's envelope), signer-agnostic, no persistence:
  [`prototype/chain-of-trust/`](https://github.com/nomos-spec/spec/tree/main/prototype/chain-of-trust)
  in this repository — `key-cert.ts`, `chain-verify-core.ts`, a standalone CLI verifier
  (`verify-chain.ts`), and a minimal `node:http` reference receiver/presenter pair
  (`receiver.ts` / `presenter.ts`) demonstrating §6's envelope over an actual socket. Order
  independence (§4.3) is verified empirically in `test.ts` (25 assertions), not just asserted
  from reading the code.
- **§5's walk-time checks ARE in the pure prototype**: §5.2's cascade (a caller-supplied
  `revokedKids` set), §5.4's certificate revocation (`revokedCerts`), and §5.5's freshness-staple
  confidence arithmetic are all implemented in `chain-verify-core.ts` and exercised in `test.ts`.
  What is NOT in the prototype is producing or verifying a §5.1 revocation statement, or signing
  a §5.3 revocation list — those need a key custody model this signer-agnostic module deliberately
  has none of.
- **Production deployment** additionally provides §5.1/§5.3's statement/list machinery
  (persistence, org key custody, issuance) and §7's rule-evaluation composition:
  `nomosprotocol.com`'s `POST /api/v1/chain-of-trust/verify` (`@nomosprotocol/sdk`'s
  `nomos.can({ artifact, key_certs, root_public_key_pem, ...facts })`). This is where a real
  revocation statement gets created, signed, and published; the pure prototype above can only
  ever check against a set someone else populated.
- **Test vectors**: [`chain-of-trust-vectors/`](https://github.com/nomos-spec/spec/tree/main/chain-of-trust-vectors)
  — fourteen fixed `{ artifact, key_certs, expected }` cases (a resolved chain, reversed-order
  equivalence, an uncertified issuer, an expired certificate, a tampered artifact, malformed
  inputs, delegation-scope cases, a revoked key, and staple-coverage cases at full and partial
  hop coverage), confirmed self-consistent with the reference implementation (`check.ts`),
  specifically so a second implementer has something concrete to check their own verifier against
  rather than only prose to interpret.
- **Cross-implementation payload check**: the production deployment's `server/lib/nomos-chain.ts`
  and this prototype's `key-cert.ts` are two independently-typed TypeScript modules (one keyed to
  `crypto.KeyObject`, the other to PEM strings) that must still produce byte-identical signed
  payloads for both a key certificate and a freshness staple — the actual property a second real
  implementer needs to match, verified directly rather than assumed from both following the same
  prose. This does not satisfy §8.2's "single implementation" gap — two implementations by the
  same author are not independent — it confirms wire compatibility between them, nothing more.
- **Schemas**: `schema/key-certificate.schema.json`, `schema/freshness-staple.schema.json`,
  `schema/chain-verification-request.schema.json`, `schema/chain-verification-response.schema.json`,
  `schema/chain-revocation-statement.schema.json`, `schema/chain-revocation-list.schema.json`.

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
  "rule": "catch-all", "missing_inputs": [], "revocation_checked": "live" }
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
{ "decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "chain_broken",
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
