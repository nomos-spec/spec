# NOMOS-SPEC-007 Revision 1.10.0: Revocation a Relying Party Can Check

**Status:** Draft (proposed revision)
**Version:** 1.10.0 (revises 1.9.0)
**Extends:** NOMOS-SPEC-001 v2.2.0, NOMOS-SPEC-010 0.2.0
**Proposed:** 2026-10-27
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group

---

## Abstract

§5 lets a parent key revoke a key it certified, or one certificate it issued, and lets a
deployment publish the current revocations as a signed list. Building revocation tooling for
institutions whose keys live in a KMS exposed four gaps, each of which an independent relying
party would meet:

1. **Ed25519 only.** Rev. 1.9 let certificates, staples and seals be ES256 so keys can stay in a
   KMS or HSM (NOMOS-SPEC-010). Revocation statements and lists stayed Ed25519, so a P-256 parent
   could certify a key but never revoke it.
2. **No wire form for certificate revocation.** §5.4 revokes one certificate by fingerprint, but a
   statement had only `revoked_kid`. The reference platform signed fingerprints in that field and
   did not publish them, so no relying party could learn of a certificate revocation.
3. **Revocation by a forged parent.** §5.1 accepted a statement whose signer "certified
   `revoked_kid` in some certificate the verifier can check". A public key is public: anyone can
   mint a key, sign a certificate for someone else's key with it, and then revoke that key.
4. **A list no relying party could authenticate.** A list was signed by "the deployment's own
   platform key", which an independent relying party has no way to recognize. Neither its
   statements' authority nor its freshness could be established.

This revision closes all four. Statements are Ed25519 or ES256. A statement revokes a key or a
certificate, never ambiguously. A statement counts only when its signer is the revoked key's
parent on a path from the relying party's own pinned root. A list carries the certificates that
make it checkable, and its date counts only when its signer is recognized the same way. A
relying party that cannot establish current revocations refuses to commit, rather than treating
silence as "nothing revoked".

The rest of rev. 1.9 is unchanged.

---

## Changes at a glance

| Section | Change |
|---|---|
| §5.1 | Statement suites (`Ed25519`, `ES256`); exactly one of `revoked_kid`, `revoked_fingerprint` |
| §5.1a (new) | When a statement counts: the authority rule |
| §5.3 | List suites; `key_certs` carried by the list; when its date counts |
| §5.3a (new) | Verifying a revocation source, as one deterministic procedure |
| §5.6 (new) | A relying party without current revocations refuses to commit |
| §8.2 | Known gaps updated |

---

## §5.1 The revocation statement (amended)

```jsonc
{
  "revoked_kid":         "8kR2Xw5dF7hJmN1s",     // revoking a key, or
  "revoked_fingerprint": "5d1f…",                // revoking one certificate (§5.4): exactly one of the two
  "reason":              "Intermediate key suspected compromised 2026-08-26.",
  "issued_at":           "2026-08-27T00:00:00Z",
  "kid":                 "V3HqL9zM2Nk4pQrT",     // the parent: the key that certified what is revoked
  "algorithm":           "Ed25519",              // or "ES256" (NOMOS-SPEC-010)
  "signature":           "…"
}
```

| Field | Change |
|---|---|
| `revoked_kid` / `revoked_fingerprint` | A statement carries **exactly one**. `revoked_fingerprint` is the SHA-256 fingerprint of one certificate (§5.4), 64 lower-case hex characters. A statement with both, or neither, is malformed. |
| `algorithm` | `"Ed25519"` or `"ES256"`, the suite of the parent's signature. It must be a suite the parent's effective scope permits (§3.6). Not signed, by the argument of rev. 1.9 §3.1: the parent's key type fixes the suite, so the field can only make a statement fail. |
| `signature` | Over `JCS({ revoked_kid, reason, issued_at })` for a key, or `JCS({ revoked_fingerprint, reason, issued_at })` for a certificate. |

**The payloads differ in their field name, on purpose.** A signature over one kind of statement
can never be read as the other. The key payload is byte-identical to 1.7.0's, so every existing
key revocation still verifies.

**Migration.** The reference platform signed certificate revocations as
`JCS({ revoked_kid: <fingerprint>, … })`. Under this revision such a statement is a key revocation
of a kid that no certificate names, so it revokes nothing (§5.1a rule 2). Those statements were
never published. They are re-signed in the certificate form by the key that holds the parent.

## §5.1a When a statement counts (new, normative)

A relying party evaluates a statement against its pinned root `R`, the certificates available to
it (its pool `P`), and the current time. The statement **counts** only if all of these hold:

1. **Shape.** Exactly one of `revoked_kid` and `revoked_fingerprint`; `reason`, `issued_at`,
   `kid`, `algorithm` and `signature` are strings; `issued_at` parses and is not later than now.
2. **The revoked object.** For a key: some certificate `c` in `P` has `child_kid = revoked_kid` and
   `parent_kid = kid`. For a certificate: some `c` in `P` has fingerprint `revoked_fingerprint`
   and `parent_kid = kid`.
3. **The parent is recognized.** `kid` is `R`'s kid, or `kid` resolves to `R` within `P` (§4.2a)
   at time `issued_at`. The purpose admits any effective scope that permits the statement's
   `algorithm` (§3.6). Revocation is not consulted on this path (see below).
4. **The parent made the certificate.** `c`'s signature verifies under the parent's key. That is
   the evidence that this parent certified what it is now revoking.
5. **The parent signed the statement.** The statement's signature verifies under the parent's key,
   with suite `algorithm`, over its payload.

A statement that fails any rule is **ignored**. It is never treated as valid, and it never stops
another statement from counting.

**Why authority to revoke is authority to certify.** Rule 2 alone, the 1.7.0 rule, let anyone
revoke any key. Rules 3 and 4 tie the statement to a parent that the relying party's own root
vouches for, and to a certificate that parent really signed. A key the root does not reach cannot
revoke anything. A passkey cannot revoke, because a `WebAuthn-ES256` key signs nothing but
consents (§3.6).

**Why rule 3 ignores revocation.** Revocations only accumulate. Suppose a parent revokes a key
and is itself revoked later, at a rotation or after a compromise. If its statements then stopped
counting, the key it had revoked would come back to life on every other path that reaches it.
That would be fail-open. With accumulation, the worst a compromised parent can do is revoke keys it
certified, which it could already do before its compromise was known. Rule 3 evaluates the
parent's path at `issued_at`, so a statement made while the parent's certificate was valid
continues to count after that certificate expires.

**Effect.** A counted key statement adds `revoked_kid` to the revoked kids. It is checked at every
hop (§5.2), on every path, whichever certificate carries the key. A counted certificate statement
adds `revoked_fingerprint` to the revoked certificates (§5.4).

## §5.3 The revocation list (amended)

```jsonc
{
  "generated_at": "2026-08-27T00:05:00Z",
  "kid":          "…",                 // the list signer
  "algorithm":    "Ed25519",           // or "ES256"
  "statements":   [ /* §5.1 statements, verbatim */ ],
  "key_certs":    [ /* certificates that make the list checkable */ ],
  "signature":    "…"                  // over JCS({ generated_at, statements }), unchanged
}
```

| Field | Change |
|---|---|
| `algorithm` | `"Ed25519"` or `"ES256"`. |
| `key_certs` | New, OPTIONAL. Certificates a relying party may need to check the statements and the signer: the closure (NOMOS-SPEC-009 §6.5), over the publisher's certificates, of every statement's `kid`, every `revoked_kid`, the parent of every revoked certificate, and the list's own `kid`. Plus each revoked certificate itself. At most 1,000. They are not signed by the list; each is verified on its own. |
| `signature` | Payload unchanged, so existing lists verify. `key_certs` is outside it: certificates need no second signature. |

**Who signs a list.** A list's statements count on their own authority (§5.1a), whoever publishes
it. The list's **date** is a different claim: that these are all the revocations its publisher
knew of at `generated_at`. That claim is evidence only when its signer is recognized. The list's
`kid` must resolve to the relying party's root within its pool at `generated_at`. Unlike §5.1a
rule 3, this resolution is subject to the revocations the list establishes. A revoked key cannot
vouch that a list is current.

An issuer publishes its list at the `revocations_url` of its NOMOS-SPEC-009 document, signed by a
key in its own hierarchy. A list signed by a key outside the relying party's hierarchy, such as a
hosting platform's own key, still contributes every statement that counts. Its date proves
nothing, so it cannot keep the relying party's revocation knowledge current (§5.6).

## §5.3a Verifying a revocation source (new, normative)

Given a list `L`, the relying party's root `R`, its own certificates `C` (for example the issuer
document's pool) and the time `now`:

1. **Shape.** `L` is an object with `generated_at`, `kid`, `algorithm` and `signature` as strings,
   `statements` an array and `key_certs`, when present, an array of at most 1,000 well-formed
   certificates. Otherwise the list is `MALFORMED` and contributes nothing.
2. **The pool.** `P = L.key_certs ∪ C`, each certificate once by fingerprint.
3. **The statements.** Evaluate every statement by §5.1a against `R` and `P`. The revoked kids and
   revoked certificates are those of the statements that count. The result does not depend on the
   order of statements or certificates.
4. **The date.** `as_of = generated_at` if `L.kid` is `R`'s kid or resolves to `R` within `P` at
   `generated_at` under the revocations of step 3; and `generated_at` is not later than `now`; and
   `L.signature` verifies under that key, with suite `L.algorithm`, over
   `JCS({ generated_at, statements })`. Otherwise `as_of` is absent.

The result is the revoked kids, the revoked certificates, `as_of`, and for each ignored statement
its index and the first rule it failed: `bad_statement` (rule 1), `no_certificate` (rule 2),
`signer_not_recognized` (rule 3), `bad_certificate_signature` (rule 4) or `bad_signature`
(rule 5).

## §5.6 Current revocation knowledge (new)

A relying party that consults revocation lists keeps the newest `as_of` it has established for
each source. If it is older than the relying party's configured maximum age, it SHOULD refuse to
commit new Acts until a current list is fetched. NOMOS-SPEC-009 relying parties answer such a
refusal with 503 and `Retry-After`. It MUST NOT treat a source it could not fetch, or a list with
no `as_of`, as evidence that nothing is revoked. Statements it already holds keep counting
regardless: a revocation is never forgotten because a later fetch failed.

The maximum age is policy, not protocol, in the same way as NOMOS-SPEC-006 §6.2's `max_age`.
Minutes suit a payment system; a day may suit an archive. A signed list proves who published it
and when, not that it is complete (NOMOS-SPEC-006 §4). Refusing to act on stale knowledge is the
relying party's protection against a publisher that stops publishing.

## Compatibility

| Change | Effect |
|---|---|
| ES256 statements and lists | Older verifiers reject them; Ed25519 statements and lists are unchanged |
| `revoked_fingerprint` | Older verifiers find no `revoked_kid` and reject the statement: fail closed, never misread |
| §5.1a authority rule | A statement counts only if its signer is reached from the relying party's root and really certified what it revokes. A relying party that pins an org's root sees exactly that org's revocations |
| List `key_certs` | Additive. A list without it is checked against the relying party's own certificates |
| List date | A list signed by a key outside the relying party's hierarchy no longer establishes currency. The reference platform's aggregate list is signed by its platform key, so for org roots its statements count and its date does not. Issuers publish their own lists (NOMOS-SPEC-009 `revocations_url`) |

## §8.2 Known gaps (updated)

- **Implementations.** Rev. 1.10 has two implementations, both by the authors:
  `python/nomosprotocol/chain.py` and `@nomosprotocol/verify`. Both pass the 22 cases of
  `chain-of-trust-vectors/revocation-vectors-1.10.json`, whose expectations were written by hand,
  and agree on all 349 mutants `mutants_revocations.py` derives from them. A verifier with any one
  rule of §5.1a or §5.3a removed fails cases. An independent implementation is still needed.
- **The hosted platform's verifier** implements rev. 1.9 through `@nomosprotocol/verify`.
  Adopting this revision on the platform needs three things: re-signing its unpublished
  certificate revocations in the new form, publishing them, and publishing per-issuer lists.
  Until then it keeps consulting its own database directly, which is complete for its own keys.

## Changelog

- **1.10.0 (proposed):**
  - ES256 revocation statements and lists;
  - `revoked_fingerprint`;
  - the authority rule for statements;
  - lists that carry their certificates, with a date that counts only from a recognized signer;
  - relying parties fail closed on stale revocation knowledge.
