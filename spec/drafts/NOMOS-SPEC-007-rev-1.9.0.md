# NOMOS-SPEC-007 Revision 1.9.0: Scope-Aware Resolution, Signature Suites, Approvers

**Status:** Draft (proposed revision)
**Version:** 1.9.0 (revises 1.8.0)
**Extends:** NOMOS-SPEC-001 v2.2.0, NOMOS-SPEC-010 0.1.0
**Proposed:** 2026-10-26
**Implements:** RFC-0001 changes 2, 3 and 4 (`proposals/RFC-0001-act-enforcement-phase-0.md`)
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group

---

## Abstract

Revision 1.8.0 resolves a key target-first over an unordered certificate set and admits statement
keys. This revision makes three changes.

1. **Scope-aware path selection.** A candidate path whose effective scope does not admit the
   purpose of the resolution is a failed candidate, and the next one is tried. In 1.8.0 the
   first path that validated *cryptographically* was chosen, and only then was its scope
   checked. So adding a valid certificate could turn an authorization into `OUT_OF_SCOPE`
   (R-19 §5.6). This revision removes that wrongful refusal.
2. **Signature suites.** Certificates, staples and seals may be signed under `Ed25519` or `ES256`
   (NOMOS-SPEC-010), and a certified key may be Ed25519 or P-256. A new `suite` dimension says
   which suites a key may sign under, so a passkey enrolled for approvals can do nothing else.
3. **Approvers.** A new `approver` dimension binds the keys of one person together, so that a
   consent count can count people rather than keys (NOMOS-SPEC-008 0.6.0).

The rest of 1.8.0 is unchanged. Everything in 1.7.0 not changed by 1.8.0 or by this revision
also remains in force.

---

## Changes at a glance

| Section | Change |
|---|---|
| §3.1 | `algorithm` is `Ed25519` or `ES256`; `child_public_key_pem` is an Ed25519 or P-256 key in canonical form |
| §3.3 | The per-certificate checks, in their normative order, with reason codes |
| §3.6 (new) | The `suite` dimension |
| §3.7 (new) | The `approver` dimension |
| §3.8 (new) | Effective scope: its order, and how a purpose admits it |
| §4.2a step 4 | Validation includes admission for the purpose (replaces 1.8.0 step 4) |
| §4.4 | Outcome table: decisions and reason codes |
| §4.7 (new) | The seal under the resolved key |
| §5.5 | Staples may be ES256; their shape is checked |
| §8.2 | Known gaps updated |

---

## §3.1 Certificate fields (amended)

| Field | Change |
|---|---|
| `algorithm` | `"Ed25519"` or `"ES256"`. It names the suite of the **parent's** signature over the certificate (NOMOS-SPEC-010). A certificate is never `WebAuthn-ES256`-signed. Any other value makes the presentation `MALFORMED` (`bad_certificate`). |
| `child_public_key_pem` | An Ed25519 or P-256 public key, in the canonical SPKI encoding of NOMOS-SPEC-010 §3.1. A P-256 key uses the uncompressed point. |

**Why `algorithm` stays unsigned.** The signed payload is unchanged (§3.2), so every existing
certificate keeps its fingerprint. This is safe because the parent's key type fixes the suite.
An Ed25519 key can sign only `Ed25519`, and `WebAuthn-ES256` is barred from certificates, so a
P-256 key can sign a certificate only under `ES256`. A certificate whose `algorithm` does not
match its parent's key type fails with `suite_key_mismatch` (§3.3). Changing the field can
therefore only make a certificate fail. It can never make a forged certificate pass.

## §3.3 Verifying one certificate (amended)

To verify certificate `c` on a candidate path, given the parent's public key `P` and the parent's
effective scope `E` (empty for the root), a verifier MUST apply these checks **in this order**.
It stops at the first that fails.

| # | Check | On failure |
|---|---|---|
| 1 | `child_public_key_pem` is a canonical Ed25519 or P-256 key (NOMOS-SPEC-010 §3.1) | `ISSUER_NOT_RECOGNIZED`, `invalid_key` |
| 2 | `kid(child_public_key_pem)` equals `child_kid` | `ISSUER_NOT_RECOGNIZED`, `kid_mismatch` |
| 3 | `E` permits `algorithm` (§3.6) | `OUT_OF_SCOPE`, dimension `suite`, `suite_not_permitted` |
| 4 | `signature` verifies under `P`, suite `algorithm`, over the §3.2 payload (NOMOS-SPEC-010) | `ISSUER_NOT_RECOGNIZED`, with the NOMOS-SPEC-010 reason: `bad_signature`, `bad_encoding`, `high_s`, `suite_key_mismatch` |
| 5 | `issued_at` and `expires_at` parse, and `issued_at ≤ now ≤ expires_at` | `ISSUER_NOT_RECOGNIZED`, `bad_time`, `not_yet_valid` or `expired` |
| 6 | `c`'s fingerprint (§5.4) is not revoked | `CERTIFICATE_REVOKED` |
| 7 | `child_kid` is not revoked (§5.2) | `KEY_REVOKED` |
| 8 | `scope` parses (§3.4, §3.6, §3.7) | `OUT_OF_SCOPE`, `malformed_scope` |
| 9 | `scope` does not widen any dimension of `E` | `OUT_OF_SCOPE`, the dimension, `widening` |

The child's effective scope is `E` narrowed by `c`'s scope (§3.8).

The order is normative because two verifiers must report the same failure for the same path.
Check 3 precedes check 4: a parent that may not sign under a suite fails on scope, whether or not
its signature happens to verify.

**A malformed scope is `OUT_OF_SCOPE`, not `MALFORMED`.** The scope is signed content of a
certificate its issuer really made. It fails that candidate path. It does not fail the
presentation, because another, well-formed path may still resolve the key. `MALFORMED` is reserved
for the shape of the presentation itself (§4.4).

## §3.6 The `suite` dimension (new)

| Dimension | Value | Narrowing | Matched against |
|---|---|---|---|
| `suite` | A comma-separated set of NOMOS-SPEC-010 suite names, exactly as the registry spells them: `Ed25519`, `ES256`, `WebAuthn-ES256` | Subset | The suite of every signature the key makes: its certificates, its staples, its seal or its statement |

1. A key whose effective scope has a `suite` term may sign only under the suites in that set.
2. A key whose effective scope has no `suite` term may sign under any suite its key type
   supports, **except `WebAuthn-ES256`**.
3. `WebAuthn-ES256` MUST stand alone in a `suite` set. A set that contains it together with any
   other suite is a malformed scope.
4. A set naming a suite outside the registry, or naming one twice, is a malformed scope.

Rules 2 and 3 together make an enrolled passkey an approval key and nothing else.
- **Rule 2** means a passkey is accepted for `WebAuthn-ES256` only if its certificate says so.
- **Rule 3** means a key certified for `WebAuthn-ES256` can sign nothing else. It cannot sign
  certificates, so it cannot be a parent. It cannot seal rules. It cannot testify, because
  testimony is never `WebAuthn-ES256` (NOMOS-SPEC-008 0.6.0 §6.3).

Without rule 3, a key certified `suite:ES256,WebAuthn-ES256` could approve by passkey *and*
testify, which RFC-0001 §5.3 states must not be possible.

## §3.7 The `approver` dimension (new)

| Dimension | Value | Narrowing | Matched against |
|---|---|---|---|
| `approver` | One opaque identifier of a person, issued by the certifying institution. It contains no comma. | Equality: a child MAY repeat its parent's value and MUST NOT change it | Read by NOMOS-SPEC-008 when it counts consents |

1. `approver` is admitted only on a key resolved for a **consent** statement. On a key resolved to
   seal an artifact, or to sign testimony, it is out of scope (§3.8).
2. The identifier need not reveal who the person is. It must be the same across the keys of one
   person, and different between people. An institution typically certifies a person's
   enrolment key with `approver:<id>`, and that key certifies each of the person's passkeys.

**Where the counting rule lives.** RFC-0001 §5.4 also states that a consent key MUST carry exactly
one `approver` term. That rule is about how consents are counted, so it is specified, and
enforced, by NOMOS-SPEC-008 0.6.0 §4.4 together with the counting rule it serves.
- **This revision defines the dimension**: its grammar, narrowing and admission.
- **Exactly one term** is already guaranteed by §3.4: a dimension appears at most once per
  certificate, and equality narrowing keeps a single value along a path.
- **Under NOMOS-SPEC-008 0.5.0**, which counts distinct keys, a consent key without an `approver`
  term remains admissible.

**Open for NOMOS-SPEC-008 0.6.0: the approver must not depend on the path.** A key's
`approver` value is read from its effective scope, which comes from the path chosen. If the same
key had two admitted paths carrying different `approver` values, the carrier would choose the
person a consent counts for by choosing which certificates to send. The carrier would then be an
input to the verdict (RFC-0001 invariant 2). Rev. 1.9 counts no consents, so no verdict here
depends on it. 0.6.0 MUST make the counted identity path-independent. The proposed rule: a
consent is `CONSENT_INVALID` (`approver_ambiguous`) when the admitted paths to its key do not all
carry the same `approver`.

## §3.8 Effective scope and admission (new)

**Order.** A key's effective scope is an ordered set of terms. A term is placed where its
dimension first appears along the path, root first. Within one certificate, terms keep the order
in which that certificate's `scope` string lists them. When a later certificate narrows a
dimension, the term keeps its original position and takes the narrower value. A verifier that
reports `effective_scope` writes the terms in this order, separated by single spaces, and omits
the field when the scope is empty.

**Admission.** Every resolution has a purpose. A purpose admits or refuses an effective scope, and
names the dimension that refused it.

*For an artifact sealed under suite `s`* (§4):
- Examine each term in order. The first term that refuses is reported:
  - `artifact`, `industry` or `jurisdiction` refuses when the artifact's `meta` does not match it
    (§3.4);
  - `suite` refuses when its set does not contain `s`;
  - any other dimension refuses. This covers `claim`, `consent` and `approver` (§3.5) and any
    unknown dimension.
- If there is no `suite` term and `s` is `WebAuthn-ES256`, the scope is refused on `suite`.

*For a statement of kind `k` (`claim` or `consent`) about name `n`, signed under suite `s`, for an
act whose authority artifact carries `meta`* (§4.6):
- If the scope has no `k` term, or its set does not contain `n`, the scope is refused on `k`.
- Otherwise examine each term in order. The first term that refuses is reported:
  - `artifact`, `industry` or `jurisdiction` refuses as above, against `meta`;
  - `suite` refuses as above;
  - `approver` refuses unless `k` is `consent`;
  - any other dimension, including the other statement kind, refuses.
- If there is no `suite` term and `s` is `WebAuthn-ES256`, the scope is refused on `suite`.

## §4.2a Target-first resolution (step 4 replaced)

Steps 1–3, 5 and 6 of 1.8.0 are unchanged. Step 4 becomes:

> 4. Validate each candidate path root-first, certificate by certificate, with the §3.3 checks.
>    Then apply the purpose's admission (§3.8) to the target's effective scope. A candidate that
>    fails any check, or whose scope the purpose refuses, is a **failed candidate**, and the next
>    candidate is tried.

Step 6 still applies. If no candidate validates, the failure of the first candidate tried is
returned, in fingerprint order. A refusal at admission is reported as `OUT_OF_SCOPE` with the
refusing dimension and no `reason_code`.

**Why this is sound.** Every candidate path is a chain of delegations its issuers actually made.
The one chosen grants no more than its own delegators granted (Proposition 2 of R-19 holds per
path). A revoked key fails every path that reaches it (Proposition 3 holds, because check 7 runs
on every candidate). The chosen path does not depend on presentation order (Proposition 4 holds,
because candidates are still tried in fingerprint order). What changes is only which delegation
is relied on when several exist. 1.8.0 could rely on one that did not cover the purpose, and
refuse, while another delegation that did cover it was present.

## §4.4 Outcomes (amended)

| Decision | `reason_code` | Meaning |
|---|---|---|
| `ALLOWED` / `RESOLVED` | — | The key resolves for this purpose; for an artifact, the seal also verifies (§4.7) |
| `ISSUER_NOT_RECOGNIZED` | `no_certificate_for_root`, `chain_broken`, `invalid_key`, `kid_mismatch`, `bad_signature`, `bad_encoding`, `high_s`, `suite_key_mismatch`, `bad_time`, `not_yet_valid`, `expired` | No candidate path validates |
| `KEY_REVOKED` | — (`revoked_kid`) | A key on the first candidate, or the root, is revoked |
| `CERTIFICATE_REVOKED` | — (`revoked_fingerprint`) | A certificate on the first candidate is revoked |
| `OUT_OF_SCOPE` | `widening`, `malformed_scope`, `suite_not_permitted` | A certificate on the first candidate is at fault (`dimension` given for `widening` and `suite_not_permitted`) |
| `OUT_OF_SCOPE` | absent | Every certificate is sound; the purpose refused the scope on `dimension` |
| `SEAL_INVALID` | `hash_mismatch`, or a NOMOS-SPEC-010 reason | The key resolves, but the artifact's seal does not verify under it |
| `MALFORMED` | `bad_chain`, `chain_over_length_cap`, `bad_certificate`, `bad_artifact`, `unsealed_artifact`, `seal_algorithm`, `bad_staples`, `bad_staple`, `bad_root` | The presentation's shape is wrong; nothing cryptographic was attempted |

`MALFORMED` gates are applied in this order, before any resolution: the certificate set, then the
artifact and its seal, then the staples. A certificate is `bad_certificate` when it is not an
object, when any of `parent_kid`, `child_kid`, `child_public_key_pem`, `issued_at`, `expires_at`,
`algorithm` or `signature` is not a non-empty string, when `algorithm` is not `Ed25519` or
`ES256`, or when `scope` is present and not a string.

A verifier reports `decision`, and `reason_code`, `dimension`, `revoked_kid` and
`revoked_fingerprint` where the table gives them. For `ALLOWED` it also reports `leaf_kid`,
`path` (the kids from the root to the target), `effective_scope` (§3.8) and `revocation_checked`
(§5.5). Two conformant verifiers produce the same values for these fields.

## §4.6 Resolving a chain for a statement (amended)

The statement's suite is part of its purpose (§3.8). The calling specification says which suites
each statement may use: NOMOS-SPEC-008 0.5.0 statements are `Ed25519`, and 0.6.0 adds `ES256`
for testimony and in-force statements, and `WebAuthn-ES256` for consent.

## §4.7 The seal under the resolved key (new)

An artifact presented for chain verification MUST carry `seal.signature_algorithm` equal to
`Ed25519` or `ES256` (NOMOS-SPEC-001 §3.10, NOMOS-SPEC-010 §6). Any other value, including an
absent field, an HMAC seal or an RS256 seal, is `MALFORMED` (`seal_algorithm`): a chain of public
keys cannot vouch for a seal that is not publicly verifiable under one.

After the key resolves, the verifier checks the seal (NOMOS-SPEC-001 §8): the hash, then the
signature over `JCS({hash, signed_by})` under the resolved key with suite
`seal.signature_algorithm`. The seal is checked once, after path selection, and this is sound:
every candidate path ends at the same certificate key, because `kid` is a hash of the key and
check 2 binds the two. Path selection changes which delegation is relied on, never which key
signed. Consequently `OUT_OF_SCOPE` is always decided before `SEAL_INVALID`.

## §5.5 Freshness staples (amended)

A staple's `algorithm` is `Ed25519` or `ES256`. A staple counts for a hop only if all of the
following hold:
- the parent's effective scope permits that suite;
- it verifies under the parent's key;
- `as_of ≤ now ≤ valid_until`.

A staple that is not an object, lacks a required string field, or names another suite is
`MALFORMED` (`bad_staple`). A well-formed staple that fails these conditions simply does not
count. The root is never staple-coverable and is not counted, and a path with no certificate is
`unchecked`. Everything else in §5.5 is unchanged.

## Compatibility

| Change | Effect |
|---|---|
| Scope-aware selection | Changes outcomes only from `OUT_OF_SCOPE` to `ALLOWED`/`RESOLVED`, and only where an in-scope path was present |
| `suite`, `approver` | Older verifiers do not recognize them and fail closed (§3.4) |
| ES256, P-256 keys | Older verifiers reject them (`MALFORMED` or `ISSUER_NOT_RECOGNIZED`); existing Ed25519 objects are unchanged, and so are their fingerprints |
| `seal.signature_algorithm` required | A seal without it is `MALFORMED`. The reference platform has always written it. The 1.7.0 vector generator wrote `algorithm` instead, which was non-conformant; it is corrected and its vectors regenerated, with no verdict changed |
| Check order (§3.3) | New outcomes only where 1.8.0 left the order open: an unparseable child key is now `invalid_key`, previously reported differently by different implementations |
| Scope before seal (§4.7) | NOMOS-SPEC-008 0.5.0 §6 step 5 lists the seal check before scope admission. Under this revision an artifact that is both out of scope and tampered is `OUT_OF_SCOPE`, not `SEAL_INVALID`. No published vector has both properties; 0.6.0 aligns its step 5 |

## Relation to RFC-0001 (errata)

This revision implements RFC-0001 §5. Four points differ from the RFC text, and each is recorded
here rather than silently adopted:

1. **Suite names.** The RFC's example `suite:webauthn-es256` is lowercase. Scope values use the
   registry's exact spelling, `suite:WebAuthn-ES256`. Every object has one canonical form
   (RFC-0001 invariant 5).
2. **WebAuthn-ES256 stands alone** (§3.6 rule 3). The RFC does not state this. Without it, the
   RFC's own claim that "an enrolled passkey is therefore an approval key and nothing else" does
   not hold.
3. **The approver MUST is enforced by NOMOS-SPEC-008 0.6.0** (§3.7), together with the counting
   rule it serves. It is not enforced at resolution.
4. **A malformed scope is `OUT_OF_SCOPE`** (§3.3). The two earlier implementations disagreed on
   this, one reporting `MALFORMED` and the other `OUT_OF_SCOPE`. The RFC was silent.

## §8.2 Known gaps (updated)

- **Implementations.** Rev. 1.9 has two implementations, both written by the authors, so neither
  is independent:
  - `python/nomos/chain.py`, shared by the SPEC-007 and SPEC-008 Python references;
  - the TypeScript prototype (`prototype/chain-of-trust`), updated from its 1.7.0 walk.

  Both pass `chain-of-trust-vectors/vectors-1.9.json`: 37 cases, each in every presentation order
  it lists, with expectations written by hand. They agree on every reported field. Together they
  show the text is sufficient to reproduce the verdicts. They do not show that a third party can
  reproduce them, and the call for an independent implementation in 1.7.0 §8.2 stands.
- **The hosted platform's verifier** implements 1.8.0 §4.2a and still selects paths without
  regard to scope. Until it adopts this revision it can return `OUT_OF_SCOPE` where a conformant
  verifier returns `ALLOWED`. It cannot wrongly allow.

---

## Appendix B — The 1.8.0 selection defect (non-normative)

These are R-19 §5.6's example and vector `scope_aware_selection_r19`. An issuer key is certified
twice from the same root:
- **directly**, with scope `industry:insurance`;
- **through an intermediate**, with no scope.

The direct certificate has the lower fingerprint, so it is tried first. The artifact declares
`industry: financial/lending`.

- **1.8.0:** the direct path validates cryptographically and is chosen. Its scope does not cover
  the artifact, so the verdict is `OUT_OF_SCOPE`. Presented without the direct certificate, the
  same artifact is `ALLOWED`.
- **1.9.0:** the direct path fails admission, so it is a failed candidate. The intermediate path
  validates, and the verdict is `ALLOWED` in every presentation order.

A mutant of the Python reference that checks scope only after selection fails exactly the two
vectors built on this pattern: this one, and `scope_aware_selection_for_a_witness`.

## Changelog

- **1.9.0 (proposed)** — scope-aware path selection; Ed25519 and ES256 certificates, staples and
  seals; `suite` and `approver` dimensions; normative check order and outcome table; effective
  scope order; seal after selection; RFC-0001 errata.
