# RFC-0001: Protocol changes for Act enforcement as infrastructure

**Status:** Accepted by the Working Group, 2026-10-26. Implementation in progress.
**Proposed:** 2026-10-26
**Authors:** NOMOS Protocol Working Group
**Affects:** NOMOS-SPEC-001 (amendment), NOMOS-SPEC-007 (rev. 1.9), NOMOS-SPEC-008 (0.6.0), and two new specifications, NOMOS-SPEC-009 (Discovery and Submission) and NOMOS-SPEC-010 (Signature Suites)

---

## 1. Purpose

NOMOS-SPEC-007 and NOMOS-SPEC-008 make an Act verifiable by any relying party that pins a root.
This RFC makes them deployable as public infrastructure. Any issuer, relying party, witness,
approver and carrier can take part, discover one another without prior arrangement, and hold
their own keys in their own custody.

It changes nothing that an existing conformant verifier relies on, except where §9 says so.

## 2. Invariants every change below preserves

1. **The verdict is computed by the relying party.** No change introduces a call to an issuer,
   to NOMOS or to any third party on the path to a verdict.
2. **The carrier is not an input.** No change gives the carrier a field that affects the verdict
   beyond the action it proposes.
3. **Authority-conferring keys stay with their holders.** Every signature the protocol accepts can
   be produced by a key the signer holds in its own KMS, HSM, authenticator or local signer.
4. **Fail closed.** Anything a verifier does not recognize is rejected, never skipped.
5. **One canonical form.** Every object has exactly one valid encoding, so two verifiers can never
   disagree on what was signed.

## 3. Summary of changes

| # | Change | Where | Why |
|---|---|---|---|
| 1 | A closed registry of signature suites: Ed25519, ES256, WebAuthn-ES256 | NOMOS-SPEC-010 (new) | Customers hold keys in KMS and HSM, where Ed25519 support is uneven and P-256 is universal; approvers sign with passkeys. Today the specs disagree on algorithms. |
| 2 | Scope-aware path selection | NOMOS-SPEC-007 rev. 1.9 | A valid extra certificate can turn an authorization into `OUT_OF_SCOPE` (R-19 §5.6). |
| 3 | A `suite` scope dimension, and suites for certificates and certified keys | NOMOS-SPEC-007 rev. 1.9 | Domain separation: a passkey certified for approvals can do nothing else. |
| 4 | An `approver` scope dimension; consents counted by distinct approver, not distinct key | NOMOS-SPEC-007 rev. 1.9, NOMOS-SPEC-008 0.6.0 | With passkeys one person holds several keys. Counting keys would let one person satisfy dual control. |
| 5 | WebAuthn consent statements | NOMOS-SPEC-008 0.6.0 | Approval by passkey, bound to the exact Act. |
| 6 | An explicit currency policy, including record-only mode | NOMOS-SPEC-008 0.6.0 | Issuer-key compromise is contained only in record-only mode (R-19 Theorem 9.4); the choice must be declared, not implied. |
| 7 | Equal-priority escalations naming different escalations are refused | NOMOS-SPEC-001 amendment 2.3.0 | Removes the authoring hazard left after SPEC-008 0.5.0 (R-19 §7.5, option (b)). |
| 8 | Discovery documents and an HTTP binding for submitting Acts | NOMOS-SPEC-009 (new) | A carrier must be able to find and use a relying party it has never met. |

---

## 4. NOMOS-SPEC-010: Signature Suites (new)

### 4.1 The registry

| Suite | Key type (SPKI) | Message signed | Signature encoding | May sign |
|---|---|---|---|---|
| `Ed25519` | Ed25519, OID 1.3.101.112 | The JCS payload bytes | 64 bytes, base64 | Every NOMOS object |
| `ES256` | EC P-256 (id-ecPublicKey, prime256v1), uncompressed point | SHA-256 of the JCS payload (ECDSA) | IEEE P1363 `r‖s`, 64 bytes, base64; `s` MUST be at most n/2 | Every NOMOS object |
| `WebAuthn-ES256` | EC P-256, uncompressed point | `authenticatorData ‖ SHA-256(clientDataJSON)`, where the challenge commits to the JCS payload (§6.1) | ASN.1 DER ECDSA, as authenticators produce it | Consent statements only |

The registry is closed. A verifier MUST reject any other suite name, and MUST reject a signature
whose declared suite does not match the type of the key that resolved for it. There is no
negotiation, no `none`, and no fallback from one suite to another.

### 4.2 Canonical keys

A key id remains `base64url(SHA-256(SPKI DER))`, first 16 characters. A P-256 key MUST use the
uncompressed point form; a verifier MUST reject a compressed point. Otherwise one key would have
two ids.

### 4.3 Why low-S for ES256

ECDSA signatures are malleable: `(r, s)` and `(r, n − s)` both verify. Certificate fingerprints
are computed over the signed payload, not the signature (NOMOS-SPEC-007 §5.4), so malleability
cannot dodge a revocation. But a testimony statement's signature is part of the testimony digest
(NOMOS-SPEC-008 §4.3), so a malleable form would let anyone change an Act's binding digest without
changing a single fact. Requiring low-S gives each statement exactly one valid encoding
(invariant 5). WebAuthn consents are exempt: the authenticator chooses their encoding, and
consents are not part of any digest.

### 4.4 Why not RSA or HMAC

NOMOS-SPEC-001 permits RS256 and HMAC-SHA256 seals. Artifacts sealed that way stay valid under
SPEC-001, per DEPRECATION.md. NOMOS-SPEC-007 and NOMOS-SPEC-008 never accepted either, and this
registry does not add them: HMAC is not publicly verifiable, and RSA adds key-size and padding
choices without serving any requirement the two elliptic suites leave open.

### 4.5 Seals

An artifact may be sealed under `Ed25519` or `ES256`. Because adding a sealing algorithm requires a
new specification number (CONTRIBUTING.md), ES256 seals are defined here, in NOMOS-SPEC-010, and
recognized by verifiers that implement it. A verifier that implements only NOMOS-SPEC-001 rejects
them, failing closed.

---

## 5. NOMOS-SPEC-007 revision 1.9

### 5.1 Suites

A certificate's `algorithm` names the suite of its **parent's** signature: `Ed25519` or `ES256`.
`child_public_key_pem` may carry an Ed25519 or a P-256 key. A key whose effective scope restricts
it to `WebAuthn-ES256` MUST NOT be accepted as the parent of any certificate.

### 5.2 Scope-aware path selection (replaces §4.2a step 4)

Validate each candidate path root-first with the §3.3 checks, the certificate and key revocation
checks **and the scope admission check for the purpose of the resolution**: §3.4 for an artifact,
§3.4.1 for a statement, and the `suite` rule (§5.3) for the signature presented. A candidate path
that fails any of these is a failed candidate, and the next is tried.

This is sound because every candidate is a delegation its issuer actually made. Accepting any
in-scope one grants no more than the delegator granted. Failure reporting is unchanged: if no
path validates, the failure of the first path tried is returned.

### 5.3 The `suite` dimension (new)

| Dimension | Value | Narrowing | Matched against |
|---|---|---|---|
| `suite` | A comma-separated set of suite names, e.g. `suite:webauthn-es256` | Subset | The suite of the signature being verified |

If absent, a key may use the suites its type supports, except `WebAuthn-ES256`. `WebAuthn-ES256`
is accepted only when the key's effective scope contains `suite:webauthn-es256` explicitly. An
enrolled passkey is therefore an approval key and nothing else.

### 5.4 The `approver` dimension (new)

| Dimension | Value | Narrowing | Matched against |
|---|---|---|---|
| `approver` | One opaque identifier of a person, issued by the certifying institution | Equality: a child MAY repeat it and MUST NOT change it | Counted by NOMOS-SPEC-008 §4.4 |

A key with a `consent` term MUST also carry exactly one `approver` term in its effective scope;
otherwise its consents are `CONSENT_OUT_OF_SCOPE`. The identifier is opaque and need not reveal
who the person is. It only has to be the same across the keys of one person, and different
between people.

### 5.5 Unchanged

Target-first resolution, the 20-certificate bound, revocation, staples, and the outcome classes.

---

## 6. NOMOS-SPEC-008 version 0.6.0

### 6.1 WebAuthn consent statements

```jsonc
{
  "binding_digest":     "<hex, §4.3>",
  "role":               "TRAVEL_APPROVER",
  "decision":           "approve",
  "signed_at":          "2026-11-02T09:14:05.000Z",
  "kid":                "<the passkey's key id>",
  "algorithm":          "WebAuthn-ES256",
  "authenticator_data": "<base64url>",
  "client_data_json":   "<base64url>",
  "signature":          "<base64url, DER>"
}
```

Let `P = JCS({ binding_digest, role, decision, signed_at, kid })`, the payload of §4.2, unchanged.
A relying party MUST accept the statement only if:

1. the key resolves (NOMOS-SPEC-007 §4.6) and its effective scope admits `consent` for `role`,
   carries one `approver` term, and contains `suite:webauthn-es256`;
2. `client_data_json` decodes to UTF-8 JSON with `type` equal to `"webauthn.get"` and `challenge`
   equal to `base64url(SHA-256(P))`, unpadded;
3. `authenticator_data` is at least 37 bytes, with the user-present (bit 0) **and user-verified
   (bit 2)** flags set;
4. `signature` verifies, under the resolved key, over `authenticator_data ‖
   SHA-256(client_data_json)`.

Failures are `CONSENT_INVALID`, with reasons `bad_client_data`, `challenge_mismatch`,
`user_not_verified` and `bad_signature`.

Because the challenge commits to `P`, the approval binds the exact Act (through
`binding_digest`), the role, the decision and the time. The passkey's binding to its origin is
enforced by the authenticator and the browser. Once the key itself is certified, the protocol
does not need that binding for correctness, so no origin check is required. A relying party
SHOULD record `client_data_json.origin` in its receipt for audit.

### 6.2 Counting consents (replaces §4.4's last condition)

An escalation needing `n` consents is satisfied by valid consents from **`n` distinct approver
identifiers** (§5.4), not `n` distinct keys. Two consents from different keys of one approver
count once.

### 6.3 Suites for other statements

Testimony and in-force statements may be signed under `Ed25519` or `ES256`, never
`WebAuthn-ES256`.

### 6.4 Currency policy (makes §5.4 explicit)

A relying party MUST operate under exactly one declared currency policy, for each authority it
accepts:

- **`record`:** the relying party establishes the version in force only from its own record. It
  MUST NOT accept an in-force statement. An authority with no record is `VERSION_UNVERIFIED`,
  reason `not_in_record`.
- **`record_or_statement`:** the behaviour of 0.5.0.

Receipts record the policy. **`record` is RECOMMENDED for any state whose compromise would be
material**, because it is the only policy under which compromise of an issuer's key cannot
authorize anything new (R-19, Theorem 9.4).

---

## 7. NOMOS-SPEC-001 amendment 2.3.0: unambiguous escalation

A producer MUST NOT seal an artifact containing two `escalate` decisions of equal `priority` that
name different escalations. A relying party evaluating an Act MUST reject such an artifact as
`MALFORMED`, reason `ambiguous_escalation`. Historical verification of artifacts sealed before this
amendment is unaffected: the rule governs new authorizations only, as NOMOS-SPEC-008 §5.4 already
separates the two.

This closes the authoring hazard R-19 §7.5 identified: under first-listed tie-breaking, an
institution that listed its dual-approval rule second would get single approval whenever both
applied. The author resolves the ambiguity by assigning distinct priorities.

---

## 8. NOMOS-SPEC-009: Discovery and Submission (new)

### 8.1 Principle

A discovery document tells a carrier where to go and what to bring. It never decides anything.
Everything it states that bears on the verdict is checked again by the verifier, so a false
document can make a carrier's Act fail, never succeed.

### 8.2 Documents

Each is served over HTTPS at a well-known path on its owner's domain, MAY additionally be signed
(NOMOS-SPEC-010) for offline attribution, and carries `version` and `valid_until`.

| Document | Path | Contents |
|---|---|---|
| Relying party | `/.well-known/nomos-relying-party` | Its audience id; the Act endpoint; the roots it pins (public keys); the authorities it accepts, each with its action types and currency policy; the relying-party facts it supplies; its maximum validity window and Act size; the suites it accepts for consent |
| Issuer | `/.well-known/nomos-issuer` | Its sealing key ids; its authorities, with each one's current version, seal hash and fetch location; its revocation sources; its in-force statement endpoint |
| Witness | `/.well-known/nomos-witness` | The claims it is certified for; its statement endpoint; how a requester proves it may receive a subject's facts |

The witness's last field is deliberate. Whether a witness may disclose a subject's facts to a
given requester is the witness's own access-control decision, not the protocol's. The protocol
only says where to ask.

### 8.3 Planning

Given an authority and a proposed action, a carrier derives what to bring from the authority's
own `data_contract`, using the relying party's document to see which facts the relying party
supplies itself and the witness documents to see where each claim is stated. Planning is
advisory and runs the verifier's own logic, so a carrier and a relying party cannot disagree on
what is required.

### 8.4 Submission binding

`POST` to the Act endpoint, with media type `application/nomos-act+json`, carrying one Act.

| Verdict | HTTP status | Body |
|---|---|---|
| `AUTHORIZED`, committed | 201 | The receipt (NOMOS-SPEC-008 §9) |
| `ESCALATED` | 202 | The binding digest, and each escalation's role and required number of approvers |
| `INCOMPLETE` | 422 | `open_rules` and `open_facts` |
| `DENIED` | 403 | The deciding rule |
| Any rejection of form, chain, testimony or consent | 400 | `decision` and `reason_code`, exactly as NOMOS-SPEC-008 §6 names them |
| `REPLAYED` | 409 | The `act_id` already committed |

The nonce is the idempotency key. Resubmitting a committed Act returns 409 with the original
receipt, never a second commit.

---

## 9. Compatibility

| Change | Effect on existing verifiers and artifacts |
|---|---|
| Suites (§4), `suite` and `approver` dimensions (§5) | Older verifiers fail closed on the new suites and dimensions. Existing Ed25519 objects are unchanged. |
| Scope-aware path selection (§5.2) | Only changes outcomes from `OUT_OF_SCOPE` to `AUTHORIZED` where a valid in-scope path existed. |
| Counting by approver (§6.2) | **Breaking for consent keys without an `approver` term.** Migration: re-certify approver keys with `approver` terms before enabling 0.6.0. |
| Currency policy (§6.4) | Existing behaviour is `record_or_statement`; declaring a policy is new. |
| Ambiguous escalation (§7) | **Breaking for any artifact with the pattern**, for new authorizations. None of the platform's 139 repository artifacts, its 5 public demonstration authorities or its EU AI Act authority contains it. |

## 10. Conformance additions

Each change ships with vectors in the same release, passing in the Python reference and the
TypeScript verifier with field-for-field agreement:

- **Suites:** an ES256 chain; an ES256 statement; high-S rejected; a compressed point rejected; a
  declared suite that mismatches the key rejected.
- **Paths:** a narrow direct path plus a broad intermediate path, authorized under §5.2.
- **`suite` dimension:** a passkey key used for testimony rejected; a passkey key as a parent
  rejected.
- **Approvers:** two keys of one approver counted once; two approvers counted twice; a consent key
  without an `approver` term rejected.
- **WebAuthn:** valid consent; user-verified flag missing; wrong challenge; wrong `type`; a
  challenge made for a different role.
- **Currency:** record-only mode given an in-force statement and no record.
- **Escalation:** an ambiguous artifact rejected.
- **Submission:** each status code above.

The derived-mutant suite is extended to every new field.

## 11. Decisions requested

1. Approve the eight changes as proposed, or amend.
2. Confirm that NOMOS-SPEC-009 and NOMOS-SPEC-010 are new numbered specifications, entering as
   Draft.
3. Confirm the two breaking changes (§9) and their migration paths.
