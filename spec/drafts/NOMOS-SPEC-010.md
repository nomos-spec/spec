# NOMOS-SPEC-010: Signature Suites

**Status:** Draft
**Version:** 0.1.0
**Proposed:** 2026-10-26 (RFC-0001, accepted)
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group
**Used by:** NOMOS-SPEC-007 rev. 1.9, NOMOS-SPEC-008 0.6.0, NOMOS-SPEC-009

---

## Abstract

Every signature a NOMOS verifier accepts is made under one of three suites: `Ed25519`, `ES256` and
`WebAuthn-ES256`. This specification defines them once, so that every NOMOS specification that
verifies a signature applies the same rules: which key types exist, which bytes are signed, how a
signature is encoded, and when a signature is refused.

It exists because the keys that confer authority must stay in their holders' custody. Issuers and
witnesses hold keys in KMS and HSM products, where Ed25519 support is uneven and ECDSA P-256 is
universal; approvers hold passkeys, which sign through WebAuthn. A protocol that accepted only
Ed25519 would push key custody onto whoever could produce Ed25519 signatures, which in practice
means the platform.

## 1. Terminology

The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119.

- **Payload:** the bytes a NOMOS specification says are signed, always
  `JCS(<object fields named by that specification>)` (RFC 8785).
- **Suite:** a named rule set that fixes a key type, the message derived from a payload, and a
  signature encoding.
- **SPKI:** a SubjectPublicKeyInfo structure (RFC 5280 §4.1.2.7), DER-encoded, carried as PEM.

## 2. The registry (normative)

| Suite | Key type | Message signed | Signature encoding |
|---|---|---|---|
| `Ed25519` | Ed25519 (RFC 8410, OID 1.3.101.112) | The payload | 64 bytes, base64 (RFC 4648 §4), padded |
| `ES256` | ECDSA P-256 (RFC 5480: id-ecPublicKey, namedCurve prime256v1) | SHA-256 of the payload, per ECDSA (FIPS 186-5) | IEEE P1363: `r ‖ s`, each a 32-byte big-endian integer; 64 bytes, base64 |
| `WebAuthn-ES256` | ECDSA P-256, as above | `authenticator_data ‖ SHA-256(client_data_json)` (§5) | ASN.1 DER `Ecdsa-Sig-Value` (RFC 3279 §2.2.3), base64url (RFC 4648 §5) |

Every base64 and base64url value MUST be in its canonical encoding: a verifier decodes it,
re-encodes it, and rejects it (`bad_encoding`) unless the result is identical. Otherwise one
signature would have several encodings.

The registry is closed. A verifier MUST reject a signature whose suite is not in this table. There
is no `none` suite, no negotiation and no fallback: a signature that fails under its declared suite
MUST NOT be retried under another.

The specification that defines an object states which suites it accepts for that object.
`WebAuthn-ES256` is defined for consent statements only (NOMOS-SPEC-008 0.6.0 §4).

## 3. Keys (normative)

### 3.1 Canonical encoding

A key has exactly one encoding, and therefore exactly one key id. The canonical encodings are fixed
byte for byte, so that no library's re-encoding behaviour can decide which keys exist:

| Key type | DER SubjectPublicKeyInfo | Length |
|---|---|---|
| Ed25519 | `302a300506032b6570032100` followed by the 32-byte public key | 44 bytes |
| P-256 | `3059301306072a8648ce3d020106082a8648ce3d03010703420004` followed by the 32-byte X and 32-byte Y coordinates | 91 bytes |

A verifier MUST base64-decode the PEM body (canonically, §2) and reject the key (`invalid_key`)
unless the DER is exactly one of these forms. For P-256 it MUST also reject a point that is not on
the curve. A compressed point, explicit curve parameters, a key of any other type, or any other
alternative encoding is rejected with the same reason, whatever a cryptographic library would
accept or re-emit. One reason for every such key means no verifier has to classify a key it
rejects, and no two verifiers can disagree about how.

### 3.2 Key ids

A key id is `base64url(SHA-256(SPKI DER))`, unpadded, first 16 characters, unchanged from
NOMOS-SPEC-001 §8.4.

### 3.3 Suite and key type must agree

A verifier MUST determine the key's type from its SPKI and MUST reject a signature whose declared
suite does not belong to that type (`Ed25519` for Ed25519 keys; `ES256` or `WebAuthn-ES256` for
P-256 keys). The key decides what it can be; a field in a signed object cannot change that.

## 4. `ES256` signatures (normative)

A verifier MUST reject an `ES256` signature unless:

1. it decodes to exactly 64 bytes;
2. `r` and `s` are each in `[1, n − 1]`, where `n` is the P-256 group order;
3. `s ≤ n / 2` (low-S);
4. it verifies over `SHA-256(payload)` under the key.

**Why low-S.** ECDSA signatures are malleable: if `(r, s)` verifies, so does `(r, n − s)`. Some
NOMOS digests cover signature bytes (the testimony digest, NOMOS-SPEC-008 §4.3), so a malleable
signature would let anyone alter a digest without altering any fact. Requiring low-S gives each
signed object exactly one valid encoding. A signer whose implementation produces high-S signatures
MUST replace `s` with `n − s` before publishing.

## 5. `WebAuthn-ES256` signatures (normative)

A `WebAuthn-ES256` signature is a WebAuthn assertion (W3C Web Authentication, Level 2 or later)
whose challenge commits to a NOMOS payload. The signed object carries three fields:
`authenticator_data`, `client_data_json` and `signature`, each base64url, unpadded.

A verifier MUST reject the signature unless:

1. `client_data_json` decodes to UTF-8 and parses as a JSON object;
2. its `type` is exactly `"webauthn.get"`;
3. its `challenge` is exactly `base64url(SHA-256(payload))`, unpadded;
4. `authenticator_data` is at least 37 bytes long;
5. its flags byte (offset 32) has the user-present bit (`0x01`) **and** the user-verified bit
   (`0x04`) set;
6. `signature` is a valid DER `Ecdsa-Sig-Value` that verifies, under the key, over
   `authenticator_data ‖ SHA-256(client_data_json)`, where `client_data_json` is the exact decoded
   bytes, not a re-serialization.

**User verification is required.** A user-present-only assertion proves that someone touched a
device, not that its owner approved. NOMOS consents are approvals by a person in a role, so the
device must have verified the person (biometric or PIN).

**Origin and relying-party id.** WebAuthn binds a credential to the website that registered it, and
the browser and authenticator enforce that binding. A NOMOS verifier does not need it for
correctness, because the key itself is certified (NOMOS-SPEC-007) and the challenge binds the exact
payload. A verifier SHOULD record `client_data_json.origin` for audit.

**No low-S rule.** The authenticator chooses the encoding, and WebAuthn signatures are not part of
any NOMOS digest.

**The signature counter is not checked.** Counters are unreliable across synced passkeys, and a
cloned credential is addressed by key revocation (NOMOS-SPEC-007 §5).

## 6. Signing (normative for producers)

- `Ed25519` signers sign the payload bytes.
- `ES256` signers MUST output the P1363 encoding with low-S. Deterministic nonces (RFC 6979) are
  RECOMMENDED; the verifier cannot tell the difference, but determinism removes a class of nonce
  failures.
- `WebAuthn-ES256` signatures are produced by the approver's authenticator through
  `navigator.credentials.get`, with `challenge` set to `SHA-256(payload)` and
  `userVerification: "required"`.

A NOMOS signer never needs the private key outside its custody: `Ed25519` and `ES256` are
supported by common KMS and HSM interfaces, and `WebAuthn-ES256` keys never leave the
authenticator.

## 7. Errors

A specification that verifies a signature reports failure in its own terms (for example
`CONSENT_INVALID` with reason `bad_signature`). The reasons below are the ones this specification
defines, and a consuming specification MUST pass them through unchanged.

| Reason | Meaning |
|---|---|
| `unknown_suite` | The declared suite is not in the registry |
| `suite_key_mismatch` | The suite does not belong to the key's type |
| `invalid_key` | The key is not exactly one of the two canonical forms of §3.1 |
| `bad_encoding` | The signature or a WebAuthn field cannot be decoded as required |
| `high_s` | An `ES256` signature is not low-S |
| `bad_client_data` | `client_data_json` is not JSON, or its `type` is wrong |
| `challenge_mismatch` | The WebAuthn challenge does not commit to this payload |
| `user_not_verified` | The user-present or user-verified flag is not set |
| `bad_signature` | The signature does not verify |

## 8. Conformance

`suite-vectors/vectors.json` contains vectors for every rule above, generated deterministically by
`suite-vectors/generate.py` from published seeds and checked by `suite-vectors/check.py`. A
conformant verifier passes every vector. The keys in the vectors are test keys derived from
published seeds; they MUST NOT be used as trust material.

## 9. Security considerations

- **Algorithm confusion.** The suite is checked against the key's own type (§3.3), never chosen by
  the object alone, so a signature cannot be reinterpreted under a weaker or different algorithm.
- **Cross-protocol use of one key.** A P-256 key could in principle sign both raw `ES256` payloads
  and WebAuthn assertions. NOMOS-SPEC-007 rev. 1.9 §3.6 separates them: a key may use
  `WebAuthn-ES256` only if its certificate chain says so, and then nothing else.
- **What this does not cover.** Whether a key is authorized to sign a given object is decided by
  the calling specification and NOMOS-SPEC-007, not here. This specification only decides whether
  a signature is a valid signature by a key.

## Changelog

- **0.1.0** — Initial draft (RFC-0001).
