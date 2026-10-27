#!/usr/bin/env python3
"""Generate NOMOS-SPEC-010 test vectors, deterministically.

    python3 generate.py > vectors.json

Every key is derived from a published seed, and ES256 and WebAuthn signatures use RFC 6979
deterministic nonces, so the output is byte-identical on every run. The keys are test keys:
never use them as trust material.
"""
import base64
import hashlib
import json
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
from nomosprotocol import suites as S  # noqa: E402
from nomosprotocol.jcs import jcs  # noqa: E402


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


ED = S.ed25519_key_from_seed(b"nomos-spec-010:ed25519")
P256 = S.p256_key_from_seed(b"nomos-spec-010:p256")
PASSKEY = S.p256_key_from_seed(b"nomos-spec-010:passkey")
P384 = ec.derive_private_key(int.from_bytes(hashlib.sha256(b"nomos-spec-010:p384").digest(), "big"), ec.SECP384R1())

ED_PEM, P256_PEM, PASSKEY_PEM, P384_PEM = (S.public_pem(k) for k in (ED, P256, PASSKEY, P384))

PAYLOAD_OBJ = {"claim": "budget_remaining", "value": 4200, "about": "DEPT-17",
               "as_of": "2026-11-02T09:00:00.000Z", "valid_until": "2026-11-03T09:00:00.000Z", "kid": "test"}
PAYLOAD = jcs(PAYLOAD_OBJ)
OTHER = jcs({**PAYLOAD_OBJ, "value": 99999})


def compressed_pem(private_key) -> str:
    """The same P-256 key, encoded with a compressed point: a non-canonical SPKI (§3.1)."""
    point = private_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    der = bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200") + point
    body = b64(der)
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + "\n-----END PUBLIC KEY-----\n"


def off_curve_pem() -> str:
    """Canonical P-256 SPKI bytes whose point is not on the curve (X = 1, Y = 1)."""
    der = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004") + (1).to_bytes(32, "big") + (1).to_bytes(32, "big")
    body = b64(der)
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + "\n-----END PUBLIC KEY-----\n"


def flip_last_bit_b64(sig_b64: str) -> str:
    raw = bytearray(base64.b64decode(sig_b64))
    raw[-1] ^= 0x01
    return b64(bytes(raw))


def p1363_to_der(sig_b64: str) -> str:
    raw = base64.b64decode(sig_b64)
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    return b64(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")))


def high_s_der(proof):
    """A WebAuthn signature re-encoded with the other s: still valid, since §5 has no low-S rule."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    r, s = decode_dss_signature(S.b64url_decode_canonical(proof["signature"]))
    return {**proof, "signature": S.b64url_encode(encode_dss_signature(r, S.P256_N - s))}


cases = []


def add(name, suite, pem, payload, proof, expected_ok, reason=None, why=""):
    cases.append({"name": name, "suite": suite, "public_key_pem": pem, "payload_b64": b64(payload),
                  "proof": proof, "expected": {"ok": expected_ok, "reason": reason}, "why": why})


ed_sig = S.sign_ed25519(ED, PAYLOAD)
es_sig = S.sign_es256(P256, PAYLOAD)
wa = S.webauthn_assert(PASSKEY, PAYLOAD)

# Ed25519
add("ed25519_valid", "Ed25519", ED_PEM, PAYLOAD, {"signature": ed_sig}, True)
add("ed25519_other_payload", "Ed25519", ED_PEM, OTHER, {"signature": ed_sig}, False, "bad_signature",
    "The signature is genuine, over a different payload.")
add("ed25519_wrong_length", "Ed25519", ED_PEM, PAYLOAD, {"signature": b64(base64.b64decode(ed_sig)[:63])}, False, "bad_encoding")
add("ed25519_unpadded_base64", "Ed25519", ED_PEM, PAYLOAD, {"signature": ed_sig.rstrip("=")}, False, "bad_encoding",
    "Base64 must be canonical: the same signature without padding is a second encoding.")

# ES256
add("es256_valid", "ES256", P256_PEM, PAYLOAD, {"signature": es_sig}, True)
add("es256_high_s", "ES256", P256_PEM, PAYLOAD, {"signature": S.sign_es256(P256, PAYLOAD, low_s=False)}, False, "high_s",
    "The same signature with s replaced by n - s verifies mathematically, but has a second encoding (§4).")
add("es256_der_encoded", "ES256", P256_PEM, PAYLOAD, {"signature": p1363_to_der(es_sig)}, False, "bad_encoding",
    "ES256 is P1363 r||s, never DER.")
add("es256_r_zero", "ES256", P256_PEM, PAYLOAD, {"signature": b64(bytes(32) + base64.b64decode(es_sig)[32:])}, False, "bad_encoding")
add("es256_other_payload", "ES256", P256_PEM, OTHER, {"signature": es_sig}, False, "bad_signature")
add("es256_tampered", "ES256", P256_PEM, PAYLOAD, {"signature": flip_last_bit_b64(es_sig)}, False, "bad_signature")

# keys and suites
add("key_compressed_point", "ES256", compressed_pem(P256), PAYLOAD, {"signature": es_sig}, False, "invalid_key",
    "The same key with a compressed point would have a second key id (§3.1).")
add("key_p384", "ES256", P384_PEM, PAYLOAD, {"signature": es_sig}, False, "invalid_key")
add("key_p256_point_off_curve", "ES256", off_curve_pem(), PAYLOAD, {"signature": es_sig}, False, "invalid_key",
    "Canonical bytes, but the point is not on the curve.")
def ed_pem(raw: bytes) -> str:
    body = b64(bytes.fromhex("302a300506032b6570032100") + raw)
    return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n"


IDENTITY = (1).to_bytes(32, "little")
add("key_ed25519_small_order", "Ed25519", ed_pem(IDENTITY), PAYLOAD, {"signature": b64(IDENTITY + bytes(32))}, False, "invalid_key",
    "The identity point. Under it, R = identity and S = 0 verifies against every message; some libraries accept that (§3.1).")
add("key_ed25519_noncanonical", "Ed25519", ed_pem((2**255 - 19 + 1).to_bytes(32, "little")), PAYLOAD, {"signature": ed_sig}, False, "invalid_key",
    "y = p + 1: a second encoding of the identity's y coordinate.")
add("key_ed25519_not_on_curve", "Ed25519", ed_pem((2).to_bytes(32, "little")), PAYLOAD, {"signature": ed_sig}, False, "invalid_key",
    "y = 2 has no x on the curve.")
add("suite_ed25519_on_p256_key", "Ed25519", P256_PEM, PAYLOAD, {"signature": ed_sig}, False, "suite_key_mismatch",
    "The key decides what it can be (§3.3).")
add("suite_es256_on_ed25519_key", "ES256", ED_PEM, PAYLOAD, {"signature": es_sig}, False, "suite_key_mismatch")
add("suite_rs256_unknown", "RS256", P256_PEM, PAYLOAD, {"signature": es_sig}, False, "unknown_suite",
    "The registry is closed (§2).")
add("suite_none_unknown", "none", P256_PEM, PAYLOAD, {"signature": ""}, False, "unknown_suite")

# WebAuthn-ES256
add("webauthn_valid", "WebAuthn-ES256", PASSKEY_PEM, PAYLOAD, wa, True)
add("webauthn_high_s_accepted", "WebAuthn-ES256", PASSKEY_PEM, PAYLOAD, high_s_der(wa), True,
    why="WebAuthn signatures are exempt from low-S: the authenticator chooses the encoding (§5).")
add("webauthn_user_present_only", "WebAuthn-ES256", PASSKEY_PEM, PAYLOAD, S.webauthn_assert(PASSKEY, PAYLOAD, flags=0x01), False,
    "user_not_verified", "A touch is not an approval: the device must have verified the person (§5).")
add("webauthn_wrong_type", "WebAuthn-ES256", PASSKEY_PEM, PAYLOAD, S.webauthn_assert(PASSKEY, PAYLOAD, type_="webauthn.create"), False,
    "bad_client_data", "A registration ceremony is not an approval.")
add("webauthn_challenge_for_other_payload", "WebAuthn-ES256", PASSKEY_PEM, PAYLOAD,
    S.webauthn_assert(PASSKEY, PAYLOAD, challenge=S.b64url_encode(hashlib.sha256(OTHER).digest())), False,
    "challenge_mismatch", "A genuine approval of a different payload.")
short = dict(wa)
short["authenticator_data"] = S.b64url_encode(S.b64url_decode_canonical(wa["authenticator_data"])[:36])
add("webauthn_short_authenticator_data", "WebAuthn-ES256", PASSKEY_PEM, PAYLOAD, short, False, "bad_encoding")
tampered = dict(wa)
auth = bytearray(S.b64url_decode_canonical(wa["authenticator_data"]))
auth[-1] ^= 0x01
tampered["authenticator_data"] = S.b64url_encode(bytes(auth))
add("webauthn_tampered_authenticator_data", "WebAuthn-ES256", PASSKEY_PEM, PAYLOAD, tampered, False, "bad_signature")
add("webauthn_padded_base64url", "WebAuthn-ES256", PASSKEY_PEM, PAYLOAD,
    {**wa, "client_data_json": wa["client_data_json"] + ("=" * (-len(wa["client_data_json"]) % 4) or "==")},
    False, "bad_encoding", "base64url must be unpadded and canonical.")
add("webauthn_on_ed25519_key", "WebAuthn-ES256", ED_PEM, PAYLOAD, wa, False, "suite_key_mismatch")
add("webauthn_proof_missing_fields", "WebAuthn-ES256", PASSKEY_PEM, PAYLOAD, {"signature": wa["signature"]}, False, "bad_encoding")

out = {
    "_readme": "NOMOS-SPEC-010 signature suite vectors. For each case, decode payload_b64 to the exact payload "
               "bytes and call verify(suite, public_key_pem, payload, proof). The result must equal expected. "
               "Keys are derived from published seeds: never use them as trust material.",
    "spec": "NOMOS-SPEC-010 0.2.0",
    "cases": cases,
}
json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
