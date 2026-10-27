"""NOMOS-SPEC-010 Signature Suites: reference verifier, and the signers the vector generator uses.

verify(suite, public_key_pem, payload, proof) -> (ok, reason)

  suite           "Ed25519" | "ES256" | "WebAuthn-ES256"
  public_key_pem  the signing key, as PEM SubjectPublicKeyInfo
  payload         the exact JCS bytes the calling specification says are signed
  proof           {"signature": ...} for Ed25519 and ES256;
                  {"authenticator_data", "client_data_json", "signature"} for WebAuthn-ES256

reason is one of the §7 reasons, or None when ok.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

SUITES = ("Ed25519", "ES256", "WebAuthn-ES256")
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

_B64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


# ── canonical base64 ─────────────────────────────────────────────────────────────────────────
def b64decode_canonical(s: Any) -> Optional[bytes]:
    """RFC 4648 §4 base64, padded, accepted only in its canonical encoding."""
    if not isinstance(s, str) or len(s) % 4 or not _B64.match(s):
        return None
    try:
        raw = base64.b64decode(s, validate=True)
    except ValueError:
        return None
    return raw if base64.b64encode(raw).decode() == s else None


def b64url_decode_canonical(s: Any) -> Optional[bytes]:
    """RFC 4648 §5 base64url, unpadded, accepted only in its canonical encoding."""
    if not isinstance(s, str) or not _B64URL.match(s) or len(s) % 4 == 1:
        return None
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except ValueError:
        return None
    return raw if b64url_encode(raw) == s else None


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# ── keys (§3) ────────────────────────────────────────────────────────────────────────────────
def _pem_der(pem: Any) -> Optional[bytes]:
    if not isinstance(pem, str):
        return None
    m = re.fullmatch(r"\s*-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END PUBLIC KEY-----\s*", pem)
    if not m:
        return None
    return b64decode_canonical("".join(m.group(1).split()))


ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")


_ED_P = 2**255 - 19
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_SMALL_ORDER = {bytes.fromhex(h) for h in (
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")}


def ed25519_point_valid(a: bytes) -> bool:
    """§3.1: canonical, on the curve, not of small order (RFC 8032 §5.1.3 decoding, strictly)."""
    if len(a) != 32 or a in _ED_SMALL_ORDER:
        return False
    y = int.from_bytes(a, "little") & ((1 << 255) - 1)
    sign = a[31] >> 7
    if y >= _ED_P:
        return False
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    if x2 == 0:
        return sign == 0
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = x * pow(2, (_ED_P - 1) // 4, _ED_P) % _ED_P
    return (x * x - x2) % _ED_P == 0


def load_key(pem: Any) -> Tuple[Optional[str], Any, Optional[str]]:
    """Returns (key_type, key, reason). key_type is 'Ed25519' or 'P-256'.

    Canonical form is checked against the exact bytes of §3.1, never by re-encoding through a
    library, whose output format is not part of the specification.
    """
    der = _pem_der(pem)
    if der is None:
        return None, None, "invalid_key"
    if len(der) == 44 and der.startswith(ED25519_SPKI_PREFIX):
        if not ed25519_point_valid(der[12:]):
            return None, None, "invalid_key"
        ktype = "Ed25519"
    elif len(der) == 91 and der.startswith(P256_SPKI_PREFIX):
        ktype = "P-256"
    else:
        return None, None, "invalid_key"
    try:
        key = serialization.load_der_public_key(der)  # also rejects a P-256 point not on the curve
    except (ValueError, TypeError):
        return None, None, "invalid_key"
    return ktype, key, None


def compute_kid(pem: str) -> str:
    der = _pem_der(pem)
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode().rstrip("=")[:16]


_SUITES_FOR_TYPE = {"Ed25519": ("Ed25519",), "P-256": ("ES256", "WebAuthn-ES256")}


# ── verification ─────────────────────────────────────────────────────────────────────────────
def verify(suite: Any, public_key_pem: Any, payload: bytes, proof: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    if suite not in SUITES:
        return False, "unknown_suite"
    ktype, key, reason = load_key(public_key_pem)
    if reason:
        return False, reason
    if suite not in _SUITES_FOR_TYPE[ktype]:
        return False, "suite_key_mismatch"
    if not isinstance(proof, dict):
        return False, "bad_encoding"
    if suite == "Ed25519":
        return _verify_ed25519(key, payload, proof.get("signature"))
    if suite == "ES256":
        return _verify_es256(key, payload, proof.get("signature"))
    return _verify_webauthn(key, payload, proof)


def _verify_ed25519(key, payload: bytes, sig_b64: Any):
    sig = b64decode_canonical(sig_b64)
    if sig is None or len(sig) != 64:
        return False, "bad_encoding"
    try:
        key.verify(sig, payload)
    except InvalidSignature:
        return False, "bad_signature"
    return True, None


def _verify_es256(key, payload: bytes, sig_b64: Any):
    sig = b64decode_canonical(sig_b64)
    if sig is None or len(sig) != 64:
        return False, "bad_encoding"
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        return False, "bad_encoding"
    if s > P256_N // 2:
        return False, "high_s"
    try:
        key.verify(encode_dss_signature(r, s), payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, "bad_signature"
    return True, None


def _verify_webauthn(key, payload: bytes, proof: Dict[str, Any]):
    auth = b64url_decode_canonical(proof.get("authenticator_data"))
    cdj = b64url_decode_canonical(proof.get("client_data_json"))
    sig = b64url_decode_canonical(proof.get("signature"))
    if auth is None or cdj is None or sig is None:
        return False, "bad_encoding"
    try:
        client = json.loads(cdj.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False, "bad_client_data"
    if not isinstance(client, dict) or client.get("type") != "webauthn.get":
        return False, "bad_client_data"
    if client.get("challenge") != b64url_encode(hashlib.sha256(payload).digest()):
        return False, "challenge_mismatch"
    if len(auth) < 37:
        return False, "bad_encoding"
    flags = auth[32]
    if not (flags & 0x01) or not (flags & 0x04):
        return False, "user_not_verified"
    try:
        decode_dss_signature(sig)
    except ValueError:
        return False, "bad_encoding"
    try:
        key.verify(sig, auth + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, "bad_signature"
    return True, None


# ── signers (producers; used by the vector generator) ────────────────────────────────────────
def ed25519_key_from_seed(seed: bytes) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())


def p256_key_from_seed(seed: bytes) -> ec.EllipticCurvePrivateKey:
    scalar = int.from_bytes(hashlib.sha256(seed).digest(), "big") % (P256_N - 1) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def public_pem(private_key) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def sign_ed25519(private_key, payload: bytes) -> str:
    return base64.b64encode(private_key.sign(payload)).decode()


def sign_es256(private_key, payload: bytes, *, low_s: bool = True) -> str:
    der = private_key.sign(payload, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    if low_s and s > P256_N // 2:
        s = P256_N - s
    if not low_s and s <= P256_N // 2:
        s = P256_N - s  # deliberately high-S, for the vector that must be refused
    return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()


def webauthn_assert(private_key, payload: bytes, *, rp_id: str = "approve.example",
                    origin: str = "https://approve.example", flags: int = 0x05,
                    type_: str = "webauthn.get", challenge: Optional[str] = None,
                    sign_count: int = 0) -> Dict[str, str]:
    """A WebAuthn assertion as an authenticator would produce it (§5)."""
    client = {"type": type_,
              "challenge": challenge if challenge is not None else b64url_encode(hashlib.sha256(payload).digest()),
              "origin": origin, "crossOrigin": False}
    cdj = json.dumps(client, separators=(",", ":")).encode()
    auth = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + sign_count.to_bytes(4, "big")
    sig = private_key.sign(auth + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    return {"authenticator_data": b64url_encode(auth), "client_data_json": b64url_encode(cdj),
            "signature": b64url_encode(sig)}
