"""Signing and building the objects of NOMOS-SPEC-001, -007, -008 and -009: seals, key certificates,
testimony, consents, in-force statements, revocations, Acts, and the certificates an Act presents.

Every payload is exactly the one the specification names, canonicalized with RFC 8785 (jcs.py)
and signed under a NOMOS-SPEC-010 suite (suites.py). The same functions the reference vector
generators use.

A `Signer` is anything with `kid`, `public_key_pem`, `algorithm` ("Ed25519" or "ES256") and
`sign(payload: bytes) -> str` (base64, the suite's encoding). `local_signer()` wraps a private key
held in this process; in production, pass one backed by your KMS or HSM.
"""
from __future__ import annotations

import base64
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from . import suites
from .act import binding_digest, consent_payload, in_force_payload, testimony_payload
from .chain import cert_payload, fingerprint, revocation_list_payload, revocation_payload
from .jcs import jcs, sha256_hex

MAX_PRESENTED = 20


class Signer(Protocol):
    kid: str
    public_key_pem: str
    algorithm: str
    def sign(self, payload: bytes) -> str: ...


@dataclass
class LocalSigner:
    """A Signer over a private key in this process: for development, tests and offline roots."""
    kid: str
    public_key_pem: str
    algorithm: str
    _key: Any

    def sign(self, payload: bytes) -> str:
        # Ed25519 signs the payload; ES256 signs SHA-256 of it, P1363 r‖s, low-S, deterministic nonces.
        return suites.sign_ed25519(self._key, payload) if self.algorithm == "Ed25519" else suites.sign_es256(self._key, payload)

    def private_key_pem(self) -> str:
        return self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def _wrap(key) -> LocalSigner:
    if isinstance(key, ed25519.Ed25519PrivateKey): alg = "Ed25519"
    elif isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1): alg = "ES256"
    else: raise ValueError("only Ed25519 and P-256 keys are NOMOS signature suites (NOMOS-SPEC-010)")
    pem = suites.public_pem(key)
    return LocalSigner(kid=suites.compute_kid(pem), public_key_pem=pem, algorithm=alg, _key=key)


def local_signer(private_key_pem: str) -> LocalSigner:
    """A signer from a PKCS#8 (or SEC1, for P-256) PEM private key."""
    return _wrap(serialization.load_pem_private_key(private_key_pem.encode(), password=None))


def generate_signer(algorithm: str = "Ed25519") -> LocalSigner:
    """A fresh in-memory key. For development and tests."""
    if algorithm == "Ed25519": return _wrap(ed25519.Ed25519PrivateKey.generate())
    if algorithm == "ES256": return _wrap(ec.generate_private_key(ec.SECP256R1()))
    raise ValueError("algorithm must be Ed25519 or ES256")


def seeded_signer(seed: str) -> LocalSigner:
    """A deterministic Ed25519 key from a seed: the same test key everywhere. The seed is the key;
    never use one for anything real. Byte-identical to @nomosprotocol/sdk's seededSigner()."""
    return _wrap(suites.ed25519_key_from_seed(seed.encode()))


def iso(t: datetime) -> str:
    """ISO 8601 UTC with milliseconds, as JavaScript's toISOString() writes it."""
    t = t.astimezone(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ── NOMOS-SPEC-007 ─────────────────────────────────────────────────────────────────────────
def certify(parent: Signer, child_kid: str, child_public_key_pem: str, *, expires_at: datetime,
            scope: Optional[str] = None, issued_at: Optional[datetime] = None) -> dict:
    """§3: `parent` certifies the child key within `scope` until `expires_at`."""
    c: Dict[str, Any] = {"parent_kid": parent.kid, "child_kid": child_kid, "child_public_key_pem": child_public_key_pem}
    if scope: c["scope"] = scope
    c["issued_at"] = iso(issued_at or now_utc()); c["expires_at"] = iso(expires_at)
    c["algorithm"] = parent.algorithm
    c["signature"] = parent.sign(jcs(cert_payload(c)))
    return c


def sign_revocation(parent: Signer, *, kid: Optional[str] = None, certificate: Optional[dict] = None,
                    reason: str, issued_at: Optional[datetime] = None) -> dict:
    """rev. 1.10 §5.1: revoke a key the parent certified, or one certificate it issued."""
    if (kid is None) == (certificate is None): raise ValueError("give exactly one of kid or certificate")
    if certificate is not None and certificate.get("parent_kid") != parent.kid:
        raise ValueError("only the parent that issued a certificate can revoke it")
    st: Dict[str, Any] = {"revoked_kid": kid} if kid else {"revoked_fingerprint": fingerprint(certificate)}
    st.update({"reason": reason, "issued_at": iso(issued_at or now_utc())})
    return {**st, "kid": parent.kid, "algorithm": parent.algorithm, "signature": parent.sign(jcs(revocation_payload(st)))}


def sign_revocation_list(signer: Signer, statements: List[dict], key_certs: Iterable[dict] = (), generated_at: Optional[datetime] = None) -> dict:
    """rev. 1.10 §5.3: a signed, dated list carrying the certificates that make it checkable."""
    lst: Dict[str, Any] = {"generated_at": iso(generated_at or now_utc()), "kid": signer.kid, "algorithm": signer.algorithm, "statements": statements}
    kc = list(key_certs)
    if kc: lst["key_certs"] = kc
    lst["signature"] = signer.sign(jcs(revocation_list_payload(lst)))
    return lst


# ── NOMOS-SPEC-001 §8 ──────────────────────────────────────────────────────────────────────
def seal(body: dict, issuer: Signer, signed_by: Any) -> dict:
    content = {k: v for k, v in body.items() if k not in ("seal", "attestations")}
    h = sha256_hex(jcs(content))
    signature = issuer.sign(jcs({"hash": h, "signed_by": signed_by}))
    return {**content, "seal": {"status": "sealed", "hash": h, "canonicalization": "JCS", "signature_algorithm": issuer.algorithm,
                                "kid": issuer.kid, "signed_by": signed_by, "signature": signature}}


# ── NOMOS-SPEC-008 ─────────────────────────────────────────────────────────────────────────
def sign_testimony(witness: Signer, *, claim: str, value: Any, about: Optional[str], valid_until: datetime, as_of: Optional[datetime] = None) -> dict:
    st = {"claim": claim, "value": value, "about": about, "as_of": iso(as_of or now_utc()), "valid_until": iso(valid_until), "kid": witness.kid, "algorithm": witness.algorithm}
    st["signature"] = witness.sign(jcs(testimony_payload(st)))
    return st


def sign_consent(approver: Signer, act: dict, role: str, decision: str = "approve") -> dict:
    c = {"binding_digest": binding_digest(act), "role": role, "decision": decision, "signed_at": iso(now_utc()), "kid": approver.kid, "algorithm": approver.algorithm}
    c["signature"] = approver.sign(jcs(consent_payload(c)))
    return c


def sign_in_force(issuer: Signer, artifact: dict, *, valid_until: datetime, as_of: Optional[datetime] = None) -> dict:
    st = {"artifact_id": artifact["meta"]["artifact_id"], "version": artifact["meta"]["version"], "seal_hash": artifact["seal"]["hash"],
          "as_of": iso(as_of or now_utc()), "valid_until": iso(valid_until), "kid": artifact["seal"]["kid"], "algorithm": issuer.algorithm}
    st["signature"] = issuer.sign(jcs(in_force_payload(st)))
    return st


def build_act(*, relying_party: str, action: dict, artifact: dict, key_certs: List[dict], testimony: Optional[List[dict]] = None,
              presenter_facts: Optional[dict] = None, in_force: Optional[dict] = None, window_seconds: int = 300,
              now: Optional[datetime] = None) -> dict:
    """§2: assemble an Act. It needs no key: what makes it valid is what it carries. Issued a second
    in the past so a relying party whose clock is a moment behind still accepts it."""
    t = (now or now_utc()) - timedelta(seconds=1)
    act: Dict[str, Any] = {
        "act_version": "1", "act_id": f"act-{uuid.uuid4()}", "nonce": base64.b64encode(os.urandom(16)).decode(),
        "issued_at": iso(t), "expires_at": iso(t + timedelta(seconds=window_seconds)),
        "relying_party": relying_party, "action": action,
        "authority": {"artifact": artifact, "key_certs": key_certs, **({"in_force": in_force} if in_force else {})},
        "testimony": testimony or [], "consents": [],
    }
    if presenter_facts: act["presenter_facts"] = presenter_facts
    return act


# ── NOMOS-SPEC-009 0.2.0 §6.5 ──────────────────────────────────────────────────────────────
def relied_kids(act: dict) -> List[str]:
    kids = [((act.get("authority") or {}).get("artifact") or {}).get("seal", {}).get("kid")]
    kids += [t.get("kid") for t in act.get("testimony") or []] + [c.get("kid") for c in act.get("consents") or []]
    out: List[str] = []
    for k in kids:
        if isinstance(k, str) and k and k not in out: out.append(k)
    return out


def presented_certificates(available: Iterable[dict], act: dict) -> List[dict]:
    """The closure of `available` over the kids `act` relies on, each certificate once. Deterministic,
    so two carriers with the same certificates present the same set (carrier indifference)."""
    unique: Dict[str, dict] = {}
    for c in available: unique.setdefault(fingerprint(c), c)
    kids, chosen = set(relied_kids(act)), {}
    grew = True
    while grew:
        grew = False
        for fp, c in unique.items():
            if fp not in chosen and c.get("child_kid") in kids:
                chosen[fp] = c; kids.add(c.get("parent_kid")); grew = True
    return list(chosen.values())
