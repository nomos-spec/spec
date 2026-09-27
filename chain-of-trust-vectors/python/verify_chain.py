#!/usr/bin/env python3
"""
NOMOS-SPEC-007 chain-of-trust verifier — a second implementation, in Python.

Written from the text of NOMOS-SPEC-007 (§3 certificates, §3.4 scope, §4 the walk,
§5 revocation and freshness staples) and NOMOS-SPEC-001 §8 (seal), WITHOUT reading the
reference TypeScript implementation (server/lib/nomos-chain.ts,
prototype/chain-of-trust/chain-verify-core.ts). Different language, different crypto
library (pyca/cryptography instead of node:crypto), different JCS code.

What this is and isn't: it is a second implementation that can be checked against the
published vectors. It is NOT a third-party implementation — it was produced for NOMOS, so
it does not by itself satisfy SPEC-007 §8.2's call for an independent implementer. Treat a
full pass as "the spec text is sufficient to reproduce the reference verdicts", not as
proven multi-vendor interoperability.

Usage:
    python3 verify_chain.py vectors.json            # run every vector case
    python3 verify_chain.py vectors.json --strict-root
        # --strict-root: apply §5.5's text literally (root counted in the confidence
        # aggregate). See FINDINGS in README.md — the vectors assume otherwise.

Requires: Python 3.9+, `cryptography` (pip install cryptography).
"""
import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

MAX_CHAIN = 20  # §4.5
KNOWN_DIMENSIONS = ("artifact", "industry", "jurisdiction")  # §3.4 table
ISO_3166 = re.compile(r"^[A-Z]{2}(-[A-Z0-9]{1,3})?$")
CERT_FIELDS = ("parent_kid", "child_kid", "child_public_key_pem", "issued_at", "expires_at", "algorithm", "signature")


# ── RFC 8785 JCS (enough for NOMOS artifacts: no NaN/Infinity, JSON-native types) ──────────
def _jcs(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            raise ValueError("non-finite number")
        if v.is_integer() and abs(v) < 1e21:
            return str(int(v))
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(_jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        # JCS sorts by UTF-16 code units
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _jcs(v[k]) for k in keys) + "}"
    raise TypeError(type(v))


def jcs(obj: Any) -> bytes:
    return _jcs(obj).encode("utf-8")


# ── keys, signatures, time ────────────────────────────────────────────────────────────────
def load_key(pem: str):
    return serialization.load_pem_public_key(pem.encode("utf-8"))


def compute_kid(pem: str) -> str:
    """SPEC-001 §8.4: base64url(SHA-256(SPKI DER)), first 16 characters."""
    der = load_key(pem).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode("ascii").rstrip("=")[:16]


def ed25519_ok(pem: str, message: bytes, sig_b64: str) -> bool:
    try:
        load_key(pem).verify(base64.b64decode(sig_b64), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def cert_payload(c: dict) -> dict:
    """§3.2 — the signed payload; scope is null when absent."""
    return {k: c.get(k) for k in ("parent_kid", "child_kid", "child_public_key_pem", "issued_at", "expires_at")} | {"scope": c.get("scope")}


def cert_fingerprint(c: dict) -> str:
    """§5.4 — SHA-256 over the canonical signed payload, hex."""
    return hashlib.sha256(jcs(cert_payload(c))).hexdigest()


# ── scope (§3.4) ─────────────────────────────────────────────────────────────────────────
class ScopeError(Exception):
    pass


def parse_scope(scope: Optional[str]) -> List[tuple]:
    if scope is None or scope.strip() == "":
        return []
    terms, seen = [], set()
    for term in scope.split():
        dim, sep, val = term.partition(":")
        if not sep or not dim or not val:
            raise ScopeError(term)
        if dim in seen:
            raise ScopeError(f"duplicate dimension {dim}")
        seen.add(dim)
        terms.append((dim, val))
    return terms


def contains(dim: str, outer: str, inner: str) -> bool:
    """Does the grant `outer` cover the value `inner` on this dimension?"""
    if dim == "artifact":
        return outer == inner
    if dim == "industry":
        return inner == outer or inner.startswith(outer + "/")
    if dim == "jurisdiction":
        return inner == outer or (len(outer) == 2 and inner.startswith(outer + "-"))
    return False


def artifact_in_scope(dim: str, val: str, meta: dict) -> bool:
    if dim == "artifact":
        return meta.get("artifact_id") == val
    if dim == "industry":
        ind = meta.get("industry")
        return isinstance(ind, str) and ind != "" and contains("industry", val, ind)
    if dim == "jurisdiction":
        codes = meta.get("jurisdiction_codes")
        if not isinstance(codes, list) or not codes:
            return False  # undeclared → fail closed
        if not all(isinstance(c, str) and ISO_3166.match(c) for c in codes):
            return False  # malformed code → never fall back to string comparison
        return all(contains("jurisdiction", val, c) for c in codes)  # every declared code in scope
    return False  # unrecognized dimension → fail closed


# ── the verifier ─────────────────────────────────────────────────────────────────────────
def verify_chain(artifact: Any, key_certs: Any, root_pem: str, now: datetime,
                 revoked_kids: Optional[Set[str]] = None, revoked_certs: Optional[Set[str]] = None,
                 staples: Optional[list] = None, strict_root: bool = False) -> Dict[str, Any]:
    # MALFORMED gates (§4.4, §4.5) — before any cryptographic work
    if not isinstance(key_certs, list) or len(key_certs) > MAX_CHAIN:
        return {"decision": "MALFORMED", "reason_code": "chain_over_length_cap" if isinstance(key_certs, list) else "bad_chain"}
    if not isinstance(artifact, dict):
        return {"decision": "MALFORMED", "reason_code": "bad_artifact"}
    seal = artifact.get("seal")
    if not isinstance(seal, dict) or seal.get("status") != "sealed" or not all(isinstance(seal.get(k), str) for k in ("hash", "signature", "kid")):
        return {"decision": "MALFORMED", "reason_code": "unsealed_artifact"}
    for c in key_certs:
        if not isinstance(c, dict) or not all(isinstance(c.get(k), str) for k in CERT_FIELDS) or c.get("algorithm") != "Ed25519":
            return {"decision": "MALFORMED", "reason_code": "bad_certificate"}
        if c.get("scope") is not None and not isinstance(c.get("scope"), str):
            return {"decision": "MALFORMED", "reason_code": "bad_certificate"}

    has_own_source = revoked_kids is not None or revoked_certs is not None
    revoked_kids = revoked_kids or set()
    revoked_certs = revoked_certs or set()

    # §4.2 the walk — by kid, searching the whole remaining set (order independence, §4.3)
    target = seal["kid"]
    root_kid = compute_kid(root_pem)
    if root_kid in revoked_kids:  # §5.2 — checked at every hop, root included
        return {"decision": "KEY_REVOKED", "revoked_kid": root_kid}
    current_kid, current_key = root_kid, root_pem
    visited: Set[str] = set()
    remaining = list(key_certs)
    path, hops = [root_kid], []  # hops: (cert, parent_pem)
    while current_kid != target:
        if current_kid in visited:
            return {"decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "cycle"}
        visited.add(current_kid)
        cert = next((c for c in remaining if c["parent_kid"] == current_kid), None)
        if cert is None:
            return {"decision": "ISSUER_NOT_RECOGNIZED",
                    "reason_code": "no_certificate_for_root" if current_kid == root_kid else "chain_broken"}
        remaining.remove(cert)
        # §3.3 verify one certificate
        try:
            kid_ok = compute_kid(cert["child_public_key_pem"]) == cert["child_kid"]
        except ValueError:
            kid_ok = False
        if not kid_ok:
            return {"decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "kid_mismatch"}
        if not ed25519_ok(current_key, jcs(cert_payload(cert)), cert["signature"]):
            return {"decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "bad_signature"}
        if now > ts(cert["expires_at"]):
            return {"decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "expired"}
        if now < ts(cert["issued_at"]):
            return {"decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "not_yet_valid"}
        # §5.4 certificate revocation — after the signature verifies, before scope is applied
        if cert_fingerprint(cert) in revoked_certs:
            return {"decision": "CERTIFICATE_REVOKED", "fingerprint": cert_fingerprint(cert)}
        # §5.2 key revocation cascade, at this hop
        if cert["child_kid"] in revoked_kids:
            return {"decision": "KEY_REVOKED", "revoked_kid": cert["child_kid"]}
        hops.append((cert, current_key))
        current_kid, current_key = cert["child_kid"], cert["child_public_key_pem"]
        path.append(current_kid)

    # §4.2 step 3 — the artifact's own seal (SPEC-001 §8), against the resolved key
    body = {k: v for k, v in artifact.items() if k not in ("seal", "attestations")}
    if hashlib.sha256(jcs(body)).hexdigest() != seal["hash"]:
        return {"decision": "SEAL_INVALID", "reason_code": "hash_mismatch"}
    if not ed25519_ok(current_key, jcs({"hash": seal["hash"], "signed_by": seal.get("signed_by")}), seal["signature"]):
        return {"decision": "SEAL_INVALID", "reason_code": "bad_signature"}

    # §3.4 scope — accumulated along the path, never widened, then matched against the artifact
    effective: Dict[str, str] = {}
    for cert, _ in hops:
        try:
            terms = parse_scope(cert.get("scope"))
        except ScopeError:
            return {"decision": "OUT_OF_SCOPE", "reason_code": "malformed_scope"}
        for dim, val in terms:
            if dim in effective and not contains(dim, effective[dim], val):
                return {"decision": "OUT_OF_SCOPE", "dimension": dim, "reason_code": "widening"}
            effective[dim] = val
    meta = artifact.get("meta") or {}
    for dim, val in effective.items():
        if dim not in KNOWN_DIMENSIONS or not artifact_in_scope(dim, val, meta):
            return {"decision": "OUT_OF_SCOPE", "dimension": dim}

    # §5.5 confidence — per kid, weakest link
    if has_own_source:
        confidence = "live"
    else:
        levels = []
        if strict_root:
            levels.append("unchecked")  # the root can never be staple-covered
        for cert, parent_pem in hops:
            ok = any(
                isinstance(s, dict) and s.get("child_kid") == cert["child_kid"] and s.get("parent_kid") == cert["parent_kid"]
                and s.get("child_kid") != root_kid
                and isinstance(s.get("as_of"), str) and isinstance(s.get("valid_until"), str)
                and ts(s["as_of"]) <= now <= ts(s["valid_until"])
                and ed25519_ok(parent_pem, jcs({k: s[k] for k in ("child_kid", "parent_kid", "as_of", "valid_until")}), s.get("signature", ""))
                for s in (staples or [])
            )
            levels.append("staple" if ok else "unchecked")
        confidence = "unchecked" if (not levels or "unchecked" in levels) else "staple"

    out: Dict[str, Any] = {"decision": "ALLOWED", "leaf_kid": current_kid, "path": path, "revocation_checked": confidence}
    if effective:
        out["effective_scope"] = " ".join(f"{d}:{v}" for d, v in effective.items())
    return out


# ── vector runner ────────────────────────────────────────────────────────────────────────
def run_vectors(path: str, strict_root: bool = False) -> int:
    vectors = json.load(open(path, encoding="utf-8"))
    now = ts(vectors["check_at"])
    passed = failed = 0
    for case in vectors["cases"]:
        got = verify_chain(
            case["artifact"], case["key_certs"], vectors["root_public_key_pem"], now,
            revoked_kids=set(case["revoked_kids"]) if "revoked_kids" in case else None,
            revoked_certs=set(case["revoked_certs"]) if "revoked_certs" in case else None,
            staples=case.get("freshness_staples"), strict_root=strict_root,
        )
        exp = case["expected"]
        diffs = {k: (v, got.get(k)) for k, v in exp.items() if got.get(k) != v}
        if diffs:
            failed += 1
            print(f"  FAIL {case['name']}: " + ", ".join(f"{k} expected {e!r} got {g!r}" for k, (e, g) in diffs.items()))
        else:
            passed += 1
            print(f"  ok   {case['name']}")
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(run_vectors(sys.argv[1], strict_root="--strict-root" in sys.argv))
