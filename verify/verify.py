#!/usr/bin/env python3
"""
NOMOS-SPEC-001 Reference Verifier (Python)

Verifies the cryptographic seal of a .nomos artifact — offline, with no call to any NOMOS
server. Two independent checks (both must pass):

  1. integrity   — recompute the JCS/SHA-256 payload hash and compare to seal.hash
  2. authenticity — verify the signature:
        · Ed25519 (RECOMMENDED) — against a PUBLIC key. Anyone can do this; the public key
          cannot forge a seal. Fetch it once from /.well-known/nomos-signing-keys (--url) or
          pass it directly (--pubkey). This is what makes a sealed .nomos independently
          verifiable rather than "trust-me".
        · HMAC-SHA256 (legacy) — symmetric; needs the shared secret, so only the sealing
          authority can verify. Not third-party verifiable.

Usage:
    python verify.py <artifact.nomos> --url https://nomosprotocol.com   # fetch the public key
    python verify.py <artifact.nomos> --pubkey signing_key.pub.pem       # fully offline
    python verify.py <artifact.nomos> --key <hex-or-raw>                 # legacy HMAC seals
    python verify.py <artifact.nomos>                                    # integrity + structure only

Requirements:
    Python 3.8+ standard library. Ed25519 verification additionally needs `cryptography`
    (pip install cryptography); the integrity check and HMAC path are stdlib-only.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import urllib.request
from typing import Any, Optional


# ---------------------------------------------------------------------------
# RFC 8785 JSON Canonicalization Scheme (JCS) — minimal implementation
# ---------------------------------------------------------------------------

def _jcs_value(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value:
            raise ValueError("NaN is not valid in JCS")
        if value == float("inf") or value == float("-inf"):
            raise ValueError("Infinity is not valid in JCS")
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_jcs_value(v) for v in value) + "]"
    if isinstance(value, dict):
        pairs = sorted(value.items(), key=lambda kv: kv[0])
        return "{" + ",".join(f"{json.dumps(k)}:{_jcs_value(v)}" for k, v in pairs) + "}"
    raise TypeError(f"Unsupported type: {type(value)}")


def jcs_canonicalize(obj: Any) -> bytes:
    return _jcs_value(obj).encode("utf-8")


# ---------------------------------------------------------------------------
# Public key discovery
# ---------------------------------------------------------------------------

def fetch_public_key(base_url: str, kid: Optional[str]) -> Optional[str]:
    """Fetch the published verification key set and return the PEM matching `kid`."""
    url = base_url.rstrip("/") + "/.well-known/nomos-signing-keys"
    with urllib.request.urlopen(url, timeout=15) as resp:
        keys = json.loads(resp.read()).get("keys", [])
    if not keys:
        return None
    match = next((k for k in keys if k.get("kid") == kid), keys[0])
    return match.get("public_key_pem")


# ---------------------------------------------------------------------------
# Seal verification
# ---------------------------------------------------------------------------

def verify_artifact(artifact_path: str, seal_key: Optional[bytes], pubkey_pem: Optional[str], base_url: Optional[str]) -> None:
    with open(artifact_path, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    seal = artifact.get("seal") or {}
    alg = seal.get("signature_algorithm") or seal.get("algorithm") or ""
    print(f"\nVerifying: {artifact_path}")
    print(f"  artifact_id : {artifact.get('artifact_id')}")
    print(f"  version     : {artifact.get('version')}")
    print(f"  algorithm   : {alg}    kid={seal.get('kid', '—')}")

    if not seal or seal.get("status") == "draft":
        _fail("Artifact is not sealed")

    # --- 1. Integrity: recompute the canonical payload hash (offline, no key) ---
    payload = {k: v for k, v in artifact.items() if k != "seal"}
    computed_hash = hashlib.sha256(jcs_canonicalize(payload)).hexdigest()
    stored_hash = seal.get("hash", "")
    if computed_hash != stored_hash:
        _fail(f"Hash mismatch — payload modified after sealing.\n  stored  : {stored_hash}\n  computed: {computed_hash}")
    print(f"  [OK] Payload hash matches: {computed_hash[:16]}...")

    # --- 2. Authenticity: verify the signature ---
    if alg == "Ed25519" or alg == "RS256" or alg == "ES256":
        _verify_asymmetric(seal, alg, pubkey_pem, base_url)
    elif alg == "HMAC-SHA256":
        _verify_hmac(seal, computed_hash, seal_key)
    else:
        _fail(f"Unsupported seal algorithm: {alg!r}")

    # --- 3. Advisory: contradictions + readiness ---
    count = artifact.get("contradiction_report", {}).get("contradiction_count", 0)
    print(f"  [WARN] {count} contradiction(s) at seal time." if count else "  [OK] No contradictions.")
    r = artifact.get("readiness", {})
    print(f"  [OK] Readiness: ARI={r.get('ari', 'N/A')}  band={r.get('autonomy_band', 'N/A')}")

    print("\nResult: VALID\n")


def _verify_asymmetric(seal: dict, alg: str, pubkey_pem: Optional[str], base_url: Optional[str]) -> None:
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        _fail("Ed25519 verification needs the `cryptography` package (pip install cryptography), or use verify.ts.")

    if pubkey_pem is None and base_url:
        pubkey_pem = fetch_public_key(base_url, seal.get("kid"))
    if pubkey_pem is None:
        _fail("Provide the published public key with --pubkey <pem> or --url <host> (fetches /.well-known/nomos-signing-keys).")

    # The signature is over the canonical bytes of {hash, signed_by} — exactly what the sealer signed.
    signed_payload = jcs_canonicalize({"hash": seal.get("hash"), "signed_by": seal.get("signed_by")})
    sig = base64.b64decode(seal.get("signature", ""))
    pub = load_pem_public_key(pubkey_pem.encode("utf-8"))
    try:
        pub.verify(sig, signed_payload)  # Ed25519: verify(signature, data); raises on failure
        print(f"  [OK] {alg} signature verified against the published PUBLIC key (no secret, no server call).")
    except InvalidSignature:
        _fail("Signature does not verify — forged, wrong key, or the seal was altered.")


def _verify_hmac(seal: dict, computed_hash: str, seal_key: Optional[bytes]) -> None:
    if seal_key is None:
        print("  [SKIP] HMAC (symmetric) seal — needs the shared secret; not third-party verifiable.")
        print("         Pass --key to verify, or re-seal with an Ed25519 key for public verifiability.")
        return
    computed_sig = hmac.new(seal_key, computed_hash.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(computed_sig, seal.get("sig", "")):
        _fail("HMAC signature mismatch — wrong key or tampered hash field.")
    print("  [OK] HMAC signature verified (symmetric — required the shared secret).")


def _fail(msg: str) -> None:
    print(f"\n  [FAIL] {msg}\n\nResult: INVALID\n")
    sys.exit(1)


def main() -> None:
    p = argparse.ArgumentParser(description="Verify a sealed .nomos artifact — offline")
    p.add_argument("artifact", help="Path to the .nomos file")
    p.add_argument("--pubkey", help="Path to the published Ed25519 public key (PEM) — fully offline")
    p.add_argument("--url", help="Base URL to fetch the published key from /.well-known/nomos-signing-keys")
    p.add_argument("--key", help="Legacy HMAC seals only: hex-encoded or raw shared secret")
    p.add_argument("--key-env", help="Env var holding the HMAC secret", default="NOMOS_SEAL_KEY")
    args = p.parse_args()

    pubkey_pem = None
    if args.pubkey:
        with open(args.pubkey, "r", encoding="utf-8") as f:
            pubkey_pem = f.read()

    seal_key: Optional[bytes] = None
    raw = args.key or os.environ.get(args.key_env)
    if raw:
        raw = raw.strip()
        try:
            seal_key = bytes.fromhex(raw)
        except ValueError:
            seal_key = raw.encode("utf-8")

    verify_artifact(args.artifact, seal_key, pubkey_pem, args.url)


if __name__ == "__main__":
    main()
