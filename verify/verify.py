#!/usr/bin/env python3
"""
NOMOS-SPEC-001 Reference Verifier (Python)

Verifies the cryptographic seal of a .nomos artifact.

Usage:
    python verify.py <artifact.nomos> --key <hex-or-raw-seal-key>
    python verify.py <artifact.nomos> --key-env NOMOS_SEAL_KEY
    python verify.py <artifact.nomos>  # seal structure check only (no sig verification)

Requirements:
    pip install cryptography
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
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
        # IEEE 754 double — Python's repr is already correct for most values
        if value != value:  # NaN
            raise ValueError("NaN is not valid in JCS")
        if value == float("inf") or value == float("-inf"):
            raise ValueError("Infinity is not valid in JCS")
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        items = ",".join(_jcs_value(v) for v in value)
        return f"[{items}]"
    if isinstance(value, dict):
        pairs = sorted(value.items(), key=lambda kv: kv[0])
        body = ",".join(f"{json.dumps(k)}:{_jcs_value(v)}" for k, v in pairs)
        return "{" + body + "}"
    raise TypeError(f"Unsupported type: {type(value)}")


def jcs_canonicalize(obj: dict) -> bytes:
    return _jcs_value(obj).encode("utf-8")


# ---------------------------------------------------------------------------
# Seal verification
# ---------------------------------------------------------------------------

def verify_artifact(artifact_path: str, seal_key: Optional[bytes]) -> None:
    with open(artifact_path, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    print(f"\nVerifying: {artifact_path}")
    print(f"  artifact_id : {artifact.get('artifact_id')}")
    print(f"  version     : {artifact.get('version')}")
    print(f"  spec_version: {artifact.get('spec_version')}")
    print(f"  confidence  : {artifact.get('confidence')}")

    # --- 1. Check spec version ---
    if artifact.get("spec_version") != "NOMOS-SPEC-001":
        _fail(f"Unknown spec_version: {artifact.get('spec_version')!r}")

    # --- 2. Extract seal ---
    seal = artifact.get("seal")
    if not seal:
        _fail("Missing 'seal' block")

    stored_hash = seal.get("hash", "")
    stored_sig  = seal.get("sig", "")
    algorithm   = seal.get("algorithm", "")

    if algorithm != "HMAC-SHA256":
        _fail(f"Unsupported seal algorithm: {algorithm!r}")

    # --- 3. Recompute payload hash ---
    payload = {k: v for k, v in artifact.items() if k != "seal"}
    canonical = jcs_canonicalize(payload)
    computed_hash = hashlib.sha256(canonical).hexdigest()

    if computed_hash != stored_hash:
        _fail(
            f"Hash mismatch!\n"
            f"  stored  : {stored_hash}\n"
            f"  computed: {computed_hash}\n"
            "  The artifact payload has been modified after sealing."
        )
    print(f"  [OK] Payload hash matches: {computed_hash[:16]}...")

    # --- 4. Verify HMAC signature ---
    if seal_key is None:
        print("  [SKIP] No seal key provided — signature not verified.")
        print("         Pass --key or --key-env to verify the full seal.\n")
    else:
        computed_sig = hmac.new(seal_key, computed_hash.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(computed_sig, stored_sig):
            _fail(
                "Signature mismatch!\n"
                "  The seal key does not match, or the hash field was tampered with."
            )
        print(f"  [OK] HMAC signature verified.")

    # --- 5. Check contradiction count ---
    report = artifact.get("contradiction_report", {})
    count = report.get("contradiction_count", 0)
    if count > 0:
        print(f"  [WARN] {count} contradiction(s) detected at seal time.")
    else:
        print(f"  [OK] No contradictions.")

    # --- 6. Readiness summary ---
    r = artifact.get("readiness", {})
    print(f"  [OK] Readiness: ARI={r.get('ari', 'N/A')}  band={r.get('autonomy_band', 'N/A')}")

    print(f"\nResult: VALID\n")


def _fail(msg: str) -> None:
    print(f"\n  [FAIL] {msg}")
    print("\nResult: INVALID\n")
    sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a .nomos artifact seal")
    parser.add_argument("artifact", help="Path to the .nomos file")
    parser.add_argument("--key",     help="Hex-encoded or raw seal key")
    parser.add_argument("--key-env", help="Environment variable holding the seal key", default="NOMOS_SEAL_KEY")
    args = parser.parse_args()

    seal_key: Optional[bytes] = None

    if args.key:
        raw = args.key.strip()
        try:
            seal_key = bytes.fromhex(raw)
        except ValueError:
            seal_key = raw.encode("utf-8")
    else:
        env_val = os.environ.get(args.key_env)
        if env_val:
            try:
                seal_key = bytes.fromhex(env_val.strip())
            except ValueError:
                seal_key = env_val.encode("utf-8")

    verify_artifact(args.artifact, seal_key)


if __name__ == "__main__":
    main()
