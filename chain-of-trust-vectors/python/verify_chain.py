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
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, Optional, Set

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "python"))
from nomosprotocol import chain  # noqa: E402  (the shared reference: python/nomosprotocol/chain.py)
from nomosprotocol.chain import ts  # noqa: E402,F401


def verify_chain(artifact: Any, key_certs: Any, root_pem: str, now: datetime,
                 revoked_kids: Optional[Set[str]] = None, revoked_certs: Optional[Set[str]] = None,
                 staples: Optional[list] = None, strict_root: bool = False) -> Dict[str, Any]:
    # MALFORMED gates (§4.4, §4.5), before any cryptographic work
    bad = chain.check_pool(key_certs) or chain.check_seal_shape(artifact) or chain.check_staples(staples)
    if bad: return {"decision": "MALFORMED", "reason_code": bad}
    has_own_source = revoked_kids is not None or revoked_certs is not None
    seal, meta = artifact["seal"], artifact.get("meta") or {}

    # §4.2a: target-first, scope-aware (rev. 1.9). OUT_OF_SCOPE is decided before the seal.
    r = chain.resolve(seal["kid"], key_certs, root_pem, now, chain.for_artifact(meta, seal["signature_algorithm"]),
                      revoked_kids, revoked_certs)
    if r["decision"] != "RESOLVED": return r
    # §4.2 step 3: the seal. The resolved key is the same on every candidate path (its kid is its
    # hash), so the seal is checked once, after the path is chosen.
    failure = chain.seal_failure(artifact, r["key"])
    if failure: return failure

    # §5.5 confidence, weakest link
    if has_own_source:
        confidence = "live"
    else:
        confidence = chain.staple_confidence(r, staples, now)
        if strict_root: confidence = "unchecked"     # the root counted, read literally (FINDINGS)
    out: Dict[str, Any] = {"decision": "ALLOWED", "leaf_kid": seal["kid"], "path": r["path"], "revocation_checked": confidence}
    if r["effective"]: out["effective_scope"] = chain.format_scope(r["effective"])
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
