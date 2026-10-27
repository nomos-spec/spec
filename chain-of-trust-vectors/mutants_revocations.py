#!/usr/bin/env python3
"""Derive mutants of the rev. 1.10 revocation-source vectors and record the Python reference's
verdict for each, so a second implementation can be checked against it field for field.

    python3 mutants_revocations.py revocation-vectors-1.10.json > revocation-mutants-1.10.json

Each mutant is one small change a publisher, a relay or an attacker could make. The verdicts are
the reference's, not hand-written: these are for agreement between implementations; the vectors
themselves carry the hand-written expectations.
"""
import copy, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
from nomos.chain import verify_revocation_list, ts  # noqa: E402

def flip(s):
    return (s[:-3] + ("A" if s[-3] != "A" else "B") + s[-2:]) if isinstance(s, str) and len(s) > 3 else s

def mutants(v, roots):
    L, own = v["list"], v["own_certs"]
    if not isinstance(L.get("statements"), list): return
    certs = L.get("key_certs", [])
    for i in range(len(L["statements"])):
        m = copy.deepcopy(L); del m["statements"][i]; yield f"drop statement {i}", m, own, v["root_public_key_pem"], v["now"]
        m = copy.deepcopy(L); m["statements"][i]["signature"] = flip(m["statements"][i].get("signature")); yield f"corrupt statement {i} signature", m, own, v["root_public_key_pem"], v["now"]
        m = copy.deepcopy(L); st = m["statements"][i]; st["algorithm"] = "ES256" if st.get("algorithm") == "Ed25519" else "Ed25519"; yield f"swap statement {i} suite", m, own, v["root_public_key_pem"], v["now"]
    for i in range(len(certs)):
        m = copy.deepcopy(L); del m["key_certs"][i]; yield f"drop certificate {i}", m, own, v["root_public_key_pem"], v["now"]
        m = copy.deepcopy(L); m["key_certs"][i]["signature"] = flip(m["key_certs"][i]["signature"]); yield f"corrupt certificate {i}", m, own, v["root_public_key_pem"], v["now"]
    m = copy.deepcopy(L); m["signature"] = flip(m["signature"]); yield "corrupt list signature", m, own, v["root_public_key_pem"], v["now"]
    m = copy.deepcopy(L); m["statements"].reverse(); m.get("key_certs", []).reverse(); yield "reverse everything", m, list(reversed(own)), v["root_public_key_pem"], v["now"]
    m = copy.deepcopy(L); m["key_certs"] = list(certs) + list(own); yield "own certificates moved into the list", m, [], v["root_public_key_pem"], v["now"]
    m = copy.deepcopy(L); m.pop("key_certs", None); yield "list certificates moved to the relying party", m, list(certs) + list(own), v["root_public_key_pem"], v["now"]
    for label, pem in roots:
        if pem != v["root_public_key_pem"]: yield f"pinned root {label}", L, own, pem, v["now"]
    yield "clock before the statements", L, own, v["root_public_key_pem"], "2026-05-01T00:00:00.000Z"
    yield "clock after the certificates expire", L, own, v["root_public_key_pem"], "2031-01-01T00:00:00.000Z"

vectors = json.load(open(sys.argv[1]))["cases"]
# Other roots a relying party might pin: every distinct certified key in the vectors.
roots, seen = [], set()
for v in vectors:
    for c in v["list"].get("key_certs", []) if isinstance(v["list"], dict) else []:
        if c["child_kid"] not in seen and len(roots) < 3: seen.add(c["child_kid"]); roots.append((c["child_kid"], c["child_public_key_pem"]))
out = []
for v in vectors:
    for mutation, L, own, root, now in mutants(v, roots):
        out.append({"case": v["name"], "mutation": mutation, "list": L, "own_certs": own, "root_public_key_pem": root, "now": now,
                    "expected": verify_revocation_list(L, root, ts(now), own)})
print(json.dumps({"_readme": "Derived from revocation-vectors-1.10.json by mutants_revocations.py. `expected` is the Python reference's verdict: a second implementation must agree on every field.",
                  "spec": "NOMOS-SPEC-007 rev. 1.10.0", "count": len(out), "cases": out}, indent=1))
