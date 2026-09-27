#!/usr/bin/env python3
"""Run every NOMOS-SPEC-008 vector through act_verify.py and compare with `expected`.
Usage: python3 check.py vectors.json"""
import json, sys
from act_verify import verify_act, ts

v = json.load(open(sys.argv[1]))
passed = failed = 0
for c in v["cases"]:
    got = verify_act(c["act"], relying_party_id=v["relying_party_id"], root_pem=v["root_public_key_pem"],
                     now=ts(c["now"]), seen_nonces=set(c["seen_nonces"]), local_facts=v["local_facts"])
    diffs = {k: (e, got.get(k)) for k, e in c["expected"].items() if got.get(k) != e}
    if diffs:
        failed += 1
        print(f"  FAIL {c['name']}: " + ", ".join(f"{k} expected {e!r} got {g!r}" for k, (e, g) in diffs.items()))
    else:
        passed += 1
        print(f"  ok   {c['name']:36s} {got['decision']}")
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
