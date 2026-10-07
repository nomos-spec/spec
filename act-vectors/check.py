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
# Non-finite numbers cannot appear in a JSON vector file, so this case is built in memory: the
# first vector's Act with its amount replaced by NaN, then by Infinity (SPEC-008 §6 step 1, §7.1).
import copy
base = v["cases"][0]
for bad in (float("nan"), float("inf")):
    a = copy.deepcopy(base["act"]); a["action"]["params"]["amount"] = bad
    got = verify_act(a, relying_party_id=v["relying_party_id"], root_pem=v["root_public_key_pem"],
                     now=ts(base["now"]), seen_nonces=set(), local_facts=v["local_facts"])
    if got.get("decision") == "MALFORMED" and got.get("reason_code") == "not_canonicalizable":
        passed += 1; print(f"  ok   amount={bad!r:<31s} MALFORMED")
    else:
        failed += 1; print(f"  FAIL amount={bad!r}: expected MALFORMED not_canonicalizable, got {got!r}")
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
