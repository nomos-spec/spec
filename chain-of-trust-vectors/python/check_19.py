#!/usr/bin/env python3
"""Run the NOMOS-SPEC-007 rev. 1.9 vectors through the Python reference, in every listed order.

    python3 check_19.py ../vectors-1.9.json
"""
import json
import sys

from verify_chain import chain, ts, verify_chain

FIELDS = ("decision", "reason_code", "dimension", "path", "effective_scope", "revoked_kid")


def run(case, pool, root_pem, now):
    if case["purpose"] == "artifact":
        return verify_chain(case["artifact"], pool, root_pem, now,
                            revoked_kids=set(case.get("revoked_kids", [])), revoked_certs=set(case.get("revoked_certs", [])))
    st = case["statement"]
    bad = chain.check_pool(pool)
    if bad: return {"decision": "MALFORMED", "reason_code": bad}
    r = chain.resolve(st["kid"], pool, root_pem, now, chain.for_statement(st["kind"], st["name"], st["authority_meta"], st["suite"]))
    if r["decision"] != "RESOLVED": return r
    out = {"decision": "RESOLVED", "path": r["path"]}
    if r["effective"]: out["effective_scope"] = chain.format_scope(r["effective"])
    return out


v = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "../vectors-1.9.json"))
now = ts(v["check_at"])
passed = failed = 0
for case in v["cases"]:
    bad = []
    for order in case["orders"]:
        got = run(case, [case["key_certs"][i] for i in order], v["root_public_key_pem"], now)
        diffs = {k: (case["expected"].get(k), got.get(k)) for k in FIELDS if case["expected"].get(k) != got.get(k)}
        if diffs: bad.append((order, diffs))
    if bad:
        failed += 1
        order, diffs = bad[0]
        print(f"  FAIL {case['name']} (order {order}, {len(bad)}/{len(case['orders'])} orders): " +
              ", ".join(f"{k} expected {e!r} got {g!r}" for k, (e, g) in diffs.items()))
    else:
        passed += 1
        print(f"  ok   {case['name']:52s} {case['expected']['decision']:22s} x{len(case['orders'])}")
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
