#!/usr/bin/env python3
"""The Python carrier against the JavaScript sandbox (`npx @nomosprotocol/cli dev --auto-approve`):
the two SDKs interoperate on the wire, in both roles that cross the network.
    python3 python/tests/interop_sandbox.py http://localhost:4747   (a FRESH sandbox started with --auto-approve)
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import nomosprotocol as nomos  # noqa: E402

to = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4747"
passed = failed = 0
def check(ok, label, got=None):
    global passed, failed
    if ok: passed += 1; print(f"  ok    {label}")
    else: failed += 1; print(f"  FAIL  {label}\n        {str(got)[:300]}")
buy = lambda **p: {"type": "purchase", "subject": p.pop("subject", "DEPT-17"), "params": {"amount": 500, "vendor": "paperco", **p}}
r = nomos.act(to=to, action=buy())
check(r["status"] == "committed" and r["receipt"]["decision"] == "AUTHORIZED", "Python carrier → JS relying party: $500 committed", r.get("verdict"))
r = nomos.act(to=to, action=buy(amount=2000), poll_seconds=0.2)
check(r["status"] == "committed" and r["verdict"].get("by_consent") is True and r["act"]["consents"][0]["role"] == "MANAGER",
      "$2,000: escalated, the JS approver consents, the Python carrier resubmits, committed by consent", r.get("verdict"))
r = nomos.act(to=to, action=buy(amount=9000))
check(r["status"] == "denied" and r["verdict"]["rule"] == "P2", "$9,000: denied by P2", r.get("verdict"))
r = nomos.act(to=to, action=buy(vendor="shadyco", amount=100))
check(r["status"] == "denied" and r["verdict"]["rule"] == "P1", "shadyco: denied by the shop's own fact (P1)", r.get("verdict"))
r = nomos.act(to=to, action=buy(subject="DEPT-99"))
check(r["status"] == "incomplete" and r["missing"][0]["fact"] == "budget_remaining" and "knows nothing" in r["missing"][0]["why"],
      "DEPT-99: incomplete, naming budget_remaining and why", r.get("missing"))
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
