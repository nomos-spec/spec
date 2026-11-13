#!/usr/bin/env python3
"""Check resolution-vectors/registrar-logs.json with the Python reference (python/nomosprotocol/registrar.py).

    python3 resolution-vectors/check_registrar_logs.py resolution-vectors/registrar-logs.json

`log` and `discovery` cases are checked whole. `network` cases are checked up to the world they
assemble (which registrars were read, which as delegates, and why any was left out); the resolution
over that world is checked by the TypeScript resolver (@nomosprotocol/verify), which has the
SPEC-008 evaluator scope predicates are decided by.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
from nomosprotocol.registrar import discover, load_registrar_world, verify_registrar_log  # noqa: E402


def main(path):
    data = json.load(open(path))
    passed = failed = 0
    for c in data["cases"]:
        problems = []
        if c["kind"] == "log":
            r = verify_registrar_log(c["entries"], c["head"], c["pinned_key"], c["now"], c["max_head_age_seconds"], c.get("previous"), c["log"])
            e = c["expect"]
            if r["ok"] != e["ok"]:
                problems.append(f"ok {r['ok']} (expected {e['ok']}): {r.get('reason')} {r.get('detail', '')}")
            elif r["ok"] and r["head"]["kid"] != e["kid"]:
                problems.append(f"kid {r['head']['kid']} (expected {e['kid']})")
            elif not r["ok"] and r["reason"] != e["reason"]:
                problems.append(f"reason {r['reason']} (expected {e['reason']}): {r['detail']}")
        elif c["kind"] == "network":
            w = load_registrar_world(c["pins"], lambda url: c["logs"].get(url), c["now"], c["max_head_age_seconds"], c.get("max_hops", 8))
            got = {rid: {"delegated": rec.get("delegated", False)} for rid, rec in w["world"]["registrars"].items()}
            if got != c["expect"]["registrars"]:
                problems.append(f"registrars {got} (expected {c['expect']['registrars']})")
            if w["absent"] != c["expect"]["absent"]:
                problems.append(f"absent {w['absent']} (expected {c['expect']['absent']})")
        elif c["kind"] == "discovery":
            r = discover(c["records"], c["registrar"], c["kid"])
            e = c["expect"]
            if r["ok"] != e["ok"] or (r["ok"] and r["url"] != e["url"]) or (not r["ok"] and r["reason"] != e["reason"]):
                problems.append(f"{r} (expected {e})")
        else:
            problems.append(f"unknown kind {c['kind']}")
        if problems:
            failed += 1
            print(f"FAIL {c['id']}: " + "; ".join(problems))
        else:
            passed += 1
    print(f"{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "registrar-logs.json")))
