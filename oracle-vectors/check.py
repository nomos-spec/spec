#!/usr/bin/env python3
"""Compare the Python reference evaluator with the Lean oracle, case by case.

    python3 check.py vectors.json            # the published corpus
    python3 check.py cases.jsonl expected.jsonl   # any generated run

A case agrees when the verdict, the deciding rule and the escalation are the same, or when the
oracle cannot evaluate the artifact and neither can the implementation.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
from nomosprotocol.act import evaluate  # noqa: E402

VERDICT = {"allow": "authorized", "block": "denied", "escalate": "escalated", "undecided": "incomplete"}


def load(argv):
    if len(argv) == 2:
        doc = json.load(open(argv[1]))
        return [(v, v["expect"]) for v in doc["vectors"]]
    cases = [json.loads(l) for l in open(argv[1]) if l.strip()]
    exp = [json.loads(l) for l in open(argv[2]) if l.strip()]
    assert len(cases) == len(exp)
    return list(zip(cases, exp))


def observed(case, by_rule):
    try:
        ev = evaluate(case["artifact"], case["facts"])
    except Exception as e:  # noqa: BLE001 - an artifact the evaluator refuses
        return {"error": True}
    rule = ev.get("rule")
    got = {
        "verdict": VERDICT[ev["outcome"]],
        "escalation": ev.get("escalation_id") if ev["outcome"] == "escalate" else None,
    }
    if by_rule:
        got["rule"] = rule
    else:
        got["decider"] = int(rule[1:]) if rule else None
    return got


def main(argv):
    pairs = load(argv)
    bad = 0
    for case, want in pairs:
        by_rule = "rule" in want or "error" in want or "unevaluable" in want
        got = observed(case, by_rule)
        if "error" in want or want.get("unevaluable"):
            exp = {"error": True}
        else:
            exp = {k: want[k] for k in ("verdict", "rule" if by_rule else "decider", "escalation")}
        if got != exp:
            bad += 1
            if bad <= 10:
                print("DISAGREE", case["id"], "python", got, "lean", exp)
    print("%d/%d agree with the Lean model" % (len(pairs) - bad, len(pairs)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
