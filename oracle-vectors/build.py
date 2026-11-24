#!/usr/bin/env python3
"""Join generated cases with the oracle's verdicts into the published vector file.

    python3 generate.py 5000 2026 > cases.jsonl
    ../papers/.lake/build/bin/oracle < cases.jsonl > expected.jsonl
    python3 build.py cases.jsonl expected.jsonl > vectors.json
"""
import json
import sys

DESCRIPTION = (
    "Random authorities and fact sets, each with the verdict the Lean model of Part II gives "
    "(papers/oracle). An implementation agrees when evaluate(artifact, facts) gives the same verdict, "
    "the same deciding rule (rN; null when the default applied) and the same escalation. Covers "
    "resolution: Kleene logic, the choice of decider, the SPEC-008 0.5.0 gate, defaults, tie orders "
    "and obligations, over the comparisons == != < <= > >=, bare booleans and exists(). Reproduce: "
    "python3 generate.py 5000 2026 | ../papers/.lake/build/bin/oracle."
)


def main(cases_path, expected_path):
    cases = [json.loads(l) for l in open(cases_path) if l.strip()]
    exp = [json.loads(l) for l in open(expected_path) if l.strip()]
    assert len(cases) == len(exp)
    vectors = []
    for c, e in zip(cases, exp):
        assert c["id"] == e["id"], (c["id"], e["id"])
        vectors.append({"id": c["id"], "artifact": c["artifact"], "facts": c["facts"],
                        "expect": {k: e[k] for k in ("verdict", "decider", "escalation")}})
    doc = {"description": DESCRIPTION, "generator": "generate.py 5000 2026",
           "oracle": "papers/oracle (Lean 4.35)", "count": len(vectors), "vectors": vectors}
    sys.stdout.write(json.dumps(doc, separators=(",", ":"), sort_keys=True) + "\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
