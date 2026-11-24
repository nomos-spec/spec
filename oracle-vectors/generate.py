#!/usr/bin/env python3
"""Random authorities and fact sets for the Lean oracle (papers/oracle).

Each case is an artifact and a fact set. The oracle reads the artifact's own `when` strings and
computes the model's verdict; check.py and the TypeScript test compare an implementation's
`evaluate(artifact, facts)` with it.

    python3 generate.py N SEED > cases.jsonl

Deterministic for a given N and SEED. Covers what implementations treat specially: ties at equal
priority under all three tie orders; a default (with and without an escalation id) when nothing
matches; obligation rules (`emit`, a declared `action`), which take no part in resolution; exists()
on inputs whose absence is and is not authoritative; facts absent, present, and of the wrong kind;
and artifacts with a ruling no evaluator may read, which must be refused whatever the facts.
"""
import json
import random
import sys

KINDS = ["number", "string", "boolean"]
SOURCES_AUTH = ["action", "relying_party"]
SOURCES_OTHER = ["testimony", "presenter"]
ESCS = ["MANAGER", "DIRECTOR", "BOARD"]
STRS = ["a", "b", "c", "d"]


def value_of(kind, r):
    if kind == "number":
        return r.randint(-3, 3)
    if kind == "string":
        return r.choice(STRS)
    return r.choice([True, False])


def lit_src(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return '"%s"' % v


def gen_cond(inputs, r, depth):
    names = list(inputs)
    if depth > 0 and r.random() < 0.45:
        op = r.choice(["and", "or", "not"])
        if op == "not":
            c, w = gen_cond(inputs, r, depth - 1)
            return {"not": c}, "not (%s)" % w
        a, wa = gen_cond(inputs, r, depth - 1)
        b, wb = gen_cond(inputs, r, depth - 1)
        return {op: [a, b]}, "(%s) %s (%s)" % (wa, op, wb)
    x = r.choice(names)
    k = inputs[x]["type"]
    roll = r.random()
    if roll < 0.12:
        return {"ex": x}, "exists(%s)" % x
    if k == "boolean" and roll < 0.3:
        return {"bool": x}, x
    if roll < 0.42:
        y = r.choice(names)
        op = r.choice(["==", "!=", ">", ">=", "<", "<="])
        return {"cmp": {"op": op, "l": x, "r": {"field": y}}}, "%s %s %s" % (x, op, y)
    ops = ["==", "!="] if k == "boolean" else ["==", "!=", ">", ">=", "<", "<="]
    op = r.choice(ops)
    # mostly a literal of the input's kind; sometimes of another kind (outside the domain)
    lk = k if r.random() < 0.9 else r.choice(KINDS)
    v = value_of(lk, r)
    return {"cmp": {"op": op, "l": x, "r": {"lit": v}}}, "%s %s %s" % (x, op, lit_src(v))


def gen_case(i, r):
    n_in = r.randint(1, 5)
    inputs = {}
    for j in range(n_in):
        src = r.choice(SOURCES_AUTH + SOURCES_OTHER + SOURCES_OTHER)
        inputs["f%d" % j] = {"type": r.choice(KINDS), "source": src}
    tie = r.choice(["deny_wins", "allow_wins", "escalate_wins"])
    n_dec = r.randint(1, 7)
    decisions, rules = [], []
    for j in range(n_dec):
        cond, when = gen_cond(inputs, r, r.randint(0, 3))
        kind = r.choice(["allow", "block", "escalate"])
        esc = r.choice(ESCS) if kind == "escalate" else None
        prio = r.randint(0, 3)
        decisions.append({"cond": cond, "kind": kind, "esc": esc, "prio": prio})
        then = {"type": kind}
        if esc is not None:
            then["escalation_id"] = esc
        rules.append({"id": "r%d" % j, "when": when, "then": [then], "priority": prio})
    # obligations: never part of resolution; interleaved at random positions
    for k in range(r.choice([0, 0, 1, 2])):
        _, when = gen_cond(inputs, r, 1)
        then = r.choice([{"type": "emit", "event": "e%d" % k}, {"type": "action", "action_name": "notify"}])
        rules.insert(r.randint(0, len(rules)), {"id": "o%d" % k, "when": when, "then": [then], "priority": r.randint(0, 5)})
    # now and then a ruling no evaluator may read: a `set`, or an action the artifact does not
    # declare. The whole artifact is then unevaluable, whatever the facts (SPEC-008 §6.0).
    if r.random() < 0.04:
        _, when = gen_cond(inputs, r, 1)
        then = r.choice([{"type": "set", "variable": "v", "value": {"lit": 1}}, {"type": "action", "action_name": "route_to"}])
        rules.insert(r.randint(0, len(rules)), {"id": "u0", "when": when, "then": [then], "priority": r.randint(0, 5)})
    dkind = r.choice(["allow", "block", "escalate", None])
    resolution = {"tie_breaker": tie, "conflict_policy": "highest_priority"}
    if dkind is not None:
        resolution["default_outcome"] = dkind
    desc = None
    if dkind == "escalate" and r.random() < 0.8:
        desc = r.choice(ESCS)
        resolution["default_escalation_id"] = desc
    facts = {}
    for x, spec in inputs.items():
        roll = r.random()
        if roll < 0.3:
            continue
        kind = spec["type"] if roll < 0.92 else r.choice(KINDS)
        facts[x] = value_of(kind, r)
    artifact = {
        "data_contract": {"inputs": inputs},
        "logic": {"decisions": rules, "resolution": resolution},
        "execution": {"actions": {"notify": {}}},
    }
    return {
        "id": "case-%d" % i,
        "facts": facts,
        "artifact": artifact,
    }


def main():
    n, seed = int(sys.argv[1]), int(sys.argv[2])
    r = random.Random(seed)
    out = sys.stdout
    for i in range(n):
        out.write(json.dumps(gen_case(i, r), separators=(",", ":"), sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
