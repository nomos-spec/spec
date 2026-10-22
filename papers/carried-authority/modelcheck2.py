#!/usr/bin/env python3
"""
Small-scope model check of the omission-safety theorem (Theorem 6, "Authorize the Act, Not the
Agent") against the reference evaluator, act_verify.evaluate.

For many random prioritized rule sets over a small vocabulary, enumerate every partial fact
assignment F the presenter could produce and every completion F* of it (the facts as they are in
the world), and check:

  Soundness     if evaluate(F) would commit (allow, or escalate), then evaluate(F*) is not block,
                and if evaluate(F) is allow then evaluate(F*) is allow.
  Completeness  if every fact is present and of its declared kind, evaluate(F) is never "undecided".

The same check is run against the two-valued evaluator (absent read as false) to show the property
is not vacuous: that evaluator violates soundness on a large fraction of rule sets.

Usage: python3 modelcheck.py [rule_sets] [seed]
"""
import itertools, random, sys, types
import act_verify_040 as AV          # SPEC-008 0.4.0 reference verifier, frozen from nomos-spec c8fa382

N = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
rng = random.Random(int(sys.argv[2]) if len(sys.argv) > 2 else 2026)

# Vocabulary: two witnessed numeric facts, one witnessed boolean, one relying-party numeric fact.
WITNESSED = {"a": "number", "b": "number", "c": "boolean"}
AUTHORITATIVE = {"r": "number"}
NUM_DOM = [0, 1, 2]
WRONG_KIND = ["1"]                     # a present value of the wrong kind (rule 3: out-of-domain)
OUT = ["allow", "block", "escalate"]

def atom():
    k = rng.random()
    if k < 0.15: return f"exists({rng.choice(list(WITNESSED) + list(AUTHORITATIVE))})"
    if k < 0.30: return f"c == {rng.choice(['true', 'false'])}"
    f = rng.choice(["a", "b", "r"])
    return f"{f} {rng.choice(['>', '>=', '<', '<=', '==', '!='])} {rng.choice(NUM_DOM)}"

def cond(depth=0):
    k = rng.random()
    if depth >= 2 or k < 0.45: return atom()
    if k < 0.70: return f"({cond(depth + 1)}) and ({cond(depth + 1)})"
    if k < 0.92: return f"({cond(depth + 1)}) or ({cond(depth + 1)})"
    return f"not ({cond(depth + 1)})"

def rule_set():
    n = rng.randint(1, 5)
    ds = [{"id": f"D{i}", "when": cond(), "then": [{"type": t, "escalation_id": rng.choice(["E1", "E2"])} if (t := rng.choice(OUT)) else None],
           "priority": rng.choice([10, 20, 20, 30, 40])} for i in range(n)]          # ties are deliberate
    inputs = {k: {"type": t, "source": "testimony"} for k, t in WITNESSED.items()}
    inputs.update({k: {"type": t, "source": "relying_party"} for k, t in AUTHORITATIVE.items()})
    return {"logic": {"decisions": ds, "resolution": {"tie_breaker": rng.choice(["deny_wins", "allow_wins", "escalate_wins"]),
                                                       "default_outcome": rng.choice(OUT), "default_escalation_id": "E1"}},
            "data_contract": {"inputs": inputs}}

ABSENT = object()
def domain(name):
    t = {**WITNESSED, **AUTHORITATIVE}[name]
    return (NUM_DOM + WRONG_KIND) if t == "number" else [True, False]

def assignments(names, allow_absent):
    doms = [domain(n) + ([ABSENT] if allow_absent else []) for n in names]
    for vals in itertools.product(*doms):
        yield {n: v for n, v in zip(names, vals) if v is not ABSENT}

TWO_VALUED_SRC = open(AV.__file__).read().replace(
    "    results = [(d, r) for d, r, _ in detail]",
    "    results = [(d, (F if r == U else r)) for d, r, _ in detail]")
TWO = types.ModuleType("two_valued"); exec(compile(TWO_VALUED_SRC, "<two>", "exec"), TWO.__dict__)
_src = open(AV.__file__).read(); assert _src.count('            return order[d["then"][0]["type"]] > order[ev["outcome"]]') == 1
# The corrected gate as an in-memory patch of 0.4.0; equivalent to act_verify_050.py's clause (ii).
PATCHED = types.ModuleType("patched_gate"); exec(compile(_src.replace('            return order[d["then"][0]["type"]] > order[ev["outcome"]]', '            if d["then"][0]["type"] == "escalate" and ev["outcome"] == "escalate" and d["then"][0].get("escalation_id") != ev.get("escalation_id"): return True\n            return order[d["then"][0]["type"]] > order[ev["outcome"]]'), "<patched>", "exec"), PATCHED.__dict__)

def check(mod, art, rp_facts):
    """Returns (soundness violations, completeness violations, committing partial states)."""
    bad_sound = bad_complete = commits = 0
    w = list(WITNESSED)
    for F in assignments(w, True):
        facts = {**F, **rp_facts}
        try: ev = mod.evaluate(art, facts)
        except Exception: continue
        if ev["outcome"] in ("allow", "escalate"):
            commits += 1
            missing = [n for n in w if n not in F]
            for ext in assignments(missing, False):
                ev2 = mod.evaluate(art, {**facts, **ext})
                same_escalation = ev2["outcome"] != "escalate" or ev2.get("escalation_id") == ev.get("escalation_id")
                if ev2["outcome"] == "block" or (ev["outcome"] == "allow" and ev2["outcome"] != "allow") \
                        or ev2["outcome"] == "undecided" or (ev["outcome"] == "escalate" and not same_escalation):
                    bad_sound += 1; break
        well_kinded = all(not isinstance(v, str) for v in facts.values())
        if len(F) == len(w) and "r" in rp_facts and well_kinded and ev["outcome"] == "undecided":
            bad_complete += 1          # Theorem 7: every read fact present and of its declared kind
    return bad_sound, bad_complete, commits

tot = {"ref": [0, 0, 0, 0], "patched": [0, 0, 0, 0], "two": [0, 0, 0, 0]}    # violations, completeness violations, commits, rule sets with a violation
for i in range(N):
    art = rule_set()
    rp_facts = {"r": rng.choice(NUM_DOM)} if rng.random() < 0.85 else {}   # the relying party's own state (or authoritative absence)
    for label, mod in (("ref", AV), ("patched", PATCHED), ("two", TWO)):
        s, c, k = check(mod, art, rp_facts)
        t = tot[label]; t[0] += s; t[1] += c; t[2] += k; t[3] += (1 if s else 0)

print(f"rule sets: {N}  (vocabulary: 3 witnessed facts, 1 relying-party fact; domains with absence and a wrong-kind value)")
for label, name in (("ref", "SPEC-008 0.4.0 reference evaluator"), ("patched", "reference with the equal-priority escalation gate"), ("two", "ablated evaluator (undecided read as not holding)")):
    v, c, k, rs = tot[label]
    print(f"  {name}\n    committing partial states checked: {k}\n    soundness violations: {v}  (rule sets affected: {rs})\n    completeness violations: {c}")
