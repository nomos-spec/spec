#!/usr/bin/env python3
"""Random fact sets for real sealed authorities, aimed at what their rules test.

    python3 laws.py N SEED artifact.json [artifact.json ...] > cases.jsonl

For each artifact: every field a rule reads, with candidate values taken from the rules
themselves (each number compared against, one either side of it, and half a step off; each
string compared against or listed in an `in`; true and false), plus the declared enum values;
about a quarter of fields absent, and now and then a value of the wrong kind. Deterministic.
"""
import json
import random
import re
import sys

TOK = re.compile(r'\s*(?:(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|("[^"]*")|(==|!=|>=|<=|>|<|\(|\)|,)|([A-Za-z_][\w.]*))')
KEYWORDS = {"and", "or", "not", "in", "contains", "between", "exists", "matches", "true", "false", "always"}


def find_artifact(o):
    if isinstance(o, dict):
        if isinstance(o.get("logic"), dict) and isinstance(o["logic"].get("decisions"), list):
            return o
        for v in o.values():
            a = find_artifact(v)
            if a:
                return a
    elif isinstance(o, list):
        for v in o:
            a = find_artifact(v)
            if a:
                return a
    return None


def tokens(s):
    out, pos = [], 0
    while pos < len(s) and s[pos:].strip():
        m = TOK.match(s, pos)
        if not m or m.end() == pos:
            break
        out.append(m.groups())
        pos = m.end()
    return out


def pools(art):
    vals = {}
    def add(f, v):
        vals.setdefault(f, set()).add(json.dumps(v))
    for d in art["logic"]["decisions"]:
        w = d.get("when")
        if not isinstance(w, str):
            continue
        ts = tokens(w)
        for i, (num, st, op, ident) in enumerate(ts):
            if ident and ident not in KEYWORDS:
                vals.setdefault(ident, set())
                nxt = ts[i + 2] if i + 2 < len(ts) else (None,) * 4
                mid = ts[i + 1] if i + 1 < len(ts) else (None,) * 4
                if nxt[0] is not None:
                    x = float(nxt[0])
                    for v in (x, x - 1, x + 1, x + 0.5):
                        add(ident, int(v) if v == int(v) else v)
                if nxt[1] is not None:
                    lit = nxt[1][1:-1]
                    if mid[3] in ("in",):
                        for p in lit.split(","):
                            add(ident, p.strip())
                    elif mid[3] == "between":
                        for p in lit.split(","):
                            try:
                                x = float(p)
                                add(ident, x)
                                add(ident, x - 1)
                            except ValueError:
                                pass
                    else:
                        add(ident, lit)
                if nxt[3] in ("true", "false"):
                    add(ident, True)
                    add(ident, False)
    for name, spec in (art.get("data_contract", {}).get("inputs") or {}).items():
        t = (spec or {}).get("type")
        if t == "boolean":
            add(name, True); add(name, False)
        for e in (spec or {}).get("enum", []) or []:
            add(name, e)
    for f in vals:
        if not vals[f]:
            vals[f] = {json.dumps(True), json.dumps(False)}
    return {f: sorted(v) for f, v in vals.items()}


def nest(facts, path, v):
    parts = path.split(".")
    cur = facts
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1]] = v


def main():
    n, seed, paths = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3:]
    r = random.Random(seed)
    for path in paths:
        art = find_artifact(json.load(open(path)))
        pool = pools(art)
        name = path.split("/")[-2] + "/" + path.split("/")[-1]
        for i in range(n):
            facts = {}
            for f in sorted(pool):
                if r.random() < 0.25:
                    continue
                v = json.loads(r.choice(pool[f]))
                if r.random() < 0.03:
                    v = r.choice([True, "x", 7])
                nest(facts, f, v)
            sys.stdout.write(json.dumps({"id": "%s#%d" % (name, i), "artifact": art, "facts": facts},
                                        separators=(",", ":"), sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
