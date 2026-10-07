#!/usr/bin/env python3
"""
NOMOS-SPEC-008 reference verifier — Act Binding.

Verifies a self-verifying Act at the relying party (the system that commits the change):
  1. the Act is addressed to this relying party, inside its validity window, not replayed
  2. the authority artifact's issuer resolves to the pinned root   (NOMOS-SPEC-007 §4)
  3. every fact is testimony from a witness whose chain carries `claim:` scope for it
     (NOMOS-SPEC-007 rev. 1.8 §3.4.1), or comes from the channel its data_contract declares,
     and has the type that input declares (SPEC-008 §7.1)
  4. the sealed rules are evaluated over exactly those facts and exactly this action
     (NOMOS-SPEC-001 §4, with the §4.6 default-outcome amendment), three-valued: a condition
     that needs an absent fact is UNDECIDED, and an allow or escalate result stands only when
     every block or escalate rule that outranks it is decided (SPEC-008 §6.2)
  5. an ESCALATED verdict becomes AUTHORIZED only with enough consents, each signed over this
     Act's binding digest by a key whose chain carries `consent:` scope for the required role

Everything is resolved from the Act itself plus the relying party's own configuration
(pinned root, its own identifier, its own state facts, its nonce ledger). No network call.

Requires: Python 3.9+, `pip install cryptography`.
"""
import base64
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

MAX_CHAIN = 20
MAX_WINDOW_SECONDS = 300          # SPEC-008 §5.3 RECOMMENDED upper bound on an Act's validity
ARTIFACT_DIMS = ("artifact", "industry", "jurisdiction")
STATEMENT_DIMS = ("claim", "consent")
ISO_3166 = re.compile(r"^[A-Z]{2}(-[A-Z0-9]{1,3})?$")
FACT_SOURCES = ("action", "testimony", "relying_party", "presenter")
# Channels whose absence is itself a fact: the action is exactly what will be committed, and the
# relying party reads its own state. For these, exists(f) is decided (SPEC-008 §6.2 rule 2).
ABSENCE_AUTHORITATIVE = ("action", "relying_party")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")

def type_ok(value: Any, spec: dict) -> bool:
    """SPEC-008 §7.1: a present fact has exactly the JSON type its input declares."""
    t = spec.get("type")
    if t == "string":   return isinstance(value, str)
    if t == "number":   return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    if t == "integer":  return (isinstance(value, int) and not isinstance(value, bool)) or (isinstance(value, float) and math.isfinite(value) and value.is_integer())
    if t == "boolean":  return isinstance(value, bool)
    if t == "date":     return isinstance(value, str) and bool(_DATE.match(value))
    if t == "datetime": return isinstance(value, str) and bool(_DATETIME.match(value))
    if t == "enum":     return isinstance(value, str) and value in (spec.get("enum") or [])
    if t == "object":   return isinstance(value, dict)
    if t == "array":    return isinstance(value, list)
    return False        # no type, or one this verifier does not know: fail closed


# ── canonical JSON (RFC 8785, sufficient for NOMOS objects) ─────────────────────────────
def _jcs(v: Any) -> str:
    if v is None: return "null"
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v, int): return str(v)
    if isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")): raise ValueError("non-finite")
        return str(int(v)) if v.is_integer() and abs(v) < 1e21 else repr(v)
    if isinstance(v, str): return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list): return "[" + ",".join(_jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        ks = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _jcs(v[k]) for k in ks) + "}"
    raise TypeError(type(v))

def jcs(o: Any) -> bytes: return _jcs(o).encode("utf-8")
def sha256_hex(b: bytes) -> str: return hashlib.sha256(b).hexdigest()


# ── keys, signatures, time ──────────────────────────────────────────────────────────────
def compute_kid(pem: str) -> str:
    der = serialization.load_pem_public_key(pem.encode()).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode().rstrip("=")[:16]

def sig_ok(pem: str, msg: bytes, sig_b64: str) -> bool:
    try:
        serialization.load_pem_public_key(pem.encode()).verify(base64.b64decode(sig_b64), msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False

def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


# ── signed payloads ─────────────────────────────────────────────────────────────────────
def cert_payload(c): return {k: c.get(k) for k in ("parent_kid", "child_kid", "child_public_key_pem", "issued_at", "expires_at")} | {"scope": c.get("scope")}
def testimony_payload(t): return {k: t.get(k) for k in ("claim", "value", "about", "as_of", "valid_until", "kid")}
def consent_payload(c): return {k: c.get(k) for k in ("binding_digest", "role", "decision", "signed_at", "kid")}

def binding_core(act: dict) -> dict:
    """SPEC-008 §4: what every consent signs, and what the relying party commits."""
    art = (act.get("authority") or {}).get("artifact") or {}
    return {
        "act_version": act.get("act_version"), "act_id": act.get("act_id"), "nonce": act.get("nonce"),
        "issued_at": act.get("issued_at"), "expires_at": act.get("expires_at"),
        "relying_party": act.get("relying_party"), "action": act.get("action"),
        "artifact_hash": (art.get("seal") or {}).get("hash"),
        "testimony_digest": sha256_hex(jcs(sorted((act.get("testimony") or []), key=lambda t: _jcs(t)))),
    }

def binding_digest(act: dict) -> str: return sha256_hex(jcs(binding_core(act)))


# ── scope (SPEC-007 §3.4 + rev. 1.8 §3.4.1) ─────────────────────────────────────────────
class ScopeError(Exception): pass

def parse_scope(s: Optional[str]) -> List[Tuple[str, str]]:
    if s is None or not s.strip(): return []
    out, seen = [], set()
    for term in s.split():
        d, sep, v = term.partition(":")
        if not sep or not d or not v or d in seen: raise ScopeError(term)
        seen.add(d); out.append((d, v))
    return out

def _set(v: str) -> Set[str]: return {x for x in v.split(",") if x}

def contains(dim: str, outer: str, inner: str) -> bool:
    if dim == "artifact": return outer == inner
    if dim == "industry": return inner == outer or inner.startswith(outer + "/")
    if dim == "jurisdiction": return inner == outer or (len(outer) == 2 and inner.startswith(outer + "-"))
    if dim in STATEMENT_DIMS: return _set(inner) <= _set(outer)      # narrowing = subset
    return False

def meta_matches(dim: str, val: str, meta: dict) -> bool:
    if dim == "artifact": return meta.get("artifact_id") == val
    if dim == "industry":
        ind = meta.get("industry"); return isinstance(ind, str) and bool(ind) and contains("industry", val, ind)
    if dim == "jurisdiction":
        cs = meta.get("jurisdiction_codes")
        if not isinstance(cs, list) or not cs or not all(isinstance(c, str) and ISO_3166.match(c) for c in cs): return False
        return all(contains("jurisdiction", val, c) for c in cs)
    return False


# ── chain resolution, generalised to any signed statement (SPEC-007 rev. 1.8 §4.6) ──────
def _fp(c) -> str: return sha256_hex(jcs(cert_payload(c)))

def _paths_to(target: str, root: str, pool: list, seen: frozenset, depth: int = 0):
    """Target-first path search (SPEC-007 rev. 1.8 §4.2a). Yields root→target certificate
    lists. Candidates are tried in fingerprint order so the result never depends on the order
    the pool was presented in, even when the pool is a tree rather than a single chain."""
    if target == root: yield []; return
    if depth >= MAX_CHAIN or target in seen: return
    for c in sorted((c for c in pool if c.get("child_kid") == target), key=_fp):
        for head in _paths_to(c.get("parent_kid"), root, pool, seen | {target}, depth + 1):
            yield head + [c]

def _validate_path(path: list, root_pem: str, now: datetime, revoked_kids: Set[str], revoked_certs: Set[str]) -> dict:
    cur_key = root_pem
    for cert in path:
        try: kid_ok = compute_kid(cert["child_public_key_pem"]) == cert["child_kid"]
        except (ValueError, KeyError): kid_ok = False
        if not kid_ok: return {"decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "kid_mismatch"}
        if not sig_ok(cur_key, jcs(cert_payload(cert)), cert.get("signature", "")):
            return {"decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "bad_signature"}
        if now > ts(cert["expires_at"]): return {"decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "expired"}
        if now < ts(cert["issued_at"]): return {"decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "not_yet_valid"}
        if _fp(cert) in revoked_certs: return {"decision": "CERTIFICATE_REVOKED"}
        if cert["child_kid"] in revoked_kids: return {"decision": "KEY_REVOKED", "revoked_kid": cert["child_kid"]}
        cur_key = cert["child_public_key_pem"]
    return {"decision": "RESOLVED", "key": cur_key}

def resolve_chain(target_kid: str, pool: list, root_pem: str, now: datetime,
                  revoked_kids: Set[str], revoked_certs: Set[str]) -> dict:
    root_kid = compute_kid(root_pem)
    if root_kid in revoked_kids: return {"decision": "KEY_REVOKED", "revoked_kid": root_kid}
    first_failure = None; hops = None; key = None
    for path in _paths_to(target_kid, root_kid, pool, frozenset()):
        r = _validate_path(path, root_pem, now, revoked_kids, revoked_certs)
        if r["decision"] == "RESOLVED": hops, key = path, r["key"]; break
        first_failure = first_failure or r
    if hops is None:
        if first_failure: return first_failure
        from_root = any(c.get("parent_kid") == root_kid for c in pool)
        return {"decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "chain_broken" if from_root else "no_certificate_for_root"}
    cur_key = key
    effective: Dict[str, str] = {}
    for cert in hops:
        try: terms = parse_scope(cert.get("scope"))
        except ScopeError: return {"decision": "OUT_OF_SCOPE", "reason_code": "malformed_scope"}
        for d, v in terms:
            if d in effective and not contains(d, effective[d], v):
                return {"decision": "OUT_OF_SCOPE", "dimension": d, "reason_code": "widening"}
            effective[d] = v
    return {"decision": "RESOLVED", "key": cur_key, "effective": effective}

def scope_ok_for_statement(effective: dict, kind: str, name: str, meta: dict) -> Tuple[bool, Optional[str]]:
    """A statement key's scope (§3.4.1): must carry `kind` covering `name`; artifact-matching
    dimensions are matched against the Act's authority artifact; anything else fails closed."""
    if kind not in effective or name not in _set(effective[kind]): return False, kind
    for d, v in effective.items():
        if d == kind: continue
        if d in ARTIFACT_DIMS:
            if not meta_matches(d, v, meta): return False, d
        else:
            return False, d        # a claim key presented as a consent key, or an unknown dimension
    return True, None


# ── Nomos-Expr v1 evaluator (SPEC-001 §4.1), three-valued (SPEC-008 §6.2) ──────────────
# A condition is TRUE, FALSE or UNDECIDED. A fact that is absent (or null) is not false: any
# primitive that reads it is UNDECIDED, and and/or/not follow Kleene's strong three-valued logic.
T, F, U = "TRUE", "FALSE", "UNDECIDED"
_KEYWORDS = {"and", "or", "not", "in", "contains", "between", "exists", "matches", "true", "false", "always"}
_TOK = re.compile(r'\s*(?:(?P<num>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(?P<str>"[^"]*")|(?P<op>==|!=|>=|<=|>|<|\(|\)|,)|(?P<id>[A-Za-z_][\w.]*))')

def _tokens(s: str) -> list:
    pos, out = 0, []
    while pos < len(s):
        if s[pos:].strip() == "": break
        m = _TOK.match(s, pos)
        if not m or m.end() == pos: raise ValueError(f"cannot parse at {pos}: {s[pos:pos+20]!r}")
        kind = m.lastgroup; val = m.group(kind); pos = m.end()
        out.append((kind, val))
    return out

def _lookup(facts: dict, path: str):
    cur: Any = facts
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur: return None
        cur = cur[part]
    return cur

def _tri(b) -> str: return T if b else F
def _and(a, b): return F if F in (a, b) else (U if U in (a, b) else T)
def _or(a, b): return T if T in (a, b) else (U if U in (a, b) else F)
def _not(a): return {T: F, F: T, U: U}[a]

class _Absent: pass
ABSENT = _Absent()

class _Parser:
    def __init__(self, toks, facts, decided_absent=()): self.t, self.i, self.f, self.da = toks, 0, facts, decided_absent
    def peek(self): return self.t[self.i] if self.i < len(self.t) else (None, None)
    def take(self): tok = self.peek(); self.i += 1; return tok
    def expr(self):
        v = self.andx()
        while self.peek() == ("id", "or"): self.take(); v = _or(v, self.andx())
        return v
    def andx(self):
        v = self.unary()
        while self.peek() == ("id", "and"): self.take(); v = _and(v, self.unary())
        return v
    def unary(self):
        if self.peek() == ("id", "not"): self.take(); return _not(self.unary())
        return self.primary()
    def operand(self):
        k, v = self.take()
        if k == "num": return float(v) if any(c in v for c in ".eE") else int(v)
        if k == "str": return v[1:-1]
        if k == "id":
            if v == "true": return True
            if v == "false": return False
            if v == "always": return True
            return ("FIELD", v)
        raise ValueError(f"unexpected {v!r}")
    def val(self, x):
        """A literal, the fact's value, or ABSENT when the fact is missing or null."""
        if not isinstance(x, tuple): return x
        got = _lookup(self.f, x[1])
        return ABSENT if got is None else got
    def primary(self) -> str:
        k, v = self.peek()
        if (k, v) == ("op", "("):
            self.take(); r = self.expr(); self.take(); return r
        if k == "id" and v in ("exists", "matches") and self.t[self.i + 1:self.i + 2] == [("op", "(")]:
            self.take(); self.take(); f = self.operand()
            if v == "exists":
                self.take()
                if self.val(f) is not ABSENT: return T
                # Absence decides exists() only where absence is authoritative (§6.2 rule 2):
                # a missing witness statement is unknown, not a statement that nothing exists.
                name = f[1] if isinstance(f, tuple) else None
                return F if name is not None and (name in self.da or name.split(".")[0] in self.da) else U
            self.take(); pat = self.operand(); self.take()
            x = self.val(f)
            if x is ABSENT: return U
            return _tri(isinstance(x, str) and re.search(pat, x) is not None)
        left = self.operand()
        k2, op = self.peek()
        if k2 == "op" and op in ("==", "!=", ">", ">=", "<", "<="):
            self.take(); right = self.operand()
            a, b = self.val(left), self.val(right)
            if a is ABSENT or b is ABSENT: return U
            try:
                return _tri({"==": a == b, "!=": a != b, ">": a > b, ">=": a >= b, "<": a < b, "<=": a <= b}[op])
            except TypeError:
                return F
        if (k2, op) in (("id", "in"), ("id", "contains"), ("id", "between")):
            self.take(); rhs = self.val(self.operand()); a = self.val(left)
            if a is ABSENT or rhs is ABSENT: return U
            if op == "in": return _tri(str(a) in [p.strip() for p in str(rhs).split(",")])
            if op == "contains": return _tri(str(rhs).lower() in str(a).lower())
            lo, hi = (float(p) for p in str(rhs).split(","))
            return _tri(isinstance(a, (int, float)) and lo <= a <= hi)
        x = self.val(left)
        return U if x is ABSENT else _tri(bool(x))

def eval_when(expr: str, facts: dict, decided_absent=()) -> str:
    p = _Parser(_tokens(expr), facts, decided_absent)
    r = p.expr()
    if p.i != len(p.t): raise ValueError(f"trailing tokens in {expr!r}")
    return r

def absent_fields(expr: str, facts: dict) -> List[str]:
    """Every fact the condition names that is missing or null — what testimony would decide it."""
    toks = _tokens(expr)
    return sorted({v for i, (k, v) in enumerate(toks)
                   if k == "id" and v not in _KEYWORDS and _lookup(facts, v) is None
                   and toks[i + 1:i + 2] != [("op", "(")]})

RANK = {"block": 3, "escalate": 2, "allow": 1}
TIE_ORDERS = {"deny_wins": RANK, "allow_wins": {"allow": 3, "escalate": 2, "block": 1}, "escalate_wins": {"escalate": 3, "block": 2, "allow": 1}}

def evaluate(artifact: dict, facts: dict) -> dict:
    logic = artifact["logic"]; res = logic.get("resolution", {})
    order = TIE_ORDERS[res.get("tie_breaker", "deny_wins")]
    inputs = artifact.get("data_contract", {}).get("inputs", {})
    decided_absent = {"action_type"} | {n for n, i in inputs.items() if (i or {}).get("source") in ABSENCE_AUTHORITATIVE}
    results = [(d, eval_when(d["when"], facts, decided_absent)) for d in logic["decisions"]]
    matched = [d for d, r in results if r == T]
    if not matched:
        default = res.get("default_outcome", "block")          # SPEC-001 §4.6 amendment; SPEC-008 §6.1
        ev = {"outcome": default, "rule": None, "reason_code": "no_matching_rule", "escalation_id": res.get("default_escalation_id")}
        decider = None
    else:
        top = max(d["priority"] for d in matched)
        best = [d for d in matched if d["priority"] == top]
        decider = max(best, key=lambda x: order[x["then"][0]["type"]])
        t = decider["then"][0]
        ev = {"outcome": t["type"], "rule": decider["id"], "escalation_id": t.get("escalation_id")}
    # SPEC-008 §6.2: a result that could commit stands only if nothing that outranks it is undecided.
    if ev["outcome"] in ("allow", "escalate"):
        def outranks(d) -> bool:
            if decider is None: return True
            if d["priority"] != decider["priority"]: return d["priority"] > decider["priority"]
            return order[d["then"][0]["type"]] > order[ev["outcome"]]
        open_rules = [d for d, r in results if r == U and d["then"][0]["type"] in ("block", "escalate") and outranks(d)]
        if open_rules:
            open_rules.sort(key=lambda d: -d["priority"])
            return {"outcome": "undecided", "rule": ev["rule"],
                    "open_rules": [d["id"] for d in open_rules],
                    "open_facts": sorted({f for d in open_rules for f in absent_fields(d["when"], facts)})}
    return ev


# ── the Act verifier (SPEC-008 §6) ──────────────────────────────────────────────────────
def verify_act(act: Any, *, relying_party_id: str, root_pem: str, now: datetime,
               seen_nonces: Set[str], local_facts: Optional[dict] = None,
               revoked_kids: Optional[Set[str]] = None, revoked_certs: Optional[Set[str]] = None) -> dict:
    revoked_kids = revoked_kids or set(); revoked_certs = revoked_certs or set(); local_facts = local_facts or {}
    # 1. structure
    need = ("act_version", "act_id", "nonce", "issued_at", "expires_at", "relying_party", "action", "authority")
    if not isinstance(act, dict) or any(k not in act for k in need) or act.get("act_version") != "1":
        return {"decision": "MALFORMED", "reason_code": "bad_envelope"}
    try:
        jcs(act)        # an Act RFC 8785 cannot canonicalize (e.g. NaN, Infinity) has no binding digest
    except (ValueError, TypeError):
        return {"decision": "MALFORMED", "reason_code": "not_canonicalizable"}
    action, auth = act["action"], act["authority"]
    if not isinstance(action, dict) or not isinstance(action.get("type"), str) or not isinstance(action.get("params", {}), dict):
        return {"decision": "MALFORMED", "reason_code": "bad_action"}
    art, pool = auth.get("artifact"), auth.get("key_certs", [])
    if not isinstance(pool, list) or len(pool) > MAX_CHAIN: return {"decision": "MALFORMED", "reason_code": "chain_over_length_cap"}
    seal = (art or {}).get("seal") if isinstance(art, dict) else None
    if not isinstance(seal, dict) or seal.get("status") != "sealed" or not all(isinstance(seal.get(k), str) for k in ("hash", "signature", "kid")):
        return {"decision": "MALFORMED", "reason_code": "unsealed_artifact"}
    try:
        t0, t1 = ts(act["issued_at"]), ts(act["expires_at"])
    except (ValueError, TypeError):
        return {"decision": "MALFORMED", "reason_code": "bad_time"}
    if (t1 - t0).total_seconds() > MAX_WINDOW_SECONDS or t1 <= t0:
        return {"decision": "MALFORMED", "reason_code": "validity_window"}
    # 2-4. addressed to us, in time, not replayed
    if act["relying_party"] != relying_party_id: return {"decision": "WRONG_RELYING_PARTY"}
    if now < t0: return {"decision": "NOT_YET_VALID"}
    if now > t1: return {"decision": "EXPIRED"}
    if act["nonce"] in seen_nonces: return {"decision": "REPLAYED"}
    # 5. authority: SPEC-007 §4 for the artifact itself
    r = resolve_chain(seal["kid"], pool, root_pem, now, revoked_kids, revoked_certs)
    if r["decision"] != "RESOLVED": return r
    body = {k: v for k, v in art.items() if k not in ("seal", "attestations")}
    if sha256_hex(jcs(body)) != seal["hash"]: return {"decision": "SEAL_INVALID", "reason_code": "hash_mismatch"}
    if not sig_ok(r["key"], jcs({"hash": seal["hash"], "signed_by": seal.get("signed_by")}), seal["signature"]):
        return {"decision": "SEAL_INVALID", "reason_code": "bad_signature"}
    meta = art.get("meta", {})
    for d, v in r["effective"].items():
        if d not in ARTIFACT_DIMS or not meta_matches(d, v, meta):
            return {"decision": "OUT_OF_SCOPE", "dimension": d}      # incl. a claim/consent key sealing rules
    # 6. testimony
    facts: Dict[str, Any] = {}; channel: Dict[str, str] = {}
    def put(name, value, src):
        if name in channel: raise KeyError(name)
        facts[name] = value; channel[name] = src
    subject = action.get("subject")
    for t in act.get("testimony") or []:
        if not isinstance(t, dict) or not all(k in t for k in ("claim", "value", "as_of", "valid_until", "kid", "signature")):
            return {"decision": "MALFORMED", "reason_code": "bad_testimony"}
        w = resolve_chain(t["kid"], pool, root_pem, now, revoked_kids, revoked_certs)
        if w["decision"] != "RESOLVED":
            return {"decision": "TESTIMONY_INVALID", "claim": t["claim"], "reason_code": "witness_" + w["decision"].lower()}
        ok, dim = scope_ok_for_statement(w["effective"], "claim", t["claim"], meta)
        if not ok: return {"decision": "TESTIMONY_OUT_OF_SCOPE", "claim": t["claim"], "dimension": dim}
        if not sig_ok(w["key"], jcs(testimony_payload(t)), t["signature"]):
            return {"decision": "TESTIMONY_INVALID", "claim": t["claim"], "reason_code": "bad_signature"}
        if now > ts(t["valid_until"]) or now < ts(t["as_of"]):
            return {"decision": "TESTIMONY_INVALID", "claim": t["claim"], "reason_code": "stale"}
        if t.get("about") is not None and t.get("about") != subject:
            return {"decision": "TESTIMONY_INVALID", "claim": t["claim"], "reason_code": "wrong_subject"}
        try: put(t["claim"], t["value"], "testimony")
        except KeyError: return {"decision": "FACT_SOURCE_VIOLATION", "field": t["claim"], "reason_code": "duplicate"}
    # 7. facts from the other three channels, checked against the declared source of each input
    try:
        put("action_type", action["type"], "action")
        for k, v in (action.get("params") or {}).items(): put(k, v, "action")
        for k, v in (act.get("presenter_facts") or {}).items(): put(k, v, "presenter")
        for k, v in local_facts.items(): put(k, v, "relying_party")
    except KeyError as e:
        return {"decision": "FACT_SOURCE_VIOLATION", "field": e.args[0], "reason_code": "duplicate"}
    inputs = art.get("data_contract", {}).get("inputs", {})
    for name, src in channel.items():
        if name == "action_type": continue
        declared = (inputs.get(name) or {}).get("source")
        if declared is None:
            return {"decision": "FACT_SOURCE_VIOLATION", "field": name, "reason_code": "undeclared_input"}
        if declared != src:
            return {"decision": "FACT_SOURCE_VIOLATION", "field": name, "declared": declared, "supplied_via": src}
    # 7b. every present fact has the type its input declares (§7.1); null is absence, not a type
    for name, value in facts.items():
        if name == "action_type" or value is None: continue
        if not type_ok(value, inputs[name]):
            return {"decision": "FACT_TYPE_VIOLATION", "field": name, "declared": inputs[name].get("type"), "supplied_via": channel[name]}
    # 8. evaluate the sealed rules over exactly these facts
    ev = evaluate(art, facts)
    digest = binding_digest(act)
    base = {"rule": ev["rule"], "act_digest": digest}
    if ev["outcome"] == "undecided":            # §6.2: no consent can stand in for a missing fact
        return {"decision": "INCOMPLETE", "commit": False, "reason_code": "undecided_rules",
                "open_rules": ev["open_rules"], "open_facts": ev["open_facts"], **base}
    if ev.get("reason_code"): base["reason_code"] = ev["reason_code"]
    if ev["outcome"] == "allow": return {"decision": "AUTHORIZED", "commit": True, **base}
    if ev["outcome"] == "block": return {"decision": "DENIED", "commit": False, **base}
    # 9. escalation: consents bound to this exact Act
    esc = next((e for e in art.get("governance", {}).get("escalations", []) if e.get("id") == ev["escalation_id"]), None)
    if esc is None: return {"decision": "ESCALATED", "commit": False, "escalation_id": ev["escalation_id"], "consents_valid": 0, "consents_required": None, **base}
    role, need_n = esc["role_required"], int(esc.get("required_consents", 1))
    signers: Set[str] = set()
    for c in act.get("consents") or []:
        if not isinstance(c, dict) or not all(k in c for k in ("binding_digest", "role", "decision", "signed_at", "kid", "signature")):
            return {"decision": "MALFORMED", "reason_code": "bad_consent"}
        k = resolve_chain(c["kid"], pool, root_pem, now, revoked_kids, revoked_certs)
        if k["decision"] != "RESOLVED": return {"decision": "CONSENT_INVALID", "reason_code": "approver_" + k["decision"].lower()}
        ok, dim = scope_ok_for_statement(k["effective"], "consent", c["role"], meta)
        if not ok: return {"decision": "CONSENT_OUT_OF_SCOPE", "role": c["role"], "dimension": dim}
        if not sig_ok(k["key"], jcs(consent_payload(c)), c["signature"]): return {"decision": "CONSENT_INVALID", "reason_code": "bad_signature"}
        if c["binding_digest"] != digest: return {"decision": "CONSENT_INVALID", "reason_code": "binding_mismatch"}
        if c["decision"] == "approve" and c["role"] == role: signers.add(c["kid"])
    if len(signers) >= need_n:
        return {"decision": "AUTHORIZED", "commit": True, "by_consent": True, "escalation_id": ev["escalation_id"], "consents_valid": len(signers), "consents_required": need_n, **base}
    return {"decision": "ESCALATED", "commit": False, "escalation_id": ev["escalation_id"], "consents_valid": len(signers), "consents_required": need_n, **base}
