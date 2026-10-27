"""
NOMOS-SPEC-008 0.6.0 reference verifier — Act Binding.

Verifies a self-verifying Act at the relying party (the system that commits the change):
  1. the Act is addressed to this relying party, inside its validity window, not replayed
  2. the authority artifact's issuer resolves to the pinned root, scope-aware (NOMOS-SPEC-007
     rev. 1.9 §4.2a), its seal verifies, it is the version in force under the relying party's
     declared currency policy (§5.4, §5.5), and its escalations are unambiguous (step 5b)
  3. every fact is testimony from a witness whose chain carries `claim:` scope for it
     (NOMOS-SPEC-007 rev. 1.8 §3.4.1), or comes from the channel its data_contract declares,
     and has the type that input declares (SPEC-008 §7.1)
  4. the sealed rules are evaluated over exactly those facts and exactly this action
     (NOMOS-SPEC-001 §4, with the §4.6 default-outcome amendment), three-valued: a condition
     that needs an absent fact is UNDECIDED, and an allow or escalate result stands only when
     every block or escalate rule that outranks it is decided (SPEC-008 §6.2)
  5. an ESCALATED verdict becomes AUTHORIZED only with consents from enough distinct people
     (§4.4), each signed over this Act's binding digest, by Ed25519, ES256 or passkey (§4.5)

Signatures follow NOMOS-SPEC-010; chain resolution is chain.py in this package.
Everything is resolved from the Act itself plus the relying party's own configuration
(pinned root, its own identifier, its own state facts, its nonce ledger). No network call.

Requires: Python 3.9+, `pip install cryptography`.
"""
import math
import re
from datetime import datetime
from typing import Any, Dict, Optional, Set, Tuple

from . import chain, suites
from .chain import ts, cert_payload, ScopeError, parse_scope, contains, meta_matches  # noqa: F401
from .jcs import jcs, jcs_text as _jcs, sha256_hex

MAX_CHAIN = chain.MAX_CHAIN
MAX_WINDOW_SECONDS = 300          # SPEC-008 §5.3 RECOMMENDED upper bound on an Act's validity
MAX_IN_FORCE_SECONDS = 86400      # SPEC-008 §5.4: an in-force statement lives at most one day
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


# §6.3 (0.6.0): the suites each statement may be signed under (NOMOS-SPEC-010)
TESTIMONY_SUITES = ("Ed25519", "ES256")          # testimony and in-force statements
CONSENT_SUITES = ("Ed25519", "ES256", "WebAuthn-ES256")
CURRENCY_POLICIES = ("record", "record_or_statement")
WEBAUTHN_FIELDS = ("authenticator_data", "client_data_json", "signature")

def proof_of(st: dict) -> dict:
    """The NOMOS-SPEC-010 proof object a statement carries for its suite."""
    if st.get("algorithm") == "WebAuthn-ES256": return {k: st.get(k) for k in WEBAUTHN_FIELDS}
    return {"signature": st.get("signature")}

def statement_sig(pem: str, st: dict, payload: dict) -> Tuple[bool, Optional[str]]:
    return suites.verify(st.get("algorithm"), pem, jcs(payload), proof_of(st))

def ambiguous_escalation(art: dict) -> bool:
    """NOMOS-SPEC-001 amendment 2.3.0: two escalate decisions of equal priority naming different
    escalations. The verdict would depend on which is listed first (R-19 §7.5)."""
    named: Dict[Any, Set[Any]] = {}
    for d in (art.get("logic") or {}).get("decisions") or []:
        t = (d.get("then") or [{}])[0]
        if t.get("type") == "escalate": named.setdefault(d.get("priority"), set()).add(t.get("escalation_id"))
    return any(len(ids) > 1 for ids in named.values())


# ── signed payloads ─────────────────────────────────────────────────────────────────────
def testimony_payload(t): return {k: t.get(k) for k in ("claim", "value", "about", "as_of", "valid_until", "kid")}
def consent_payload(c): return {k: c.get(k) for k in ("binding_digest", "role", "decision", "signed_at", "kid")}
def in_force_payload(s): return {k: s.get(k) for k in ("artifact_id", "version", "seal_hash", "as_of", "valid_until", "kid")}

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


# ── chain resolution: NOMOS-SPEC-007 rev. 1.9, shared (python/nomosprotocol/chain.py) ─────────────
def resolve_statement_key(kind: str, name: str, st: dict, pool: list, root_pem: str, now: datetime,
                          meta: dict, revoked_kids: Set[str], revoked_certs: Set[str]) -> dict:
    """§4.6: resolve a witness or approver key for one statement, scope-aware (rev. 1.9 §4.2a),
    under the statement's own suite. A consent key must carry an `approver` (§4.4), and every
    admitted path to it is collected so the approver cannot depend on the path presented."""
    consent = kind == "consent"
    admit = chain.for_statement(kind, name, meta, st["algorithm"], required=("approver",) if consent else ())
    return chain.resolve(st["kid"], pool, root_pem, now, admit, revoked_kids, revoked_certs, all_paths=consent)

def statement_failure(r: dict, invalid: str, out_of_scope: str, **who) -> dict:
    """An admission failure (the key is genuine but not permitted this statement) is *_OUT_OF_SCOPE;
    every other failure of the witness's or approver's chain is *_INVALID (SPEC-007 rev. 1.8 §4.6)."""
    if r["decision"] == "OUT_OF_SCOPE" and "reason_code" not in r:
        return {"decision": out_of_scope, **who, "dimension": r["dimension"]}
    prefix = "witness_" if invalid == "TESTIMONY_INVALID" else "approver_"
    return {"decision": invalid, **who, "reason_code": prefix + r["decision"].lower()}


# ── Nomos-Expr v1 evaluator (SPEC-001 §4.1), three-valued (SPEC-008 §6.2) ──────────────
# A condition is TRUE, FALSE or UNDECIDED. A fact that is absent (or null) is not false: any
# primitive that reads it is UNDECIDED, and and/or/not follow Kleene's strong three-valued logic.
T, F, U = "TRUE", "FALSE", "UNDECIDED"
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

def _kind(x) -> str:
    """The JSON type of a present value. Booleans are not numbers."""
    if isinstance(x, bool): return "boolean"
    if isinstance(x, (int, float)): return "number"
    if isinstance(x, str): return "string"
    if isinstance(x, dict): return "object"
    if isinstance(x, list): return "array"
    return "other"
# SPEC-008 §6.2 rule 3: a primitive whose present operands are outside its domain is UNDECIDED,
# like an absent one. A value of the wrong kind says nothing decisive about the condition, and
# reading it as FALSE would let a presenter silence a deny rule by choosing the kind.

class _Parser:
    def __init__(self, toks, facts, decided_absent=()):
        self.t, self.i, self.f, self.da = toks, 0, facts, decided_absent
        self.undecided_by: Set[str] = set()     # fields that left some primitive UNDECIDED
    def _u(self, *ops) -> str:
        """UNDECIDED, recording which fields made it so: they are what would decide the rule."""
        self.undecided_by.update(o[1] for o in ops if isinstance(o, tuple))
        return U
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
                return F if name is not None and (name in self.da or name.split(".")[0] in self.da) else self._u(f)
            self.take(); pat = self.operand(); self.take()
            x = self.val(f)
            if x is ABSENT or _kind(x) != "string": return self._u(f)
            return _tri(re.search(pat, x) is not None)
        left = self.operand()
        k2, op = self.peek()
        if k2 == "op" and op in ("==", "!=", ">", ">=", "<", "<="):
            self.take(); right = self.operand()
            a, b = self.val(left), self.val(right)
            # §6.2: open_facts names the fields that left the primitive undecided — the absent ones,
            # not a present operand beside them.
            if a is ABSENT or b is ABSENT: return self._u(*[x for x, v in ((left, a), (right, b)) if v is ABSENT])
            ka, kb = _kind(a), _kind(b)
            if ka != kb or ka == "other" or (op not in ("==", "!=") and ka not in ("number", "string")): return self._u(left, right)
            if ka in ("object", "array"):
                eq = jcs(a) == jcs(b)
                return _tri(eq if op == "==" else not eq)
            return _tri({"==": a == b, "!=": a != b, ">": a > b, ">=": a >= b, "<": a < b, "<=": a <= b}[op])
        if (k2, op) in (("id", "in"), ("id", "contains"), ("id", "between")):
            self.take(); right = self.operand(); rhs = self.val(right); a = self.val(left)
            if a is ABSENT or rhs is ABSENT: return self._u(*[x for x, v in ((left, a), (right, rhs)) if v is ABSENT])
            if op == "between":
                if _kind(a) != "number": return self._u(left)
                lo, hi = (float(p) for p in str(rhs).split(","))
                return _tri(lo <= a <= hi)
            if _kind(a) not in ("string", "number", "boolean"): return self._u(left)
            if op == "in": return _tri(str(a) in [p.strip() for p in str(rhs).split(",")])
            return _tri(str(rhs).lower() in str(a).lower())
        x = self.val(left)
        return self._u(left) if x is ABSENT or _kind(x) != "boolean" else _tri(x)

def eval_when_detail(expr: str, facts: dict, decided_absent=()) -> Tuple[str, Set[str]]:
    p = _Parser(_tokens(expr), facts, decided_absent)
    r = p.expr()
    if p.i != len(p.t): raise ValueError(f"trailing tokens in {expr!r}")
    return r, p.undecided_by

def eval_when(expr: str, facts: dict, decided_absent=()) -> str:
    return eval_when_detail(expr, facts, decided_absent)[0]

RANK = {"block": 3, "escalate": 2, "allow": 1}
TIE_ORDERS = {"deny_wins": RANK, "allow_wins": {"allow": 3, "escalate": 2, "block": 1}, "escalate_wins": {"escalate": 3, "block": 2, "allow": 1}}

def evaluate(artifact: dict, facts: dict) -> dict:
    logic = artifact["logic"]; res = logic.get("resolution", {})
    order = TIE_ORDERS[res.get("tie_breaker", "deny_wins")]
    inputs = artifact.get("data_contract", {}).get("inputs", {})
    decided_absent = {"action_type"} | {n for n, i in inputs.items() if (i or {}).get("source") in ABSENCE_AUTHORITATIVE}
    detail = [(d, *eval_when_detail(d["when"], facts, decided_absent)) for d in logic["decisions"]]
    results = [(d, r) for d, r, _ in detail]
    undecided_by = {d["id"]: u for d, _, u in detail}
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
        def same_rank_other_escalation(d) -> bool:   # §6.2 (0.5.0): equal priority, both escalate, different escalation
            return (decider is not None and ev["outcome"] == "escalate" and d["then"][0]["type"] == "escalate"
                    and d["priority"] == decider["priority"] and d["then"][0].get("escalation_id") != ev.get("escalation_id"))
        open_rules = [d for d, r in results if r == U and d["then"][0]["type"] in ("block", "escalate") and (outranks(d) or same_rank_other_escalation(d))]
        if open_rules:
            open_rules.sort(key=lambda d: -d["priority"])
            return {"outcome": "undecided", "rule": ev["rule"],
                    "open_rules": [d["id"] for d in open_rules],
                    "open_facts": sorted({f for d in open_rules for f in undecided_by[d["id"]]})}
    return ev


# ── the Act verifier (SPEC-008 §6) ──────────────────────────────────────────────────────
def verify_act(act: Any, *, relying_party_id: str, root_pem: str, now: datetime,
               seen_nonces: Set[str], currency_policy: str, local_facts: Optional[dict] = None,
               revoked_kids: Optional[Set[str]] = None, revoked_certs: Optional[Set[str]] = None,
               in_force: Optional[Dict[str, str]] = None, revoked_artifacts: Optional[Set[str]] = None,
               max_window_seconds: int = MAX_WINDOW_SECONDS) -> dict:
    """`in_force` is the relying party's own record of the version in force, artifact_id -> seal hash
    (§5.4); `revoked_artifacts` the seal hashes its revocation source lists (NOMOS-SPEC-006);
    `currency_policy` the policy it declares for establishing currency (§5.5): "record" or
    "record_or_statement". There is no default: the choice is the relying party's to declare.
    `max_window_seconds` is the relying party's own maximum Act window (§5.1), 300 unless it
    configures otherwise, for example to leave a human time to approve (NOMOS-SPEC-009 §6.3)."""
    if currency_policy not in CURRENCY_POLICIES: raise ValueError(f"currency_policy must be one of {CURRENCY_POLICIES}")
    revoked_kids = revoked_kids or set(); revoked_certs = revoked_certs or set(); local_facts = local_facts or {}
    in_force = in_force or {}; revoked_artifacts = revoked_artifacts or set()
    # 1. structure
    need = ("act_version", "act_id", "nonce", "issued_at", "expires_at", "relying_party", "action", "authority")
    if not isinstance(act, dict) or any(k not in act for k in need) or act.get("act_version") != "1" \
            or not isinstance(act.get("authority"), dict):
        return {"decision": "MALFORMED", "reason_code": "bad_envelope"}
    try:
        jcs(act)        # an Act RFC 8785 cannot canonicalize (e.g. NaN, Infinity) has no binding digest
    except (ValueError, TypeError):
        return {"decision": "MALFORMED", "reason_code": "not_canonicalizable"}
    action, auth = act["action"], act["authority"]
    if not isinstance(action, dict) or not isinstance(action.get("type"), str) or not isinstance(action.get("params", {}), dict):
        return {"decision": "MALFORMED", "reason_code": "bad_action"}
    art, pool = auth.get("artifact"), auth.get("key_certs", [])
    bad = chain.check_pool(pool) or chain.check_seal_shape(art)
    if bad: return {"decision": "MALFORMED", "reason_code": bad}
    seal = art["seal"]
    try:
        t0, t1 = ts(act["issued_at"]), ts(act["expires_at"])
    except (ValueError, TypeError):
        return {"decision": "MALFORMED", "reason_code": "bad_time"}
    if (t1 - t0).total_seconds() > max_window_seconds or t1 <= t0:
        return {"decision": "MALFORMED", "reason_code": "validity_window"}
    # 2-4. addressed to us, in time, not replayed
    if act["relying_party"] != relying_party_id: return {"decision": "WRONG_RELYING_PARTY"}
    if now < t0: return {"decision": "NOT_YET_VALID"}
    if now > t1: return {"decision": "EXPIRED"}
    if act["nonce"] in seen_nonces: return {"decision": "REPLAYED"}
    # 5. authority: SPEC-007 §4 for the artifact itself
    #    Scope-aware (rev. 1.9 §4.2a): a path whose scope does not admit this artifact is a failed
    #    candidate. The resolved key is the same on every path, so the seal is checked once, after.
    meta = art.get("meta", {})
    r = chain.resolve(seal["kid"], pool, root_pem, now, chain.for_artifact(meta, seal["signature_algorithm"]), revoked_kids, revoked_certs)
    if r["decision"] != "RESOLVED": return r
    failure = chain.seal_failure(art, r["key"])
    if failure: return failure
    # 5a. the authority in force at `now` (§5.4): genuine is not enough, it must also be current.
    #     A superseded version stays valid for verifying past decisions; it cannot authorize new ones.
    art_id = meta.get("artifact_id")
    if seal["hash"] in revoked_artifacts:
        return {"decision": "ARTIFACT_REVOKED", "artifact_id": art_id}
    if art_id in in_force:
        if in_force[art_id] != seal["hash"]:
            return {"decision": "SUPERSEDED", "artifact_id": art_id, "in_force_seal_hash": in_force[art_id]}
        in_force_source = "record"
    elif currency_policy == "record":
        # §5.5: only the relying party's own record establishes currency; no statement is read,
        # so a compromised issuer key cannot make a version current (R-19 Theorem 9.4).
        return {"decision": "VERSION_UNVERIFIED", "artifact_id": art_id, "reason_code": "not_in_record"}
    else:
        st = auth.get("in_force")
        def unverified(reason): return {"decision": "VERSION_UNVERIFIED", "artifact_id": art_id, "reason_code": reason}
        if st is None: return unverified("no_in_force_evidence")
        if not isinstance(st, dict) or not all(isinstance(st.get(k), str) for k in ("artifact_id", "version", "seal_hash", "as_of", "valid_until", "kid", "signature")) \
                or st.get("algorithm") not in TESTIMONY_SUITES:
            return unverified("bad_statement")
        if st["artifact_id"] != art_id or st["seal_hash"] != seal["hash"] or st["version"] != meta.get("version"):
            return unverified("statement_mismatch")
        if st["kid"] != seal["kid"] or not chain.suite_permitted(r["effective"], st["algorithm"]) \
                or not statement_sig(r["key"], st, in_force_payload(st))[0]:
            return unverified("bad_signature")
        try:
            sa, su = ts(st["as_of"]), ts(st["valid_until"])
        except (ValueError, TypeError):
            return unverified("bad_statement")
        if (su - sa).total_seconds() > MAX_IN_FORCE_SECONDS or su <= sa: return unverified("statement_window")
        if now < sa or now > su: return unverified("stale")
        in_force_source = "statement"
    # 5b. an authority whose verdict would depend on listing order cannot authorize (SPEC-001 2.3.0)
    if ambiguous_escalation(art): return {"decision": "MALFORMED", "reason_code": "ambiguous_escalation"}
    # 6. testimony
    facts: Dict[str, Any] = {}; channel: Dict[str, str] = {}
    def put(name, value, src):
        if name in channel: raise KeyError(name)
        facts[name] = value; channel[name] = src
    subject = action.get("subject")
    for t in act.get("testimony") or []:
        if not isinstance(t, dict) or not all(k in t for k in ("claim", "value", "as_of", "valid_until", "kid", "signature")) \
                or t.get("algorithm") not in TESTIMONY_SUITES:
            return {"decision": "MALFORMED", "reason_code": "bad_testimony"}
        w = resolve_statement_key("claim", t["claim"], t, pool, root_pem, now, meta, revoked_kids, revoked_certs)
        if w["decision"] != "RESOLVED":
            return statement_failure(w, "TESTIMONY_INVALID", "TESTIMONY_OUT_OF_SCOPE", claim=t["claim"])
        ok, why = statement_sig(w["key"], t, testimony_payload(t))
        if not ok: return {"decision": "TESTIMONY_INVALID", "claim": t["claim"], "reason_code": why}
        try:
            fresh = ts(t["as_of"]) <= now <= ts(t["valid_until"])
        except (ValueError, TypeError, AttributeError):
            fresh = False                               # an unreadable window is not a current one
        if not fresh: return {"decision": "TESTIMONY_INVALID", "claim": t["claim"], "reason_code": "stale"}
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
    try:
        ev = evaluate(art, facts)
    except (ValueError, KeyError, TypeError, IndexError):
        return {"decision": "MALFORMED", "reason_code": "unevaluable_rules", "commit": False}   # never commit what cannot be evaluated
    digest = binding_digest(act)
    base = {"rule": ev["rule"], "act_digest": digest, "in_force_source": in_force_source, "currency_policy": currency_policy}
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
    approvers: Set[str] = set()
    for c in act.get("consents") or []:
        if not isinstance(c, dict) or not all(isinstance(c.get(k), str) for k in ("binding_digest", "role", "decision", "signed_at", "kid", "signature")) \
                or c.get("algorithm") not in CONSENT_SUITES \
                or (c["algorithm"] == "WebAuthn-ES256" and not all(isinstance(c.get(k), str) for k in WEBAUTHN_FIELDS)):
            return {"decision": "MALFORMED", "reason_code": "bad_consent"}
        k = resolve_statement_key("consent", c["role"], c, pool, root_pem, now, meta, revoked_kids, revoked_certs)
        if k["decision"] != "RESOLVED":
            r = statement_failure(k, "CONSENT_INVALID", "CONSENT_OUT_OF_SCOPE", role=c["role"])
            if r["decision"] == "CONSENT_INVALID": r.pop("role")
            return r
        # §4.4: the person a consent counts for must not depend on which certificates were sent
        if len({e["approver"] for e in k["admitted"]}) > 1: return {"decision": "CONSENT_INVALID", "reason_code": "approver_ambiguous"}
        ok, why = statement_sig(k["key"], c, consent_payload(c))
        if not ok: return {"decision": "CONSENT_INVALID", "reason_code": why}
        if c["binding_digest"] != digest: return {"decision": "CONSENT_INVALID", "reason_code": "binding_mismatch"}
        if c["decision"] == "approve" and c["role"] == role: approvers.add(k["effective"]["approver"])
    # §4.4: n consents means n distinct people, never n keys
    if len(approvers) >= need_n:
        return {"decision": "AUTHORIZED", "commit": True, "by_consent": True, "escalation_id": ev["escalation_id"], "consents_valid": len(approvers), "consents_required": need_n, **base}
    return {"decision": "ESCALATED", "commit": False, "escalation_id": ev["escalation_id"], "consents_valid": len(approvers), "consents_required": need_n, **base}
