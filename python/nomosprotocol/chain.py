"""NOMOS-SPEC-007 revision 1.9 (resolution) and 1.10 (revocation sources).

One resolver for every signed object a relying party accepts: an artifact's seal (§4), and the
testimony, consent and in-force statements of NOMOS-SPEC-008 (§4.6). Pure: no network, no clock
other than the `now` it is given, no state other than the revocation sets it is given.

    resolve(target_kid, pool, root_pem, now, admit, revoked_kids, revoked_certs) -> verdict

`admit` is the purpose of the resolution (§4.2a step 4): `for_artifact(...)` or
`for_statement(...)`. A candidate path whose effective scope the purpose does not admit is a
failed candidate, exactly like one with a bad signature, and the next candidate is tried.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

from . import suites
from .jcs import jcs, sha256_hex

MAX_CHAIN = 20                                   # §4.5
CERT_SUITES = ("Ed25519", "ES256")               # §3.1: a certificate or staple is never WebAuthn-signed
SEAL_SUITES = ("Ed25519", "ES256")               # NOMOS-SPEC-010 §6
ARTIFACT_DIMS = ("artifact", "industry", "jurisdiction")
STATEMENT_DIMS = ("claim", "consent")
SET_DIMS = ("claim", "consent", "suite")
KNOWN_DIMS = ARTIFACT_DIMS + STATEMENT_DIMS + ("suite", "approver")
CERT_FIELDS = ("parent_kid", "child_kid", "child_public_key_pem", "issued_at", "expires_at", "algorithm", "signature")
STAPLE_FIELDS = ("child_kid", "parent_kid", "as_of", "valid_until", "algorithm", "signature")
ISO_3166 = re.compile(r"^[A-Z]{2}(-[A-Z0-9]{1,3})?$")

Verdict = Dict[str, Any]
Effective = Dict[str, str]
Admit = Callable[[Effective], Optional[str]]


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


# ── certificates (§3) ────────────────────────────────────────────────────────────────────────
def cert_payload(c: dict) -> dict:
    """§3.2: the signed payload. `algorithm` and `signature` are not signed; `scope` is null when absent."""
    return {k: c.get(k) for k in ("parent_kid", "child_kid", "child_public_key_pem", "issued_at", "expires_at")} | {"scope": c.get("scope")}


def fingerprint(c: dict) -> str:
    """§5.4: SHA-256 over the canonical signed payload, hex. Never over the signature."""
    return sha256_hex(jcs(cert_payload(c)))


def staple_payload(s: dict) -> dict:
    return {k: s.get(k) for k in ("child_kid", "parent_kid", "as_of", "valid_until")}


def check_pool(pool: Any) -> Optional[str]:
    """§4.4-4.5 shape gates, applied before any cryptographic work. Returns a reason or None."""
    if not isinstance(pool, list): return "bad_chain"
    if len(pool) > MAX_CHAIN: return "chain_over_length_cap"
    for c in pool:
        if not isinstance(c, dict) or not all(isinstance(c.get(k), str) and c.get(k) for k in CERT_FIELDS):
            return "bad_certificate"
        if c["algorithm"] not in CERT_SUITES: return "bad_certificate"
        if c.get("scope") is not None and not isinstance(c.get("scope"), str): return "bad_certificate"
    return None


def check_staples(staples: Any) -> Optional[str]:
    if staples is None: return None
    if not isinstance(staples, list) or len(staples) > MAX_CHAIN: return "bad_staples"
    for s in staples:
        if not isinstance(s, dict) or not all(isinstance(s.get(k), str) and s.get(k) for k in STAPLE_FIELDS):
            return "bad_staple"
        if s["algorithm"] not in CERT_SUITES: return "bad_staple"
    return None


# ── scope (§3.4, §3.4.1, §3.6, §3.7) ─────────────────────────────────────────────────────────
class ScopeError(Exception):
    pass


def _set(v: str) -> Set[str]: return set(v.split(","))


def parse_scope(s: Optional[str]) -> List[Tuple[str, str]]:
    """A scope string, parsed whole or rejected whole. Never partially applied."""
    if s is None or not s.strip(): return []
    out, seen = [], set()
    for term in s.split():
        d, sep, v = term.partition(":")
        if not sep or not d or not v or d in seen: raise ScopeError(term)
        seen.add(d)
        if d in SET_DIMS:
            members = v.split(",")
            if "" in members or len(set(members)) != len(members): raise ScopeError(term)
            if d == "suite":
                if any(m not in suites.SUITES for m in members): raise ScopeError(term)
                # §3.6: a key permitted WebAuthn-ES256 is permitted nothing else, so an enrolled
                # passkey can only ever approve.
                if "WebAuthn-ES256" in members and len(members) > 1: raise ScopeError(term)
        if d == "approver" and "," in v: raise ScopeError(term)
        out.append((d, v))
    return out


def contains(dim: str, outer: str, inner: str) -> bool:
    """Does the grant `outer` cover `inner` on this dimension? Used for both narrowing and matching."""
    if dim == "artifact": return outer == inner
    if dim == "industry": return inner == outer or inner.startswith(outer + "/")
    if dim == "jurisdiction": return inner == outer or (len(outer) == 2 and inner.startswith(outer + "-"))
    if dim in SET_DIMS: return _set(inner) <= _set(outer)
    if dim == "approver": return outer == inner
    return False                                 # unknown dimension: never narrows, never matches


def meta_matches(dim: str, val: str, meta: dict) -> bool:
    if dim == "artifact": return meta.get("artifact_id") == val
    if dim == "industry":
        ind = meta.get("industry")
        return isinstance(ind, str) and bool(ind) and contains("industry", val, ind)
    if dim == "jurisdiction":
        cs = meta.get("jurisdiction_codes")
        if not isinstance(cs, list) or not cs or not all(isinstance(c, str) and ISO_3166.match(c) for c in cs): return False
        return all(contains("jurisdiction", val, c) for c in cs)
    return False


def suite_permitted(effective: Effective, suite: str) -> bool:
    """§3.6: without a `suite` term a key may use any suite but WebAuthn-ES256."""
    if "suite" in effective: return suite in _set(effective["suite"])
    return suite != "WebAuthn-ES256"


def format_scope(effective: Effective) -> str:
    return " ".join(f"{d}:{v}" for d, v in effective.items())


# ── purposes (§4.2a step 4) ──────────────────────────────────────────────────────────────────
# Each term of the effective scope is examined in effective-scope order and the first that does
# not admit the purpose is the reported dimension (§3.8). A statement checks its own kind first.
def _term_fails(d: str, v: str, meta: dict, suite: str, allowed: Tuple[str, ...]) -> bool:
    if d in ARTIFACT_DIMS: return not meta_matches(d, v, meta)
    if d == "suite": return suite not in _set(v)
    return d not in allowed                      # statement dimensions off-purpose, or unknown: fail closed


def _default_suite_fails(effective: Effective, suite: str) -> bool:
    return "suite" not in effective and not suite_permitted(effective, suite)


def for_artifact(meta: dict, suite: str) -> Admit:
    """§3.4, §3.5, §3.6: may this key seal this artifact, under this suite?"""
    def admit(effective: Effective) -> Optional[str]:
        for d, v in effective.items():
            if _term_fails(d, v, meta, suite, ()): return d
        return "suite" if _default_suite_fails(effective, suite) else None
    return admit


def for_statement(kind: str, name: str, meta: dict, suite: str, required: Tuple[str, ...] = ()) -> Admit:
    """§3.4.1, §3.6, §3.7: may this key sign a `kind` statement about `name`, under this suite,
    for an act whose authority artifact carries `meta`? `required` names dimensions the calling
    specification requires on the key (NOMOS-SPEC-008 0.6.0 requires `approver` on consent keys);
    a path whose scope lacks one is refused on that dimension, like any other refusal."""
    allowed = (kind, "approver") if kind == "consent" else (kind,)
    def admit(effective: Effective) -> Optional[str]:
        if kind not in effective or name not in _set(effective[kind]): return kind
        for d in required:
            if d not in effective: return d
        for d, v in effective.items():
            if _term_fails(d, v, meta, suite, allowed): return d
        return "suite" if _default_suite_fails(effective, suite) else None
    return admit


# ── resolution (§4.2a) ───────────────────────────────────────────────────────────────────────
def _candidates(target: str, root: str, pool: list, on_path: frozenset, depth: int = 0) -> Iterator[list]:
    """Root-to-target certificate lists, enumerated from the target, in fingerprint order."""
    if target == root:
        yield []
        return
    if depth >= MAX_CHAIN or target in on_path: return
    for c in sorted((c for c in pool if c.get("child_kid") == target), key=fingerprint):
        for head in _candidates(c.get("parent_kid"), root, pool, on_path | {target}, depth + 1):
            yield head + [c]


def _fail(decision: str, **kw) -> Verdict:
    return {"decision": decision, **kw}


def _sig_ok(cert: dict, parent_pem: str, memo: Optional[dict]) -> Tuple[bool, Optional[str]]:
    """A certificate's signature under its parent, verified once per resolution (§4.5 bounds the
    candidates; this bounds the cost of each)."""
    k = (fingerprint(cert), cert["signature"], cert["algorithm"], parent_pem)
    if memo is not None and k in memo: return memo[k]
    r = suites.verify(cert["algorithm"], parent_pem, jcs(cert_payload(cert)), {"signature": cert["signature"]})
    if memo is not None: memo[k] = r
    return r


def _validate(path: list, root_pem: str, now: datetime, admit: Admit,
              revoked_kids: Set[str], revoked_certs: Set[str], memo: Optional[dict] = None) -> Verdict:
    cur_pem, effective = root_pem, {}
    hops = []
    for cert in path:
        ktype, _, reason = suites.load_key(cert["child_public_key_pem"])
        if reason: return _fail("ISSUER_NOT_RECOGNIZED", reason_code="invalid_key")
        if suites.compute_kid(cert["child_public_key_pem"]) != cert["child_kid"]:
            return _fail("ISSUER_NOT_RECOGNIZED", reason_code="kid_mismatch")
        if not suite_permitted(effective, cert["algorithm"]):
            return _fail("OUT_OF_SCOPE", dimension="suite", reason_code="suite_not_permitted")
        ok, why = _sig_ok(cert, cur_pem, memo)
        if not ok: return _fail("ISSUER_NOT_RECOGNIZED", reason_code=why)
        try:
            issued, expires = ts(cert["issued_at"]), ts(cert["expires_at"])
        except (ValueError, TypeError):
            return _fail("ISSUER_NOT_RECOGNIZED", reason_code="bad_time")
        if now > expires: return _fail("ISSUER_NOT_RECOGNIZED", reason_code="expired")
        if now < issued: return _fail("ISSUER_NOT_RECOGNIZED", reason_code="not_yet_valid")
        fp = fingerprint(cert)
        if fp in revoked_certs: return _fail("CERTIFICATE_REVOKED", revoked_fingerprint=fp)
        if cert["child_kid"] in revoked_kids: return _fail("KEY_REVOKED", revoked_kid=cert["child_kid"])
        try:
            terms = parse_scope(cert.get("scope"))
        except ScopeError:
            return _fail("OUT_OF_SCOPE", reason_code="malformed_scope")
        narrowed = dict(effective)
        for d, v in terms:
            if d in effective and not contains(d, effective[d], v):
                return _fail("OUT_OF_SCOPE", dimension=d, reason_code="widening")
            narrowed[d] = v
        hops.append({"cert": cert, "parent_pem": cur_pem, "parent_effective": effective})
        cur_pem, effective = cert["child_public_key_pem"], narrowed
    dim = admit(effective)
    if dim is not None: return _fail("OUT_OF_SCOPE", dimension=dim)
    return {"decision": "RESOLVED", "key": cur_pem, "effective": effective, "hops": hops}


def resolve(target_kid: str, pool: list, root_pem: str, now: datetime, admit: Admit,
            revoked_kids: Optional[Set[str]] = None, revoked_certs: Optional[Set[str]] = None,
            all_paths: bool = False) -> Verdict:
    """§4.2a. `pool` must already have passed check_pool. On success the verdict carries the
    resolved key, its effective scope, the kids on the path (root first) and the hops. With
    `all_paths`, every candidate is tried and `admitted` lists the effective scope of each one
    that validates (NOMOS-SPEC-008 0.6.0 §4.4 reads it to make the approver path-independent);
    the first, in fingerprint order, is still the one reported."""
    revoked_kids = revoked_kids or set()
    revoked_certs = revoked_certs or set()
    _, _, reason = suites.load_key(root_pem)
    if reason: return _fail("MALFORMED", reason_code="bad_root")
    root_kid = suites.compute_kid(root_pem)
    if root_kid in revoked_kids: return _fail("KEY_REVOKED", revoked_kid=root_kid)
    first_failure, first_resolved, admitted = None, None, []
    memo: dict = {}
    for path in _candidates(target_kid, root_kid, pool, frozenset()):
        r = _validate(path, root_pem, now, admit, revoked_kids, revoked_certs, memo)
        if r["decision"] == "RESOLVED":
            r["path"] = [root_kid] + [c["child_kid"] for c in path]
            if not all_paths: return r
            first_resolved = first_resolved or r
            admitted.append(r["effective"])
            continue
        first_failure = first_failure or r
    if first_resolved:
        first_resolved["admitted"] = admitted     # the effective scope of every admitted path
        return first_resolved
    if first_failure: return first_failure
    from_root = any(c.get("parent_kid") == root_kid for c in pool)
    return _fail("ISSUER_NOT_RECOGNIZED", reason_code="chain_broken" if from_root else "no_certificate_for_root")


# ── the artifact's own seal (NOMOS-SPEC-001 §8, NOMOS-SPEC-010 §6) ──────────────────────────
def check_seal_shape(artifact: Any) -> Optional[str]:
    if not isinstance(artifact, dict): return "bad_artifact"
    seal = artifact.get("seal")
    if not isinstance(seal, dict) or seal.get("status") != "sealed" or not all(isinstance(seal.get(k), str) for k in ("hash", "signature", "kid")):
        return "unsealed_artifact"
    if seal.get("signature_algorithm") not in SEAL_SUITES: return "seal_algorithm"
    return None


def seal_failure(artifact: dict, key_pem: str) -> Optional[Verdict]:
    """None if the seal verifies under the resolved key; otherwise the SEAL_INVALID verdict."""
    seal = artifact["seal"]
    body = {k: v for k, v in artifact.items() if k not in ("seal", "attestations")}
    if sha256_hex(jcs(body)) != seal["hash"]: return _fail("SEAL_INVALID", reason_code="hash_mismatch")
    ok, why = suites.verify(seal["signature_algorithm"], key_pem,
                            jcs({"hash": seal["hash"], "signed_by": seal.get("signed_by")}), {"signature": seal["signature"]})
    return None if ok else _fail("SEAL_INVALID", reason_code=why)


# ── freshness staples (§5.5) ─────────────────────────────────────────────────────────────────
def staple_confidence(resolved: Verdict, staples: Optional[list], now: datetime) -> str:
    """§5.5 for a verifier with no revocation source of its own: the weakest link along the
    resolved path. The root is never staple-coverable and is not counted (§5.5, FINDINGS)."""
    levels = []
    for hop in resolved["hops"]:
        cert = hop["cert"]
        covered = False
        for s in staples or []:
            if s["child_kid"] != cert["child_kid"] or s["parent_kid"] != cert["parent_kid"]: continue
            if not suite_permitted(hop["parent_effective"], s["algorithm"]): continue
            try:
                if not ts(s["as_of"]) <= now <= ts(s["valid_until"]): continue
            except (ValueError, TypeError):
                continue
            if suites.verify(s["algorithm"], hop["parent_pem"], jcs(staple_payload(s)), {"signature": s["signature"]})[0]:
                covered = True
                break
        levels.append("staple" if covered else "unchecked")
    return "unchecked" if not levels or "unchecked" in levels else "staple"


# ── revocation sources (rev. 1.10 §5.1, §5.1a, §5.3, §5.3a) ──────────────────────────────────
REVOCATION_SUITES = ("Ed25519", "ES256")
MAX_LIST_CERTS = 1000
_FP = re.compile(r"^[0-9a-f]{64}$")


def revocation_payload(st: dict) -> dict:
    """§5.1: the field name says what is revoked, so one kind can never be read as the other."""
    if "revoked_fingerprint" in st:
        return {"revoked_fingerprint": st["revoked_fingerprint"], "reason": st["reason"], "issued_at": st["issued_at"]}
    return {"revoked_kid": st["revoked_kid"], "reason": st["reason"], "issued_at": st["issued_at"]}


def revocation_list_payload(lst: dict) -> dict:
    return {"generated_at": lst["generated_at"], "statements": lst["statements"]}


def for_signing(suite: str) -> Admit:
    """The purpose of a key that signs a revocation statement or a list: any effective scope that
    permits the suite (§3.6). Authority to revoke is authority to certify."""
    def admit(effective: Effective) -> Optional[str]:
        return None if suite_permitted(effective, suite) else "suite"
    return admit


def _unique(certs: list) -> list:
    seen, out = set(), []
    for c in certs:
        fp = fingerprint(c)
        if fp not in seen: seen.add(fp); out.append(c)
    return out


def _signer_pem(kid: str, pool: list, root_pem: str, at: datetime, suite: str,
                revoked_kids: Set[str], revoked_certs: Set[str]) -> Optional[str]:
    """The signer's key if it is the root or resolves to it (§4.2a) at `at`, else None."""
    r = resolve(kid, pool, root_pem, at, for_signing(suite), revoked_kids, revoked_certs)
    return r["key"] if r["decision"] == "RESOLVED" else None


def evaluate_statement(st: Any, pool: list, root_pem: str, now: datetime) -> Optional[str]:
    """§5.1a. None if the statement counts, else the first rule it fails."""
    if not isinstance(st, dict): return "bad_statement"
    has_kid, has_fp = "revoked_kid" in st, "revoked_fingerprint" in st
    if has_kid == has_fp: return "bad_statement"
    target = st.get("revoked_kid") if has_kid else st.get("revoked_fingerprint")
    if not isinstance(target, str) or not target: return "bad_statement"
    if has_fp and not _FP.match(target): return "bad_statement"
    if not isinstance(st.get("reason"), str): return "bad_statement"
    if not all(isinstance(st.get(f), str) and st.get(f) for f in ("issued_at", "kid", "algorithm", "signature")): return "bad_statement"
    if st["algorithm"] not in REVOCATION_SUITES: return "bad_statement"
    try:
        issued = ts(st["issued_at"])
    except (ValueError, TypeError):
        return "bad_statement"
    if issued > now: return "bad_statement"
    # rule 2: the revoked object, certified by this parent
    certs = [c for c in pool if c.get("parent_kid") == st["kid"] and
             (c.get("child_kid") == target if has_kid else fingerprint(c) == target)]
    if not certs: return "no_certificate"
    # rule 3: the parent is recognized from the root, at issued_at, revocation not consulted
    parent = _signer_pem(st["kid"], pool, root_pem, issued, st["algorithm"], set(), set())
    if parent is None: return "signer_not_recognized"
    # rule 4: the parent made the certificate
    if not any(suites.verify(c["algorithm"], parent, jcs(cert_payload(c)), {"signature": c["signature"]})[0] for c in certs):
        return "bad_certificate_signature"
    # rule 5: the parent signed the statement
    ok, _ = suites.verify(st["algorithm"], parent, jcs(revocation_payload(st)), {"signature": st["signature"]})
    return None if ok else "bad_signature"


def verify_revocation_list(lst: Any, root_pem: str, now: datetime, own_certs: Optional[list] = None) -> dict:
    """§5.3a. Returns {decision, revoked_kids, revoked_certs, as_of?, ignored} with sorted lists."""
    if (not isinstance(lst, dict) or not all(isinstance(lst.get(f), str) for f in ("generated_at", "kid", "algorithm", "signature"))
            or not isinstance(lst.get("statements"), list)):
        return {"decision": "MALFORMED", "reason_code": "bad_list"}
    extra = lst.get("key_certs", [])
    if not isinstance(extra, list) or len(extra) > MAX_LIST_CERTS: return {"decision": "MALFORMED", "reason_code": "bad_list_certs"}
    if extra and check_pool_unbounded(extra) is not None: return {"decision": "MALFORMED", "reason_code": "bad_list_certs"}
    pool = _unique(list(extra) + list(own_certs or []))
    kids, fps, ignored = set(), set(), []
    for i, st in enumerate(lst["statements"]):
        why = evaluate_statement(st, pool, root_pem, now)
        if why: ignored.append({"index": i, "reason": why}); continue
        (kids if "revoked_kid" in st else fps).add(st.get("revoked_kid") or st.get("revoked_fingerprint"))
    out = {"decision": "OK", "revoked_kids": sorted(kids), "revoked_certs": sorted(fps), "ignored": ignored}
    try:
        generated = ts(lst["generated_at"])
    except (ValueError, TypeError):
        return out
    if generated > now or lst["algorithm"] not in REVOCATION_SUITES: return out
    signer = _signer_pem(lst["kid"], pool, root_pem, generated, lst["algorithm"], kids, fps)
    if signer and suites.verify(lst["algorithm"], signer, jcs(revocation_list_payload(lst)), {"signature": lst["signature"]})[0]:
        out["as_of"] = lst["generated_at"]
    return out


def check_pool_unbounded(pool: list) -> Optional[str]:
    """check_pool's shape rules without the 20-certificate presentation bound (a list's own bound
    is MAX_LIST_CERTS)."""
    for c in pool:
        if not isinstance(c, dict) or not all(isinstance(c.get(f), str) and c.get(f) for f in CERT_FIELDS) or c.get("algorithm") not in CERT_SUITES:
            return "bad_certificate"
        if c.get("scope") is not None and not isinstance(c.get("scope"), str): return "bad_certificate"
    return None
