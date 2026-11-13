"""NOMOS-SPEC-014 0.4.0 registrar logs: the reference reading of a registrar's log, written apart
from the TypeScript verifier so the published vectors are checked by two implementations.

    verify_registrar_log(...)   is this copy of a log genuine, current, append-only, and signed by the
                                key in force (after rotations the key in force signed)?
    fold_registrar_log(...)     the record the resolver reads: claims, closures, recognitions (with
                                their windows and any delegation), supersessions, revocations
    parse_dns_record(...)       §2.5: a `_nomos-registrar` TXT record, or None
    discover(...)               §2.5: where the log is, given the kid the relying party already holds
    load_registrar_world(...)   §2.3: pins first, then delegates named by recognitions in force,
                                each verified under the key the relying party or its recognizer chose

Pure: no network (logs are passed in), no clock but the one passed.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import suites as S
from .jcs import jcs, sha256_hex

GENESIS = "0" * 64
PLATFORM_LOG = "nomos-exchange-log"


def registrar_log_name(registrar_id: str) -> str:
    return f"nomos-registrar:{registrar_id}"


def _ts(s: Any) -> Optional[float]:
    if not isinstance(s, str):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def suite_for_key(pem: Any) -> Optional[str]:
    ktype, _, reason = S.load_key(pem)
    if reason:
        return None
    return "Ed25519" if ktype == "Ed25519" else "ES256"


def head_payload(head: Dict[str, Any], log: str) -> bytes:
    return jcs({"log": log, "size": head["size"], "hash": head["hash"], "at": head["at"]})


def rotation_payload(log: str, seq: int, prev_hash: str, kid: str, public_key_pem: str) -> bytes:
    return jcs({"log": log, "seq": seq, "prev_hash": prev_hash, "kid": kid, "public_key_pem": public_key_pem})


def entry_hash(e: Dict[str, Any]) -> str:
    body = {k: e[k] for k in ("seq", "kind", "name", "version", "seal_hash", "entry", "at", "prev_hash")}
    return sha256_hex(jcs(body))


def verify_chain(entries: List[Dict[str, Any]]) -> Tuple[bool, Dict[int, str], str]:
    prev, hash_at = GENESIS, {0: GENESIS}
    for i, e in enumerate(entries):
        if e.get("seq") != i + 1:
            return False, hash_at, f"entry {i + 1}: its seq is {e.get('seq')}"
        if e.get("prev_hash") != prev:
            return False, hash_at, f"entry {e['seq']}: prev_hash does not match"
        if entry_hash(e) != e.get("hash"):
            return False, hash_at, f"entry {e['seq']}: its hash does not match its contents"
        prev = e["hash"]
        hash_at[e["seq"]] = prev
    return True, hash_at, ""


def verify_registrar_log(entries: List[Dict[str, Any]], head: Dict[str, Any], public_key_pem: str, now: str,
                         max_head_age_seconds: int, previous: Optional[Dict[str, Any]] = None,
                         log: str = PLATFORM_LOG) -> Dict[str, Any]:
    def fail(reason: str, detail: str) -> Dict[str, Any]:
        return {"ok": False, "reason": reason, "detail": detail}

    ok, hash_at, detail = verify_chain(entries)
    if not ok:
        return fail("chain_broken", detail)
    size = head.get("size") if isinstance(head, dict) else None
    if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size > len(entries) or hash_at.get(size) != head.get("hash"):
        return fail("head_mismatch", "the head does not name an entry of this chain")
    if not head.get("signature") or not head.get("kid"):
        return fail("head_unsigned", "the head is not signed")
    if "log" in head and head["log"] != log:
        return fail("wrong_log", f"the head is for log {head['log']!r}, not {log!r}")

    pinned_suite = suite_for_key(public_key_pem)
    if pinned_suite is None:
        return fail("wrong_key", "the pinned key is not an Ed25519 or P-256 key in canonical form")
    pinned_kid = S.compute_kid(public_key_pem)
    vouched = entries[:size]
    start = 0
    for i, e in enumerate(vouched):
        if e.get("kind") == "key" and e.get("name") == pinned_kid:
            start = i + 1
            break
    pem = public_key_pem
    for e in vouched[start:]:
        if e.get("kind") != "key":
            continue
        new = (e.get("entry") or {}).get("public_key_pem")
        if not isinstance(new, str) or suite_for_key(new) is None or S.compute_kid(new) != e.get("name"):
            return fail("rotation_invalid", f"entry {e['seq']}: the new key is not canonical or its kid differs")
        good, _ = S.verify(suite_for_key(pem), pem, rotation_payload(log, e["seq"], e["prev_hash"], e["name"], new),
                           {"signature": (e.get("entry") or {}).get("signature")})
        if not good:
            return fail("rotation_invalid", f"entry {e['seq']}: the rotation is not signed by the key in force")
        pem = new

    kid = S.compute_kid(pem)
    if head.get("kid") != kid:
        return fail("wrong_key", f"the head is signed by {head.get('kid')}, not the key in force {kid}")
    suite = suite_for_key(pem)
    if "algorithm" in head and head["algorithm"] != suite:
        return fail("algorithm_mismatch", f"the head names {head['algorithm']!r}; the key in force verifies {suite} only")
    good, _ = S.verify(suite, pem, head_payload(head, log), {"signature": head.get("signature")})
    if not good:
        return fail("bad_signature", "the head signature does not verify under the key in force")
    t_head, t_now = _ts(head.get("at")), _ts(now)
    if t_head is None:
        return fail("head_stale", "the head carries no time")
    age = t_now - t_head
    if age < -60:
        return fail("head_in_future", "the head is dated after now")
    if age > max_head_age_seconds:
        return fail("head_stale", f"the head is {round(age)} s old; the bound is {max_head_age_seconds} s")
    if previous and hash_at.get(previous.get("size")) != previous.get("hash"):
        return fail("history_rewritten", "the head kept earlier is not part of this log")
    return {"ok": True, "size": len(entries), "head": {"size": size, "hash": head["hash"], "at": head["at"], "kid": kid}, "public_key_pem": pem}


def fold_registrar_log(entries: List[Dict[str, Any]], registrar_id: str, certified_scope: str = "always",
                       delegated: bool = False) -> Dict[str, Any]:
    open_claims: Dict[str, Dict[str, Any]] = {}
    closed_claims: List[Dict[str, Any]] = []
    closures: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    open_edges: Dict[str, Dict[str, Any]] = {}
    supersessions: List[Dict[str, Any]] = []
    revoked = set()
    head = None
    for e in entries:
        head = e["hash"]
        kind, name, x, at = e.get("kind"), e.get("name"), e.get("entry") or {}, e.get("at")
        if kind == "applies":
            if name in open_claims:
                closed_claims.append({**open_claims[name], "until": at})
            c = {"authority": name, "version": e.get("version"), "scope": x["scope"] if isinstance(x.get("scope"), str) else "always",
                 "exclusive": x.get("exclusive") is True, "from": at, "until": x["until"] if isinstance(x.get("until"), str) else None}
            if isinstance(x.get("basis"), str):
                c["basis"] = x["basis"]
            open_claims[name] = c
        elif kind == "withdrawn":
            if name in open_claims:
                closed_claims.append({**open_claims.pop(name), "until": at})
            if name in open_edges:
                edges.append({**open_edges.pop(name), "until": at})
        elif kind == "revoked":
            revoked.add(name)
        elif kind == "closed":
            c = {"scope": x["scope"] if isinstance(x.get("scope"), str) else "always",
                 "authorities": [a for a in x.get("authorities", []) if isinstance(a, str)] if isinstance(x.get("authorities"), list) else [],
                 "at": at, "label": name}
            if isinstance(x.get("max_age_days"), (int, float)) and not isinstance(x.get("max_age_days"), bool):
                c["max_age_days"] = x["max_age_days"]
            closures.append(c)
        elif kind == "recognizes":
            if name in open_edges:
                edges.append({**open_edges[name], "until": at})
            edge = {"to": name, "scope": x["scope"] if isinstance(x.get("scope"), str) else "always", "from": at, "until": None}
            if all(isinstance(x.get(k), str) for k in ("kid", "public_key_pem", "url")):
                edge.update({"delegates": True, "kid": x["kid"], "public_key_pem": x["public_key_pem"], "url": x["url"],
                             "log": x["log"] if isinstance(x.get("log"), str) else registrar_log_name(name)})
            open_edges[name] = edge
        elif kind == "superseded":
            if isinstance(x.get("by"), str):
                supersessions.append({"superseded": name, "by": x["by"], "from": at})
    record = {"id": registrar_id, "certified_scope": certified_scope, "claims": closed_claims + list(open_claims.values()),
              "closures": closures, "recognitions": edges + list(open_edges.values()), "supersessions": supersessions,
              "revoked": sorted(revoked), "head": head}
    if delegated:
        record["delegated"] = True
    return record


def parse_dns_record(txt: Any) -> Optional[Dict[str, str]]:
    """§2.5: `v=nomos1; id=…; url=…; kid=…`, or None when it is not one."""
    if not isinstance(txt, str):
        return None
    fields: Dict[str, str] = {}
    for part in txt.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k, v = k.strip(), v.strip()
        if k and k not in fields:
            fields[k] = v
    if fields.get("v") != "nomos1" or not all(fields.get(k) for k in ("id", "url", "kid")):
        return None
    return {"id": fields["id"], "url": fields["url"], "kid": fields["kid"]}


def discover(records: List[str], registrar_id: str, kid: str) -> Dict[str, Any]:
    """§2.5: the log URL from the first record that is one; refused if it disagrees with what is held."""
    for txt in records:
        r = parse_dns_record(txt)
        if r is None:
            continue
        if r["id"] != registrar_id or r["kid"] != kid:
            return {"ok": False, "reason": "discovery_mismatch", "detail": "the record names another registrar or key"}
        if not r["url"].startswith("https://"):
            return {"ok": False, "reason": "discovery_mismatch", "detail": "the record's url is not https"}
        return {"ok": True, "url": r["url"]}
    return {"ok": False, "reason": "unreachable", "detail": "no _nomos-registrar record"}


def load_registrar_world(pins: List[Dict[str, Any]], logs: Callable[[str], Optional[Dict[str, Any]]], now: str,
                         max_head_age_seconds: int = 600, max_hops: int = 8, max_registrars: int = 32) -> Dict[str, Any]:
    """§2.3: pins = [{id, url, public_key_pem, certified_scope, log?}]; logs(url) -> {entries, head} or None."""
    registrars: Dict[str, Any] = {}
    absent: Dict[str, str] = {}
    pinned = {p["id"] for p in pins}
    frontier = [{"id": p["id"], "url": p["url"], "pem": p["public_key_pem"], "log": p.get("log") or registrar_log_name(p["id"]),
                 "scope": p["certified_scope"], "delegated": False, "hop": 0} for p in sorted(pins, key=lambda p: p["id"])]
    seen = set()
    t_now = _ts(now)
    while frontier:
        batch = [j for j in frontier if j["id"] not in seen]
        loaded_before = len(registrars)
        nxt: Dict[str, Tuple[Dict[str, Any], set]] = {}
        for i, j in enumerate(batch):
            seen.add(j["id"])
            if loaded_before + i >= max_registrars:
                absent[j["id"]] = "beyond_bounds"
                continue
            got = logs(j["url"])
            if got is None:
                absent[j["id"]] = "unreachable"
                continue
            head = got.get("head") or {}
            entries = got.get("entries") or []
            size = head.get("size")
            vouched = entries[:size] if isinstance(size, int) and size >= 0 else entries
            check = verify_registrar_log(vouched, head, j["pem"], now, max_head_age_seconds, None, j["log"])
            if not check["ok"]:
                absent[j["id"]] = check["reason"]
                continue
            rec = fold_registrar_log(vouched, j["id"], j["scope"], j["delegated"])
            rec["head_at"] = check["head"]["at"]
            registrars[j["id"]] = rec
            for e in rec["recognitions"]:
                if not e.get("delegates") or e.get("until") or e["to"] in pinned:
                    continue
                if e.get("from") and _ts(e["from"]) > t_now:
                    continue
                job = {"id": e["to"], "url": e["url"], "pem": e["public_key_pem"], "log": e["log"], "scope": "always", "delegated": True, "hop": j["hop"] + 1}
                if e["to"] in nxt:
                    nxt[e["to"]][1].add(e["kid"])
                else:
                    nxt[e["to"]] = (job, {e["kid"]})
        frontier = []
        for rid in sorted(nxt):
            job, kids = nxt[rid]
            if rid in seen or rid in absent:
                continue
            if len(kids) > 1:
                absent[rid] = "key_disagreement"
                seen.add(rid)
                continue
            if job["hop"] > max_hops:
                absent[rid] = "beyond_bounds"
                seen.add(rid)
                continue
            frontier.append(job)
    return {"world": {"pins": sorted(p["id"] for p in pins), "registrars": registrars, "max_head_age_seconds": max_head_age_seconds}, "absent": absent}
