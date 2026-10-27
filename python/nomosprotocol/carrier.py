"""act(): the carrier, an agent taking an action at a system it may never have met.

    r = act(to="https://shop.example", action={"type": "purchase", "subject": "DEPT-17", "params": {"amount": 500}})
    if r["status"] == "committed": print(r["receipt"])

It follows NOMOS-SPEC-009 end to end: discovers the relying party (§3.1) and the authority's issuer
(§3.2), fetches the sealed authority, asks the issuer's witnesses for the testimony it reads (§4),
builds the Act, presents exactly the certificates it relies on (0.2.0 §6.5), submits it (§6), and
if a person must approve, asks the approver for consent over this exact Act (§5) and resubmits it
(§6.3). It holds no key: nothing it does can make an Act succeed that the relying party would refuse.

Standard library only (urllib). The same behaviour as @nomosprotocol/sdk's act().
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from .accept import ACT_MEDIA_TYPE
from .statements import MAX_PRESENTED, build_act, presented_certificates

STATUS_OF = {"AUTHORIZED": "committed", "ESCALATED": "escalated", "INCOMPLETE": "incomplete", "DENIED": "denied", "REPLAYED": "replayed"}
WELL_KNOWN = {"relying-party": "/.well-known/nomos-relying-party", "issuer": "/.well-known/nomos-issuer", "witness": "/.well-known/nomos-witness"}


class NomosActError(Exception):
    pass


def _origin(url: str) -> str:
    u = urlparse(url); return f"{u.scheme}://{u.netloc}"


def _http(method: str, url: str, body: Any = None, content_type: str = "application/json", headers: Optional[dict] = None, timeout: float = 30):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={"accept": "application/json", **({"content-type": content_type} if data else {}), **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read() or b"{}")
        except ValueError: return e.code, {}
    except (urllib.error.URLError, OSError) as e:
        return 0, {"error": str(getattr(e, "reason", e))}


def fetch_document(kind: str, url: str) -> dict:
    status, doc = _http("GET", _origin(url) + WELL_KNOWN[kind])
    if status != 200 or doc.get("nomos_document") != kind or doc.get("version") != "1":
        raise NomosActError(f"{_origin(url)} serves no version-1 {kind} document at {WELL_KNOWN[kind]} ({status}).")
    return doc


def act(*, to: str, action: dict, authority: Optional[str] = None, presenter_facts: Optional[dict] = None,
        witness_headers: Optional[Dict[str, dict]] = None, approval_timeout_seconds: Optional[float] = None,
        on_approval: Optional[Callable[[dict], None]] = None, poll_seconds: float = 1.0) -> dict:
    # 1. The relying party (§3.1).
    rp = fetch_document("relying-party", to)
    cands = [a for a in rp["authorities"] if action["type"] in a["actions"] and (not authority or a["artifact_id"] == authority)]
    if not cands: raise NomosActError(f"{_origin(to)} accepts no authority for action type {action['type']!r}.")
    if len(cands) > 1 and not authority: raise NomosActError(f"{_origin(to)} accepts several authorities for {action['type']!r}; pass authority=.")
    accepted = cands[0]
    if not accepted.get("issuer"): raise NomosActError(f"{_origin(to)} does not say where {accepted['artifact_id']}'s issuer publishes it.")

    # 2. The authority, from its issuer (§3.2). Its seal is verified by the relying party.
    issuer = fetch_document("issuer", accepted["issuer"])
    entry = next((a for a in issuer["authorities"] if a["artifact_id"] == accepted["artifact_id"]), None)
    if not entry: raise NomosActError(f"The issuer at {accepted['issuer']} does not publish {accepted['artifact_id']}.")
    status, artifact = _http("GET", entry["artifact_url"])
    if status != 200: raise NomosActError(f"Could not fetch the authority from {entry['artifact_url']} ({status}).")
    in_force = None
    if accepted.get("currency_policy") == "record_or_statement" and not accepted.get("in_force_seal_hash") and entry.get("in_force_url"):
        s, st = _http("GET", entry["in_force_url"]); in_force = st if s == 200 else None

    # 3. Testimony for every witnessed input (§4), and the chains witnesses return with it.
    inputs = (artifact.get("data_contract") or {}).get("inputs") or {}
    witnessed = [n for n, i in inputs.items() if (i or {}).get("source") == "testimony"]
    escalates = bool((artifact.get("governance") or {}).get("escalations"))
    window = rp["max_window_seconds"] if escalates else min(300, rp["max_window_seconds"])
    witnesses = []
    for w in issuer.get("witnesses") or []:
        try: witnesses.append(fetch_document("witness", w))
        except NomosActError: pass        # a witness that is down leaves its facts missing; the verdict says so
    testimony: List[dict] = []
    available: List[dict] = list(issuer.get("key_certs") or [])
    unavailable: List[dict] = []
    for claim in witnessed:
        w = next((x for x in witnesses if claim in x["claims"]), None)
        if not w: unavailable.append({"fact": claim, "why": f"no witness of {issuer['issuer_id']} publishes {claim}"}); continue
        s, body = _http("POST", w["statement_endpoint"], {"claim": claim, "about": action.get("subject"), "valid_for_seconds": window},
                        headers=(witness_headers or {}).get(_origin(w["statement_endpoint"])))
        t = body.get("testimony") if s == 200 else None
        if not t: unavailable.append({"fact": claim, "why": f"{w['witness_id']} answered {s or 'nothing'}{': ' + body['error'] if body.get('error') else ''}"}); continue
        if t.get("claim") != claim or t.get("about") != action.get("subject"):
            unavailable.append({"fact": claim, "why": f"{w['witness_id']} answered for a different claim or subject"}); continue
        testimony.append(t)
        available += body.get("key_certs") or []

    # 4. Build, present the closure, submit (§6).
    the_act = build_act(relying_party=rp["relying_party_id"], action=action, artifact=artifact, key_certs=[], testimony=testimony,
                        presenter_facts=presenter_facts, in_force=in_force, window_seconds=window)
    _present(the_act, available)
    status, body = _submit(rp["act_endpoint"], the_act)

    # 5. A person must approve (§5, §6.3).
    approval_url = None
    while status == 202 and body.get("decision") == "ESCALATED":
        role = body.get("role")
        endpoint = next((a["endpoint"] for a in issuer.get("approvals") or [] if a["role"] == role), None)
        if not endpoint: return _done("escalated", body, the_act, summary=f"Needs approval from {role}, and {issuer['issuer_id']} publishes no approval endpoint for that role.")
        expires = _epoch(the_act["expires_at"])
        deadline = min(expires, time.time() + approval_timeout_seconds) if approval_timeout_seconds is not None else expires
        answer, approval_url = _request_consent(endpoint, role, the_act, deadline, poll_seconds, body.get("act_digest"), on_approval)
        if answer == "refused": return _done("denied", body, the_act, summary=f"The {role} refused this action.")
        if not answer:
            return _done("escalated", body, the_act, approval_url=approval_url, summary=(
                f"Not approved by {role} before the Act expired at {the_act['expires_at']}; build a new Act to ask again." if time.time() >= expires
                else f"Waiting for approval from {role}{' at ' + approval_url if approval_url else ''}. This Act stays valid until {the_act['expires_at']}."))
        the_act["consents"].append(answer["consent"])
        available += answer.get("key_certs") or []
        _present(the_act, available)       # the approver's chain now belongs in the presented set
        before = int(body.get("consents_valid") or 0)
        status, body = _submit(rp["act_endpoint"], the_act)
        if status == 202 and int(body.get("consents_valid") or 0) <= before:
            return _done("escalated", body, the_act, approval_url=approval_url, summary=f"Needs {body.get('consents_required')} distinct {role} approvals; {body.get('consents_valid')} given.")

    kind = STATUS_OF.get(body.get("decision"), "refused")
    if kind == "incomplete":
        missing = []
        for fact in body.get("open_facts") or []:
            why = next((u for u in unavailable if u["fact"] == fact or fact.startswith(u["fact"] + ".")), None)
            missing.append({"fact": fact, "source": (inputs.get(fact.split(".")[0]) or {}).get("source"), "why": why["why"] if why else "not supplied"})
        return _done("incomplete", body, the_act, missing=missing, summary="Not committed: " + "; ".join(f"{m['fact']} ({m['why']})" for m in missing) + ".")
    summary = {"committed": f"Committed by {rp['relying_party_id']}{', with approval' if body.get('by_consent') else ''}.",
               "denied": f"Denied by rule {body.get('rule') or '(default)'}.", "replayed": "Already committed; this is the original receipt."
               }.get(kind, f"Refused: {body.get('decision')}{' (' + body['reason_code'] + ')' if body.get('reason_code') else ''}.")
    return _done(kind, body, the_act, receipt=body.get("receipt"), result=body.get("result"), summary=summary)


def _present(the_act: dict, available: List[dict]) -> None:
    s = presented_certificates(available, the_act)
    if len(s) > MAX_PRESENTED:
        raise NomosActError(f"This Act relies on {len(s)} certificates; at most {MAX_PRESENTED} can be presented (NOMOS-SPEC-008 §6 step 1).")
    the_act["authority"]["key_certs"] = s


def _submit(endpoint: str, the_act: dict):
    status, body = _http("POST", endpoint, the_act, content_type=ACT_MEDIA_TYPE)
    if status >= 500 or status == 0: raise NomosActError(f"The relying party could not answer ({status}): {body.get('error', '')}")
    return status, body


def _epoch(s: str) -> float:
    from .chain import ts
    return ts(s).timestamp()


def _request_consent(endpoint, role, the_act, deadline, poll_seconds, act_digest, on_approval):
    s, body = _http("POST", endpoint, {"role": role, "act": {**the_act, "consents": []}})
    if s == 200 and body.get("status") == "approved": return {"consent": body["consent"], "key_certs": body.get("key_certs")}, None
    if s != 202 or not body.get("poll_url"): return None, None
    url = body.get("approval_url")
    if on_approval: on_approval({"role": role, "url": url, "act_digest": act_digest})
    while time.time() < deadline:
        time.sleep(poll_seconds)
        _, p = _http("GET", body["poll_url"])
        if p.get("status") == "approved": return {"consent": p["consent"], "key_certs": p.get("key_certs")}, url
        if p.get("status") == "refused": return "refused", url
        if p.get("status") == "expired": return None, url
    return None, url


def _done(status: str, verdict: dict, the_act: dict, **extra) -> dict:
    return {"status": status, "verdict": verdict, "act": the_act, **{k: v for k, v in extra.items() if v is not None}}
