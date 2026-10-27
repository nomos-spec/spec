"""accept(): the relying party, the system that makes the change.

    rp = accept(relying_party_id="orders.acme.example", root=ROOT_PEM, act_endpoint="https://orders.acme.example/nomos/acts",
                authorities=[{"artifact_id": "acme-purchasing", "issuer": "https://policy.acme.example",
                              "actions": ["purchase"], "currency_policy": "record", "in_force_seal_hash": SEAL_HASH}],
                local_facts=lambda act, tx=None: {"vendor_blocked": is_blocked(act["action"]["params"]["vendor"])},
                commit=lambda action, tx, act_id: create_order(tx, action),
                store=postgres_store(pool))
    app = rp.wsgi            # Flask, Django, any WSGI server
    app = rp.asgi            # FastAPI/Starlette mount, any ASGI server

For every Act it runs NOMOS-SPEC-008 §6 locally (nomosprotocol.act, the reference verifier) and on
AUTHORIZED applies §8 in one transaction: record the nonce, re-read its own facts (re-verifying if
they moved), hand `commit` exactly the verified action, store the receipt and the Act. It answers
with the NOMOS-SPEC-009 §6.2 statuses and serves its discovery document (§3.1), generated from
this same configuration.

The same behaviour as @nomosprotocol/sdk's accept(), including: a duplicate that loses the race for
the nonce reads the winner's receipt only after its own transaction has ended (so a burst of
duplicates cannot exhaust a connection pool), and revocations that cannot be read are refused
with 503, never treated as "nothing revoked" (NOMOS-SPEC-007 rev. 1.10 §5.6).
"""
from __future__ import annotations

import copy
import json
import threading
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterator, List, Optional, Protocol, Tuple

from .act import verify_act
from .chain import ts
from .statements import iso, now_utc
from . import suites

ACT_MEDIA_TYPE = "application/nomos-act+json"
STATUS = {"AUTHORIZED": 201, "ESCALATED": 202, "INCOMPLETE": 422, "DENIED": 403, "REPLAYED": 409}
WELL_KNOWN = "/.well-known/nomos-relying-party"


def status_for(decision: str) -> int:
    return STATUS.get(decision, 400)


class RevocationUnavailable(Exception):
    """Raise from `revocations()` when current revocation status cannot be established."""
    def __init__(self, message: str, retry_after_seconds: int = 60):
        super().__init__(message); self.retry_after_seconds = retry_after_seconds


class Transaction(Protocol):
    tx: Any
    def claim_nonce(self, nonce: str) -> bool: ...
    def put_receipt(self, nonce: str, receipt: dict, act: dict) -> None: ...


class Store(Protocol):
    def has_nonce(self, nonce: str) -> bool: ...
    def receipt_for(self, nonce: str) -> Optional[dict]: ...
    def transaction(self): ...   # a context manager yielding a Transaction; rolls back on exception


class MemoryStore:
    """Nonces and receipts in memory, one transaction at a time. Lost on restart, single process:
    development and tests only. Use postgres_store() in production."""
    def __init__(self):
        self._lock = threading.Lock(); self.nonces: set = set(); self.receipts: Dict[str, dict] = {}; self.acts: Dict[str, dict] = {}

    def has_nonce(self, nonce): return nonce in self.nonces
    def receipt_for(self, nonce): return self.receipts.get(nonce)

    @contextmanager
    def transaction(self):
        with self._lock:
            staged, receipts, acts = set(), {}, {}
            class T:
                tx = None
                def claim_nonce(s, n):
                    if n in self.nonces or n in staged: return False
                    staged.add(n); return True
                def put_receipt(s, n, r, a): receipts[n] = r; acts[n] = a
            yield T()
            self.nonces |= staged; self.receipts.update(receipts); self.acts.update(acts)   # only if the block completed


def postgres_store(connect: Callable[[], Any], table: str = "nomos_acts"):
    """Nonces, receipts and Acts in your own Postgres, in the same transaction as your change.
    `connect()` returns a DB-API connection (psycopg 3, psycopg2), e.g. a pool's getconn. `tx` passed
    to `commit` is that connection, so your writes and the nonce commit together. The nonce is the
    primary key: any number of concurrent duplicates commit exactly once."""
    import re
    if not re.match(r"^[a-z_][a-z0-9_]{0,62}$", table): raise ValueError(f'"{table}" is not a plain lower-case table name')
    schema = f"""CREATE TABLE IF NOT EXISTS {table} (
  nonce text PRIMARY KEY, act_id text NOT NULL, receipt json NOT NULL, act json NOT NULL, committed_at timestamptz NOT NULL DEFAULT now())"""

    class PgStore:
        def migrate(self):
            c = connect()
            try:
                with c.cursor() as cur: cur.execute(schema)
                c.commit()
            finally: c.close()
        def _one(self, sql, args):
            c = connect()
            try:
                with c.cursor() as cur: cur.execute(sql, args); row = cur.fetchone()
                c.rollback(); return row
            finally: c.close()
        def has_nonce(self, nonce): return self._one(f"SELECT 1 FROM {table} WHERE nonce = %s", (nonce,)) is not None
        def receipt_for(self, nonce):
            row = self._one(f"SELECT receipt::text FROM {table} WHERE nonce = %s", (nonce,))
            return json.loads(row[0]) if row else None
        @contextmanager
        def transaction(self):
            c = connect(); claimed = {"nonce": None, "done": False}
            try:
                class T:
                    tx = c
                    def claim_nonce(s, n):
                        with c.cursor() as cur:
                            cur.execute(f"INSERT INTO {table} (nonce, act_id, receipt, act) VALUES (%s, '', '{{}}', '{{}}') ON CONFLICT (nonce) DO NOTHING RETURNING nonce", (n,))
                            won = cur.fetchone() is not None
                        if won: claimed["nonce"] = n
                        return won
                    def put_receipt(s, n, r, a):
                        if n != claimed["nonce"]: raise RuntimeError("put_receipt for a nonce this transaction did not claim")
                        with c.cursor() as cur:
                            cur.execute(f"UPDATE {table} SET act_id = %s, receipt = %s::json, act = %s::json WHERE nonce = %s",
                                        (r["act_id"], json.dumps(r, separators=(",", ":")), json.dumps(a, separators=(",", ":")), n))
                        claimed["done"] = True
                yield T()
                if claimed["nonce"] and not claimed["done"]: raise RuntimeError("the transaction claimed a nonce but stored no receipt")
                c.commit()
            except BaseException:
                c.rollback(); raise
            finally:
                c.close()
    s = PgStore(); s.schema = schema
    return s


class _LostRace(Exception): pass
class _Rollback(Exception):
    def __init__(self, answer): super().__init__("rollback"); self.answer = answer


HINTS: Dict[str, Callable[[dict], str]] = {
    "INCOMPLETE": lambda v: f"Missing facts that could change the outcome: {', '.join(v.get('open_facts') or [])}. Bring them as testimony from a witness certified for each claim, or as the channel the authority declares.",
    "ESCALATED": lambda v: f"Needs {v.get('consents_required')} approval(s) from role {v.get('role')}. Request consent over act_digest {v.get('act_digest')} and resubmit this same Act before {v.get('retry_until')}.",
    "DENIED": lambda v: f"Rule {v.get('rule') or '(default)'} refuses this action. No approval can change a denial.",
    "WRONG_RELYING_PARTY": lambda v: "The Act is addressed to another system. Build it with this relying_party_id.",
    "EXPIRED": lambda v: "The Act's window has passed. Build a new Act.",
    "REPLAYED": lambda v: "This Act was already committed; the original receipt is attached.",
}


def _answer(verdict: dict, **extra) -> Tuple[int, Dict[str, str], dict]:
    body = {k: v for k, v in verdict.items() if k != "detail"}
    body.update(extra)
    hint = HINTS.get(verdict["decision"])
    if hint: body["hint"] = hint({**verdict, **extra})
    return status_for(verdict["decision"]), {"content-type": "application/json"}, body


class RelyingParty:
    def __init__(self, *, relying_party_id: str, root: str, authorities: List[dict], commit: Callable[..., Any], act_endpoint: str,
                 local_facts: Optional[Callable[..., dict]] = None, store: Optional[Store] = None,
                 max_window_seconds: int = 900, max_act_bytes: int = 1024 * 1024,
                 revocations: Optional[Callable[[], dict]] = None, mode: str = "enforce",
                 on_verdict: Optional[Callable[[dict, dict], None]] = None, document_ttl_seconds: int = 86400,
                 now: Callable[[], Any] = now_utc):
        for a in authorities:
            if a.get("currency_policy") not in ("record", "record_or_statement"): raise ValueError(f"{a.get('artifact_id')}: currency_policy must be record or record_or_statement (no default)")
            if a["currency_policy"] == "record" and not a.get("in_force_seal_hash"): raise ValueError(f"{a['artifact_id']}: currency_policy record needs in_force_seal_hash")
        if store is None:
            import warnings
            warnings.warn("nomosprotocol accept(): using the in-memory store. Nonces and receipts are lost on restart. Development only; use postgres_store() in production.")
        self.relying_party_id, self.root, self.authorities, self.commit = relying_party_id, root, authorities, commit
        self.act_endpoint, self.local_facts, self.store = act_endpoint, local_facts, store or MemoryStore()
        self.max_window_seconds, self.max_act_bytes, self.revocations, self.mode = max_window_seconds, max_act_bytes, revocations, mode
        self.on_verdict, self.document_ttl_seconds, self.now = on_verdict, document_ttl_seconds, now
        from urllib.parse import urlparse
        self.endpoint_path = urlparse(act_endpoint).path
        self.root_kid = suites.compute_kid(root)

    def document(self) -> dict:
        from datetime import timedelta
        return {
            "nomos_document": "relying-party", "version": "1", "relying_party_id": self.relying_party_id, "act_endpoint": self.act_endpoint,
            "roots": [{"kid": self.root_kid, "public_key_pem": self.root}],
            "authorities": [{"artifact_id": a["artifact_id"], **({"issuer": a["issuer"]} if a.get("issuer") else {}), "actions": a["actions"],
                             "currency_policy": a["currency_policy"], **({"in_force_seal_hash": a["in_force_seal_hash"]} if a.get("in_force_seal_hash") else {})}
                            for a in self.authorities],
            "max_window_seconds": self.max_window_seconds, "max_act_bytes": self.max_act_bytes,
            "consent_suites": ["Ed25519", "ES256", "WebAuthn-ES256"],
            "valid_until": iso(self.now() + timedelta(seconds=self.document_ttl_seconds)),
        }

    def _verify(self, act, authority, facts, at, seen, rev) -> dict:
        return verify_act(act, relying_party_id=self.relying_party_id, root_pem=self.root, now=at,
                          seen_nonces={act["nonce"]} if seen else set(), currency_policy=authority["currency_policy"], local_facts=facts,
                          revoked_kids=rev.get("kids"), revoked_certs=rev.get("certs"), revoked_artifacts=rev.get("artifacts"),
                          in_force={authority["artifact_id"]: authority["in_force_seal_hash"]} if authority.get("in_force_seal_hash") else {},
                          max_window_seconds=self.max_window_seconds)

    def handle(self, method: str, content_type: str, body: bytes) -> Tuple[int, Dict[str, str], dict]:
        """The framework-neutral core: one Act in, one NOMOS-SPEC-009 §6.2 answer out."""
        if method.upper() != "POST": return 405, {"allow": "POST", "content-type": "application/json"}, {"error": "POST an Act here."}
        if (content_type or "").split(";")[0].strip().lower() != ACT_MEDIA_TYPE:
            return 415, {"content-type": "application/json"}, {"error": f"Content-Type must be {ACT_MEDIA_TYPE}."}
        if len(body) > self.max_act_bytes: return 413, {"content-type": "application/json"}, {"error": f"The Act is larger than {self.max_act_bytes} bytes."}
        try: act = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError): return _answer({"decision": "MALFORMED", "reason_code": "bad_json"})
        artifact_id = (((act or {}).get("authority") or {}).get("artifact") or {}).get("meta", {}).get("artifact_id") if isinstance(act, dict) else None
        authority = next((a for a in self.authorities if a["artifact_id"] == artifact_id), None)
        if not authority: return _answer({"decision": "NOT_ACCEPTED", "reason_code": "authority_not_accepted", "artifact_id": artifact_id})
        if (act.get("action") or {}).get("type") not in authority["actions"]:
            return _answer({"decision": "NOT_ACCEPTED", "reason_code": "action_not_accepted", "action_type": (act.get("action") or {}).get("type")})
        try: rev = (self.revocations() if self.revocations else None) or {}
        except Exception as e:
            retry = e.retry_after_seconds if isinstance(e, RevocationUnavailable) else 60
            return 503, {"content-type": "application/json", "retry-after": str(retry)}, {
                "error": "Revocation status is not current, so nothing is committed. Resubmit this same Act later.", "detail": str(e), "retry_after": retry}
        at = self.now()
        facts = self.local_facts(act) if self.local_facts else {}
        verdict = self._verify(act, authority, facts, at, self.store.has_nonce(act["nonce"]), rev)

        def receipt_of(v, f, committed_at=None):
            r = {"act_id": act["act_id"], "act_digest": v.get("act_digest", ""), "decision": v["decision"], "rule": v.get("rule"),
                 **({"by_consent": True} if v.get("by_consent") else {}), "verified_at": iso(at),
                 **({"committed_at": iso(committed_at)} if committed_at else {}), "relying_party_facts": f,
                 **({"in_force_source": v["in_force_source"]} if v.get("in_force_source") else {}), "currency_policy": authority["currency_policy"]}
            return r

        if verdict["decision"] == "REPLAYED":
            return _answer(verdict, act_id=act["act_id"], receipt=self.store.receipt_for(act["nonce"]))
        if verdict["decision"] != "AUTHORIZED" or self.mode == "shadow":
            if self.on_verdict: self.on_verdict(verdict, receipt_of(verdict, facts))
            if verdict["decision"] == "ESCALATED":
                esc = next((e for e in ((act["authority"]["artifact"].get("governance") or {}).get("escalations") or []) if e.get("id") == verdict.get("escalation_id")), None)
                return _answer(verdict, role=(esc or {}).get("role_required"), retry_until=act["expires_at"])
            if self.mode == "shadow":
                s, h, b = _answer(verdict); return 200, h, {**b, "shadow": True}
            return _answer(verdict)

        # SPEC-008 §8, one atomic operation.
        try:
            with self.store.transaction() as t:
                if not t.claim_nonce(act["nonce"]): raise _LostRace()
                final, final_facts = verdict, facts
                if self.local_facts:
                    fresh = self.local_facts(act, t.tx)
                    if fresh != facts:                      # step 3: our state moved since verification
                        final_facts = fresh
                        final = self._verify(act, authority, fresh, at, False, rev)
                        if final["decision"] != "AUTHORIZED": raise _Rollback(_answer(final))
                a = act["action"]
                action = copy.deepcopy({"type": a["type"], **({"subject": a["subject"]} if "subject" in a else {}), "params": a.get("params") or {}})
                result = self.commit(action, t.tx, act["act_id"])
                receipt = receipt_of(final, final_facts, self.now())
                t.put_receipt(act["nonce"], receipt, act)
            if self.on_verdict: self.on_verdict(final, receipt)
            return _answer(final, receipt=receipt, **({"result": result} if result is not None else {}))
        except _Rollback as r:
            return r.answer
        except _LostRace:
            # Read only now, after the losing transaction has ended and released its connection.
            return _answer({"decision": "REPLAYED"}, act_id=act["act_id"], receipt=self.store.receipt_for(act["nonce"]))
        except Exception as e:
            return 500, {"content-type": "application/json"}, {"error": "The commit failed and was rolled back; nothing was applied.", "detail": str(e)}

    # ── WSGI and ASGI ──────────────────────────────────────────────────────────────────────
    def wsgi(self, environ, start_response):
        path, method = environ.get("PATH_INFO", ""), environ.get("REQUEST_METHOD", "GET")
        def send(status, headers, body):
            data = json.dumps(body).encode()
            start_response(f"{status} {_REASON.get(status, '')}", [*headers.items(), ("content-length", str(len(data)))])
            return [data]
        if method == "GET" and path == WELL_KNOWN:
            return send(200, {"content-type": "application/json", "cache-control": "max-age=300"}, self.document())
        if path != self.endpoint_path: return send(404, {"content-type": "application/json"}, {"error": "Not found"})
        try: length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError: length = 0
        body = environ["wsgi.input"].read(min(length, self.max_act_bytes + 1)) if length else b""
        if length > self.max_act_bytes: body = b"x" * (self.max_act_bytes + 1)
        return send(*self.handle(method, environ.get("CONTENT_TYPE", ""), body))

    async def asgi(self, scope, receive, send):
        if scope["type"] != "http": return
        path, method = scope["path"], scope["method"]
        async def reply(status, headers, body):
            data = json.dumps(body).encode()
            await send({"type": "http.response.start", "status": status, "headers": [(k.encode(), v.encode()) for k, v in {**headers, "content-length": str(len(data))}.items()]})
            await send({"type": "http.response.body", "body": data})
        if method == "GET" and path == WELL_KNOWN:
            return await reply(200, {"content-type": "application/json", "cache-control": "max-age=300"}, self.document())
        if path != self.endpoint_path: return await reply(404, {"content-type": "application/json"}, {"error": "Not found"})
        chunks, size = [], 0
        while True:
            m = await receive(); b = m.get("body", b""); size += len(b)
            if size <= self.max_act_bytes: chunks.append(b)
            if not m.get("more_body"): break
        body = b"".join(chunks) if size <= self.max_act_bytes else b"x" * (self.max_act_bytes + 1)
        ctype = next((v.decode() for k, v in scope.get("headers", []) if k.decode().lower() == "content-type"), "")
        import asyncio
        return await reply(*(await asyncio.get_running_loop().run_in_executor(None, self.handle, method, ctype, body)))


_REASON = {200: "OK", 201: "Created", 202: "Accepted", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
           409: "Conflict", 413: "Payload Too Large", 415: "Unsupported Media Type", 422: "Unprocessable Entity", 500: "Internal Server Error", 503: "Service Unavailable"}


def accept(**options) -> RelyingParty:
    return RelyingParty(**options)
