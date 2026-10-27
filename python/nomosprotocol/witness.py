"""witness(): turn an existing lookup into signed statements (NOMOS-SPEC-009 §3.3, §4).

    finance = witness(origin="https://finance.acme.example", witness_id="acme-finance", signer=finance_key,
                      claims={"budget_remaining": lambda about: budgets.get(about)},   # None = unknown subject
                      key_certs=finance_chain)                                       # returned with every statement (0.2.0 §4)
    app = finance.wsgi          # or finance.asgi

A witness is never in a relying party's verification path: it only produces statements, which the
relying party checks against the root it pins. `authorize` is your access control.
"""
from __future__ import annotations

import json
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional

from .statements import Signer, iso, now_utc, sign_testimony

WELL_KNOWN = "/.well-known/nomos-witness"


class Witness:
    def __init__(self, *, origin: str, witness_id: str, signer: Signer, claims: Dict[str, Callable[[Optional[str]], Any]],
                 max_validity_seconds: int = 900, authorize: Optional[Callable[[dict], bool]] = None,
                 access: Optional[str] = None, key_certs: Optional[List[dict]] = None):
        self.base, self.witness_id, self.signer, self.claims = origin.rstrip("/"), witness_id, signer, claims
        self.max_validity_seconds, self.authorize, self.access, self.key_certs = max_validity_seconds, authorize, access, key_certs or []

    def document(self) -> dict:
        return {"nomos_document": "witness", "version": "1", "witness_id": self.witness_id, "kid": self.signer.kid, "claims": list(self.claims),
                "statement_endpoint": f"{self.base}/nomos/statements", **({"access": self.access} if self.access else {}),
                "valid_until": iso(now_utc() + timedelta(days=1))}

    def handle(self, method: str, path: str, body: bytes):
        if method == "GET" and path == WELL_KNOWN: return 200, self.document()
        if method != "POST" or path != "/nomos/statements": return 404, {"error": "Not found"}
        try: req = json.loads(body or b"{}")
        except ValueError: return 400, {"error": "Not JSON."}
        claim, about = str(req.get("claim") or ""), req.get("about")
        read = self.claims.get(claim)
        if read is None: return 404, {"error": f"{self.witness_id} does not state {claim}."}
        if self.authorize and not self.authorize({"claim": claim, "about": about}): return 403, {"error": "Not entitled to this statement."}
        value = read(about)
        if value is None: return 404, {"error": f"{self.witness_id} knows nothing about {about}."}
        try: wanted = float(req.get("valid_for_seconds") or self.max_validity_seconds)
        except (TypeError, ValueError): wanted = self.max_validity_seconds
        seconds = max(1, min(self.max_validity_seconds, wanted))
        t = sign_testimony(self.signer, claim=claim, value=value, about=about, valid_until=now_utc() + timedelta(seconds=seconds))
        return 200, {"testimony": t, **({"key_certs": self.key_certs} if self.key_certs else {})}

    def wsgi(self, environ, start_response):
        try: length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError: length = 0
        status, body = self.handle(environ.get("REQUEST_METHOD", "GET"), environ.get("PATH_INFO", ""), environ["wsgi.input"].read(length) if length else b"")
        data = json.dumps(body).encode()
        start_response(f"{status} {'OK' if status == 200 else 'Error'}", [("content-type", "application/json"), ("content-length", str(len(data)))])
        return [data]

    async def asgi(self, scope, receive, send):
        if scope["type"] != "http": return
        chunks = []
        while True:
            m = await receive(); chunks.append(m.get("body", b""))
            if not m.get("more_body"): break
        status, body = self.handle(scope["method"], scope["path"], b"".join(chunks))
        data = json.dumps(body).encode()
        await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]})
        await send({"type": "http.response.body", "body": data})


def witness(**options) -> Witness:
    return Witness(**options)
