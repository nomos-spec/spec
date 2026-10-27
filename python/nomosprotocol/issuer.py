"""issuer(): publish your sealed authorities, the version of each in force, your certificate pool
and your revocation list (NOMOS-SPEC-009 §3.2, NOMOS-SPEC-008 §5.4, NOMOS-SPEC-007 rev. 1.10 §5.3).

    acme = issuer(origin="https://policy.acme.example", issuer_id="acme", signer=sealing_key,
                  authorities=[policy], key_certs=lambda: registry_pool(),
                  witnesses=["https://finance.acme.example"], approvals=[{"role": "MANAGER", "endpoint": "https://approve.acme.example/nomos/approvals"}],
                  revocations=lambda: current_list)
    app = acme.wsgi
"""
from __future__ import annotations

import json
from datetime import timedelta
from typing import Any, Callable, List, Optional, Union
from urllib.parse import quote, unquote

from .statements import Signer, iso, now_utc, sign_in_force

WELL_KNOWN = "/.well-known/nomos-issuer"


class Issuer:
    def __init__(self, *, origin: str, issuer_id: str, signer: Signer, authorities: List[dict],
                 key_certs: Union[List[dict], Callable[[], List[dict]]], witnesses: Optional[List[str]] = None,
                 approvals: Optional[List[dict]] = None, revocations: Optional[Callable[[], dict]] = None,
                 revocations_url: Optional[str] = None):
        self.base, self.issuer_id, self.signer = origin.rstrip("/"), issuer_id, signer
        self.by_id = {a["meta"]["artifact_id"]: a for a in authorities}
        self.key_certs, self.witnesses, self.approvals, self.revocations = key_certs, witnesses, approvals, revocations
        self.revocations_url = f"{self.base}/nomos/revocations" if revocations else revocations_url

    def document(self) -> dict:
        pool = self.key_certs() if callable(self.key_certs) else self.key_certs
        return {
            "nomos_document": "issuer", "version": "1", "issuer_id": self.issuer_id,
            "authorities": [{"artifact_id": i, "version": a["meta"]["version"], "seal_hash": a["seal"]["hash"],
                             "artifact_url": f"{self.base}/nomos/authorities/{quote(i, safe='')}.nomos",
                             "in_force_url": f"{self.base}/nomos/authorities/{quote(i, safe='')}/in-force"} for i, a in self.by_id.items()],
            "key_certs": pool, **({"witnesses": self.witnesses} if self.witnesses else {}),
            **({"approvals": self.approvals} if self.approvals else {}),
            **({"revocations_url": self.revocations_url} if self.revocations_url else {}),
            "valid_until": iso(now_utc() + timedelta(days=1)),
        }

    def handle(self, method: str, path: str):
        if method != "GET": return 404, {"error": "Not found"}
        if path == WELL_KNOWN: return 200, self.document()
        if path == "/nomos/revocations" and self.revocations: return 200, self.revocations()
        prefix = "/nomos/authorities/"
        if path.startswith(prefix):
            rest = path[len(prefix):]
            if rest.endswith(".nomos") and unquote(rest[:-6]) in self.by_id: return 200, self.by_id[unquote(rest[:-6])]
            if rest.endswith("/in-force") and unquote(rest[:-9]) in self.by_id:
                art = self.by_id[unquote(rest[:-9])]
                return 200, sign_in_force(self.signer, art, valid_until=now_utc() + timedelta(days=1))
        return 404, {"error": "Not found"}

    def wsgi(self, environ, start_response):
        status, body = self.handle(environ.get("REQUEST_METHOD", "GET"), environ.get("PATH_INFO", ""))
        data = json.dumps(body).encode()
        start_response(f"{status} {'OK' if status == 200 else 'Not Found'}", [("content-type", "application/json"), ("content-length", str(len(data)))])
        return [data]

    async def asgi(self, scope, receive, send):
        if scope["type"] != "http": return
        status, body = self.handle(scope["method"], scope["path"])
        data = json.dumps(body).encode()
        await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]})
        await send({"type": "http.response.body", "body": data})


def issuer(**options) -> Issuer:
    return Issuer(**options)
