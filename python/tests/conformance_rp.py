#!/usr/bin/env python3
"""nomosprotocol's accept() configured with the NOMOS-SPEC-009 conformance profile, for the runner:
    python3 python/tests/conformance_rp.py submission-vectors/profile.json [port]
    node submission-vectors/run.mjs http://localhost:<port>
"""
import json, os, sys, warnings
from wsgiref.simple_server import WSGIRequestHandler, make_server
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import nomosprotocol as nomos  # noqa: E402

warnings.simplefilter("ignore")
profile = json.load(open(sys.argv[1]))
port = int(sys.argv[2]) if len(sys.argv) > 2 else 4803
a = profile["authority"]
rp = nomos.accept(relying_party_id=profile["relying_party_id"], root=profile["root_public_key_pem"], act_endpoint=f"http://localhost:{port}/nomos/acts",
                  authorities=[{"artifact_id": a["artifact_id"], "actions": a["actions"], "currency_policy": a["currency_policy"], "in_force_seal_hash": a["in_force_seal_hash"]}],
                  local_facts=lambda act, tx=None: {"vendor_blocked": ((act.get("action") or {}).get("params") or {}).get("vendor") == "blocked-vendor"},
                  commit=lambda action, tx, act_id: {"ok": True}, store=nomos.MemoryStore())
class Quiet(WSGIRequestHandler):
    def log_message(self, *x): pass
srv = make_server("127.0.0.1", port, rp.wsgi, handler_class=Quiet)
print(f"nomosprotocol accept() conformance relying party on http://localhost:{port}", flush=True)
srv.serve_forever()
