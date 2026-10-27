#!/usr/bin/env python3
"""nomosprotocol's developer layer, over real HTTP: a Python issuer, witness and relying party, and
the Python carrier, plus the certificate-selection vectors, concurrency on the memory and Postgres
stores, and fail-closed revocation.

    python3 python/tests/test_sdk.py                                   (memory store)
    NOMOS_TEST_DATABASE_URL=postgresql://…@127.0.0.1:…/scratch python3 python/tests/test_sdk.py   (also Postgres; LOCAL only)
"""
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from urllib.parse import urlparse
from wsgiref.simple_server import WSGIRequestHandler, make_server

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import nomosprotocol as nomos  # noqa: E402
from nomosprotocol.chain import fingerprint  # noqa: E402
from nomosprotocol.statements import now_utc  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
passed = failed = 0


def check(ok, label, got=None):
    global passed, failed
    if ok: passed += 1; print(f"  ok    {label}")
    else: failed += 1; print(f"  FAIL  {label}\n        {json.dumps(got, default=str)[:400]}")


class Quiet(WSGIRequestHandler):
    def log_message(self, *a): pass


def serve(app):
    srv = make_server("127.0.0.1", 0, app, handler_class=Quiet)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_port}", srv


# 1. NOMOS-SPEC-009 §6.5 selection vectors.
sel = json.load(open(os.path.join(HERE, "..", "..", "submission-vectors", "selection.json")))
for c in sel["cases"]:
    relied = {"authority": {"artifact": {"seal": {}}}, "testimony": [{"kid": k} for k in c["relied_kids"]]}
    got = nomos.presented_certificates([x for v in c["available"].values() for x in v], relied)
    shape = {"presentable": False, "size": len(got)} if len(got) > 20 else {"presentable": True, "size": len(got), "fingerprints": sorted(fingerprint(x) for x in got)}
    check(shape == c["expected"], f"SPEC-009 §6.5 vector: {c['name']}", shape)

# 2. Keys match the TypeScript SDK's.
check(nomos.seeded_signer("nomos-dev/v1:root (TEST KEY)").kid == "fzvRKZgKytzBJlKk", "seeded keys are byte-identical to @nomosprotocol/sdk's (the sandbox root)")
for alg in ("Ed25519", "ES256"):
    s = nomos.generate_signer(alg); r = nomos.local_signer(s.private_key_pem())
    check(r.kid == s.kid and r.sign(b"x") == s.sign(b"x"), f"{alg}: a key survives PEM round-trip with the same kid and deterministic signatures")

# 3. A whole world in Python, over HTTP.
root, acme, finance = nomos.seeded_signer("py-sdk:root"), nomos.generate_signer("ES256"), nomos.generate_signer("Ed25519")
year = now_utc() + timedelta(days=365)
policy = nomos.seal({
    "nomos_version": "2.2.0", "meta": {"artifact_id": "py-purchasing", "version": "1.0.0"},
    "data_contract": {"inputs": {"amount": {"type": "number", "source": "action"}, "vendor": {"type": "string", "source": "action"},
                                 "budget_remaining": {"type": "number", "source": "testimony"}, "vendor_blocked": {"type": "boolean", "source": "relying_party"}}},
    "logic": {"decisions": [
        {"id": "P1", "when": "vendor_blocked == true", "then": [{"type": "block"}], "priority": 100},
        {"id": "P2", "when": "amount > budget_remaining", "then": [{"type": "block"}], "priority": 90},
        {"id": "P4", "when": "amount <= 1000", "then": [{"type": "allow"}], "priority": 10}],
        "resolution": {"conflict_policy": "highest_priority", "tie_breaker": "deny_wins", "default_outcome": "block"}},
}, acme, "acme")
seal_cert = nomos.certify(root, acme.kid, acme.public_key_pem, scope="artifact:py-purchasing", expires_at=year)
finance_cert = nomos.certify(root, finance.kid, finance.public_key_pem, scope="claim:budget_remaining", expires_at=year)
budgets = {"D1": 5000}
wit_holder = {}
wit_url, _ = serve(lambda e, s: wit_holder["w"].wsgi(e, s))
wit_holder["w"] = nomos.witness(origin=wit_url, witness_id="py-finance", signer=finance, claims={"budget_remaining": lambda about: budgets.get(about)}, key_certs=[finance_cert])
iss_holder = {}
iss_url, _ = serve(lambda e, s: iss_holder["i"].wsgi(e, s))
iss_holder["i"] = nomos.issuer(origin=iss_url, issuer_id="acme", signer=acme, authorities=[policy], key_certs=lambda: [seal_cert], witnesses=[wit_url])
orders, revocation_state = [], {"raise": False}
def revs():
    if revocation_state["raise"]: raise nomos.RevocationUnavailable("the issuer's list is stale", 30)
    return {}
rp_holder = {}
rp_url, _ = serve(lambda e, s: rp_holder["rp"].wsgi(e, s))
import warnings; warnings.simplefilter("ignore")
rp_holder["rp"] = nomos.accept(relying_party_id="py.shop", root=root.public_key_pem, act_endpoint=f"{rp_url}/nomos/acts",
                               authorities=[{"artifact_id": "py-purchasing", "issuer": iss_url, "actions": ["purchase"], "currency_policy": "record", "in_force_seal_hash": policy["seal"]["hash"]}],
                               local_facts=lambda a, tx=None: {"vendor_blocked": a["action"]["params"].get("vendor") == "shadyco"},
                               commit=lambda action, tx, act_id: (orders.append(action), {"order": len(orders)})[1], revocations=revs)

r = nomos.act(to=rp_url, action={"type": "purchase", "subject": "D1", "params": {"amount": 500, "vendor": "paperco"}})
check(r["status"] == "committed" and r["receipt"]["decision"] == "AUTHORIZED" and r["result"] == {"order": 1}, "Python carrier → Python relying party: committed", r.get("verdict"))
check(len(r["act"]["authority"]["key_certs"]) == 2, "presented exactly the seal's and the witness's certificates (the witness returned its own)", len(r["act"]["authority"]["key_certs"]))
import urllib.request
def post_act(a, ctype="application/nomos-act+json"):
    req = urllib.request.Request(f"{rp_url}/nomos/acts", data=json.dumps(a).encode(), method="POST", headers={"content-type": ctype})
    try:
        with urllib.request.urlopen(req) as resp: return resp.status, json.loads(resp.read()), dict(resp.headers)
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}"), dict(e.headers)
st, body, _ = post_act(r["act"])
check(st == 409 and body["receipt"] == r["receipt"], "the same Act again: 409 with the identical receipt", body)
r = nomos.act(to=rp_url, action={"type": "purchase", "subject": "D9", "params": {"amount": 500, "vendor": "paperco"}})
check(r["status"] == "incomplete" and r["missing"][0]["fact"] == "budget_remaining", "an unknown subject: incomplete, naming budget_remaining", r.get("missing"))
r = nomos.act(to=rp_url, action={"type": "purchase", "subject": "D1", "params": {"amount": 9000, "vendor": "paperco"}})
check(r["status"] == "denied" and r["verdict"]["rule"] == "P2", "over budget: denied by P2", r.get("verdict"))
r = nomos.act(to=rp_url, action={"type": "purchase", "subject": "D1", "params": {"amount": 100, "vendor": "shadyco"}})
check(r["status"] == "denied" and r["verdict"]["rule"] == "P1", "the relying party's own fact applies (blocked vendor): denied by P1", r.get("verdict"))
st, _, _ = post_act({}, "application/json")
check(st == 415, "any other media type: 415", st)
revocation_state["raise"] = True
r2 = nomos.build_act(relying_party="py.shop", action={"type": "purchase", "subject": "D1", "params": {"amount": 1, "vendor": "x"}}, artifact=policy, key_certs=[seal_cert])
st, body, hdrs = post_act(r2)
check(st == 503 and hdrs.get("retry-after") == "30", "revocations that cannot be established: 503 with Retry-After, nothing committed", body)
revocation_state["raise"] = False

# 4. Concurrency: twenty submissions of one Act, exactly one commit.
def race(rp, act, n=20):
    with ThreadPoolExecutor(max_workers=n) as ex:
        return list(ex.map(lambda _: rp.handle("POST", "application/nomos-act+json", json.dumps(act).encode()), range(n)))
def fresh_act(amount=100):
    t = nomos.sign_testimony(finance, claim="budget_remaining", value=5000, about="D1", valid_until=now_utc() + timedelta(minutes=10))
    return nomos.build_act(relying_party="py.shop", action={"type": "purchase", "subject": "D1", "params": {"amount": amount, "vendor": "x"}},
                           artifact=policy, key_certs=[seal_cert, finance_cert], testimony=[t], window_seconds=600)
def rp_with(store, commit=None):
    return nomos.accept(relying_party_id="py.shop", root=root.public_key_pem, act_endpoint="http://x/nomos/acts", store=store,
                        authorities=[{"artifact_id": "py-purchasing", "actions": ["purchase"], "currency_policy": "record", "in_force_seal_hash": policy["seal"]["hash"]}],
                        local_facts=lambda a, tx=None: {"vendor_blocked": False}, commit=commit or (lambda action, tx, act_id: {"ok": True}))
res = race(rp_with(nomos.MemoryStore()), fresh_act())
check(sorted(s for s, _, _ in res) == [201] + [409] * 19, "memory store: 20 concurrent duplicates, exactly one 201", sorted(s for s, _, _ in res))

url = os.environ.get("NOMOS_TEST_DATABASE_URL")
if url and urlparse(url).hostname in ("127.0.0.1", "localhost", "::1"):
    import psycopg
    table = f"nomos_acts_pytest_{os.getpid()}"
    from psycopg_pool import ConnectionPool
    pool = ConnectionPool(url, min_size=4, max_size=25, open=True)
    store = nomos.postgres_store(pool.connection, table=table)
    store.migrate(); store.migrate()
    try:
        a = fresh_act()
        res = race(rp_with(store), a)
        statuses = sorted(s for s, _, _ in res)
        receipts = {json.dumps(b["receipt"], sort_keys=True) for s, _, b in res}
        check(statuses == [201] + [409] * 19 and len(receipts) == 1, "postgres store: 20 concurrent duplicates, exactly one 201, every 409 with the same receipt", statuses)
        def boom(action, tx, act_id):
            with tx.cursor() as cur: cur.execute(f"SELECT 1")
            raise RuntimeError("merchant failure")
        b = fresh_act(200)
        s1, _, _ = rp_with(store, boom).handle("POST", "application/nomos-act+json", json.dumps(b).encode())
        check(s1 == 500 and not store.has_nonce(b["nonce"]), "a failing commit is 500 and leaves no nonce", s1)
        s2, _, body = rp_with(store).handle("POST", "application/nomos-act+json", json.dumps(b).encode())
        check(s2 == 201 and store.receipt_for(b["nonce"]) == body.get("receipt"), "the same Act then commits, and its receipt is stored", [s2, body])
        with psycopg.connect(url) as c, c.cursor() as cur:
            cur.execute(f"SELECT act::text FROM {table} WHERE nonce = %s", (b["nonce"],)); stored = json.loads(cur.fetchone()[0])
        check(stored == b, "the exact Act is retained beside its receipt", None)
        check(pool.get_stats().get("pool_size", 0) >= 4 and not pool.closed, "the pool keeps its connections: the store never closes one", pool.get_stats())
        once = nomos.postgres_store(lambda: psycopg.connect(url), table=table)
        c = fresh_act(300)
        s3, _, _ = rp_with(once).handle("POST", "application/nomos-act+json", json.dumps(c).encode())
        check(s3 == 201 and once.has_nonce(c["nonce"]), "a plain connect-per-call factory works too", s3)
    finally:
        with psycopg.connect(url) as c, c.cursor() as cur: cur.execute(f"DROP TABLE IF EXISTS {table}")
        pool.close()
else:
    print("  skip  postgres store (set NOMOS_TEST_DATABASE_URL to a local Postgres)")

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
