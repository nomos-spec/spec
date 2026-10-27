# nomosprotocol

NOMOS for Python. It includes the reference verifiers of the NOMOS specifications and the developer
layer built on them:
- `accept()`, for the system that makes a change;
- `act()`, for the agent that carries one;
- `witness()` and `issuer()`, for the systems that sign the facts and publish the rules.

```
pip install nomosprotocol             # cryptography is the only dependency
pip install "nomosprotocol[postgres]" # adds psycopg, for postgres_store()
```

Python 3.9+. The verifiers in this package are the same code the specification's published test
vectors are generated and checked with, so there is no second Python implementation to drift from
the reference.

## Be the system that makes the change

```python
import nomosprotocol as nomos

rp = nomos.accept(
    relying_party_id="orders.acme.example",
    root=ACME_ROOT_PEM,                                   # the root you pin; there is no default
    act_endpoint="https://orders.acme.example/nomos/acts",
    authorities=[{"artifact_id": "acme-purchasing", "issuer": "https://policy.acme.example",
                  "actions": ["purchase"], "currency_policy": "record", "in_force_seal_hash": POLICY_SEAL_HASH}],
    local_facts=lambda act, tx=None: {"vendor_blocked": is_blocked(act["action"]["params"]["vendor"])},
    commit=lambda action, tx, act_id: create_order(tx, action),    # your code, on the same transaction
    store=nomos.postgres_store(lambda: psycopg.connect(DATABASE_URL)),
)
app = rp.wsgi      # Flask, Django, gunicorn: any WSGI server
app = rp.asgi      # FastAPI/Starlette mount, uvicorn: any ASGI server
```

Every Act is verified locally (NOMOS-SPEC-008). If it is authorized, `accept()` does four things
in one transaction: records the nonce, re-reads your facts, hands `commit` exactly the verified
action, and stores the receipt with the Act.

| Verdict | Status |
|---|---|
| AUTHORIZED, committed | 201 |
| ESCALATED | 202 |
| INCOMPLETE | 422 |
| DENIED | 403 |
| REPLAYED | 409, with the original receipt |
| Any other refusal | 400 |
| Revocations unavailable | 503 |

If any number of copies of one Act arrive at once, exactly one commits and the rest get its
receipt. If revocation status can't be established, nothing commits.

## Be the agent

```python
r = nomos.act(to="http://localhost:4747",
              action={"type": "purchase", "subject": "DEPT-17", "params": {"amount": 500, "vendor": "paperco"}})
print(r["status"])        # committed | escalated | incomplete | denied | refused | replayed
```

`act()` handles the whole round trip:
- discovers the system;
- fetches the rules it acts under;
- collects signed facts from the witnesses;
- presents exactly the certificates the Act relies on;
- submits;
- if a person must approve, waits for the approval and resubmits.

It uses only the standard library. To try it, run `npx @nomosprotocol/cli dev`.

## The other roles

- `witness(origin=…, witness_id=…, signer=…, claims={"budget_remaining": lambda about: …}, key_certs=…)` signs one fact about one subject on request.
- `issuer(origin=…, issuer_id=…, signer=…, authorities=[policy], key_certs=…, revocations=…)` publishes the sealed rules, the version in force, the certificate pool and the revocation list.

Keys are `Signer`s: anything with `kid`, `public_key_pem`, `algorithm` and `sign(payload) -> str`.
`local_signer(pem)` and `generate_signer()` are for development; for production, wrap your KMS.

## Verify directly

```python
from nomosprotocol import verify_act, chain
v = verify_act(act, relying_party_id="…", root_pem=ROOT, now=datetime.now(timezone.utc),
               seen_nonces=set(), currency_policy="record", in_force={"acme-purchasing": SEAL_HASH})
chain.verify_revocation_list(lst, ROOT, now)          # NOMOS-SPEC-007 rev. 1.10
```

## Conformance

This package is checked against:
- every vector of NOMOS-SPEC-007 (1.7.0, rev. 1.9, rev. 1.10 revocation sources), NOMOS-SPEC-008
  0.6.0 and NOMOS-SPEC-010 0.2.0;
- the NOMOS-SPEC-009 selection vectors;
- the NOMOS-SPEC-009 HTTP runner, 17 of 17, with `accept()` behind it
  (`python/tests/conformance_rp.py`).

`act()` also interoperates with the JavaScript sandbox, escalation and approval included
(`python/tests/interop_sandbox.py`).

MIT licensed.
