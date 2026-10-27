# NOMOS-SPEC-010 signature suite vectors

Test vectors for [NOMOS-SPEC-010](../spec/drafts/NOMOS-SPEC-010.md), and two independent verifiers
that pass them.

```
pip install cryptography          # 42 or later (RFC 6979 deterministic ECDSA)
python3 generate.py > vectors.json   # deterministic: byte-identical on every run
python3 check.py vectors.json        # the Python reference
node check.mjs vectors.json          # an independent verifier, Node built-in crypto only
```

| File | What it is |
|---|---|
| `../python/nomosprotocol/suites.py` | The reference verifier, and the signers the generator uses (shared with the SPEC-007 and SPEC-008 references) |
| `generate.py` | Builds `vectors.json` from published seeds |
| `check.py` | Runs the reference verifier against the vectors |
| `check.mjs` | A second verifier, written from the specification text alone, sharing no code with the reference |
| `vectors.json` | 30 cases: Ed25519 (including the key-validity rule of §3.1), ES256 (including low-S and P1363 encoding), WebAuthn-ES256 (including user verification and challenge binding), canonical keys, and closed-registry rejection |

Each case gives the suite, the public key, the exact payload bytes (`payload_b64`) and the proof,
and expects `{ ok, reason }`. A conformant verifier reproduces `expected` exactly, including the
reason.

Writing the second verifier found a real ambiguity in the first draft: it defined a canonical key
as "re-encode it and compare", and Node re-emits a compressed P-256 point in the same compressed
form while Python re-emits it uncompressed, so the two disagreed on whether the key was valid.
§3.1 now fixes the canonical encodings byte for byte.

The keys are test keys derived from published seeds. Never use them as trust material.
