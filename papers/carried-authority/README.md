# Evidence for "Authorize the Act, Not the Agent" (Computable Authority, Part II)

Everything here runs offline, with no secrets. The keys come from the published seeds of the SPEC-008 test vectors; never use them as trust material.

| File | What it is |
|---|---|
| `act_verify_040.py`, `generate_040.py`, `vectors_040.json` | SPEC-008 0.4.0 reference verifier, generator and 29 vectors, frozen byte-for-byte from commit `c8fa382` (the 0.5.0 versions are in `../../act-vectors/`) |
| `ablate.py` → `ablation-results.json` | §7.1: removes one obligation at a time from the 0.4.0 verifier and presents an attack built from genuine statements (12/12 witnessed, plus the certificate-order ablation) |
| `modelcheck2.py` → `modelcheck2-results.txt` | §7.2: small-scope check of omission safety over random prioritized rule sets, for the 0.4.0 gate, the 0.5.0 gate and a two-valued control |
| `modelcheck.py` → `modelcheck-results.txt` | an earlier run where every escalation shares one identity; it cannot see the 0.4.0 gap, which is why the gap survived earlier testing |
| `lean/CarriedAuthority.lean` | §5: Proposition 1 (omission safety) for the 0.5.0 gate, the never-DENIED corollary, and the 0.4.0 counterexample (vector 30), mechanized in Lean 4 (core only, no Mathlib) |
| `pub_lending_v1.nomos` | the generator's input policy, copied from `../../act-vectors/` |

```
pip install cryptography
python3 ablate.py vectors_040.json      # 12/12 necessity witnesses; rewrites ablation-results.json identically
python3 modelcheck2.py 20000 2026       # ~17 minutes; reproduces modelcheck2-results.txt
cd lean && lean CarriedAuthority.lean   # Lean 4.35; prints nothing on success
cd ../../../act-vectors && python3 check.py vectors.json   # 32/32 under SPEC-008 0.5.0
```
