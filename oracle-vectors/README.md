# Lean-oracle vectors

The Lean model of Part II (`papers/carried-authority/lean`) is the definition the proofs are about. These vectors tie the implementations to it: random authorities and fact sets, each with the verdict the model gives, computed by the executable in `papers/oracle`.

That executable is the model's own verdict, by proof: the deciding rule is `pick` (`pick_isDecider`, Completeness.lean), and the gate is a Boolean function proved equal to the model's `GateFires` (`gateB_iff`, `verdict_is_model` in `papers/oracle/OracleCore.lean`). Standard axioms only. The JSON reading and the comparison primitives in `papers/oracle/Main.lean` are ordinary code: the model leaves primitives abstract, so these vectors check resolution (Kleene logic, the choice of decider, the 0.5.0 gate, defaults, tie orders, obligations), not parsing or primitives, which the SPEC-008 vectors cover.

| File | What it is |
|---|---|
| `generate.py` | random cases, deterministic for a count and a seed: ties under all three tie orders, defaults with and without an escalation, obligation rules, exists() on inputs whose absence is and is not authoritative, facts absent, present and of the wrong kind |
| `build.py` | joins the cases with the oracle's verdicts into `vectors.json` |
| `vectors.json` | 5,000 cases (`generate.py 5000 2026`), reproduced byte for byte in CI |
| `check.py` | the Python reference (`nomosprotocol.act.evaluate`) against the vectors, or against any generated run |

An implementation agrees with a case when `evaluate(artifact, facts)` gives the same verdict (allow → authorized, block → denied, escalate → escalated, undecided → incomplete), the same deciding rule (`rN` → N; none when the default applied) and the same escalation.

```
cd papers && lake build oracle                    # Lean 4.35
cd ../oracle-vectors
python3 check.py vectors.json                     # 5000/5000
# any number more, locally:
python3 generate.py 1000000 $RANDOM > cases.local.jsonl
../papers/.lake/build/bin/oracle < cases.local.jsonl > expected.local.jsonl
python3 check.py cases.local.jsonl expected.local.jsonl
```

The TypeScript verifier (`@nomosprotocol/verify`) checks the same file in its conformance suite, and has a runner for generated batches (`test/lean-oracle-run.ts`).

Checked on 24 November 2026: 5,000 published cases and 200,000 generated ones (seed 9431), Python and TypeScript both agree with the model on every case.

The corpus catches each of these faults, introduced one at a time into the TypeScript evaluator (published cases that then fail, of 5,000):

| Fault | Cases that fail |
|---|---|
| gate clause (ii) dropped (the 0.4.0 gap) | 46 |
| gate clause (i) dropped | 1,113 |
| absence never authoritative (exists() on the action or relying party's state) | 35 |
| a later rule wins a full tie (position ignored) | 196 |
| the tie order ignored (always deny_wins) | 244 |
| the default outcome ignored | 868 |
| the default escalation id dropped | 78 |
| a fact of the wrong kind read as false, not undecided | 357 |
