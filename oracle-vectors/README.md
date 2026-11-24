# Lean-oracle vectors

The Lean model of Part II (`papers/carried-authority/lean`) is the definition the proofs are about. These vectors tie the implementations to it: random authorities and fact sets, each with the verdict the model gives, computed by the executable in `papers/oracle`.

The oracle reads each case's artifact itself, its `when` strings included (`papers/oracle/OracleExpr.lean`), and its verdict is the model's by proof: the deciding rule is `pick` (`pick_isDecider`), the gate a Boolean function proved equal to `GateFires` (`gateB_iff`, `verdict_is_model`), and the parser provably inverts the printer (`parse_print`). Standard axioms only. The tokenizer, JSON reading and the comparison primitives, which the model leaves abstract, are ordinary code transcribed from the references.

| File | What it is |
|---|---|
| `generate.py` | random cases, deterministic for a count and a seed: ties under all three tie orders, defaults with and without an escalation, obligation rules, exists() on inputs whose absence is and is not authoritative, facts absent, present and of the wrong kind, and artifacts with a ruling no evaluator may read (`set`, an undeclared action), which must be refused whatever the facts |
| `laws.py` | random fact sets for real sealed authorities, aimed at the numbers, values and lists their rules test |
| `build.py` | joins the cases with the oracle's verdicts into `vectors.json` |
| `vectors.json` | 5,000 cases (`generate.py 5000 2026`), 174 of them unevaluable, reproduced byte for byte in CI |
| `check.py` | the Python reference (`nomosprotocol.act.evaluate`) against the vectors, or against any generated run |

An implementation agrees with a case when `evaluate(artifact, facts)` gives the same verdict (allow → authorized, block → denied, escalate → escalated, undecided → incomplete), the same deciding rule (`rN` → N; none when the default applied) and the same escalation; or, for `{"unevaluable": true}`, refuses the artifact.

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

Checked on 24 November 2026:

- **Generated:** the 5,000 published cases and 200,000 more (seed 9431). Python and TypeScript agree with the model on every one.
- **Real laws:** 3,700 fact sets (`laws.py`) over eight authorities: seven sealed ones from the NOMOS Exchange (the 851-rule EU AI Act listing, the 186-rule EU AI Act, the DIFC Data Protection Law, ADGM DPR, the UAE PDPL, Saudi PDPL and Qatar PDPPL) and the EU AI Act Article 5 draft. Python and TypeScript agree with the model on every one: the same verdict, deciding rule and escalation on 3,500, and on the listing's 200 a refusal, below.
- **A conformance bug found:** the 851-rule EU AI Act listing has `set` rulings, which SPEC-008 §6.0 says make the artifact unevaluable (`MALFORMED`, `unevaluable_rules`) whatever the facts. Both references refused it only when such a rule was reached, and returned a verdict for 48 of the 200 fact sets. Both now refuse it before evaluating; one derived SPEC-008 mutant's expectation changed accordingly (DENIED → MALFORMED, `act-vectors/mutants.json` regenerated).

The corpus catches each of these faults, introduced one at a time into the TypeScript evaluator (published cases that then fail, of 5,000):

| Fault | Cases that fail |
|---|---|
| gate clause (ii) dropped (the 0.4.0 gap) | 38 |
| gate clause (i) dropped | 1,132 |
| absence never authoritative (exists() on the action or relying party's state) | 45 |
| a later rule wins a full tie (position ignored) | 207 |
| the tie order ignored (always deny_wins) | 280 |
| the default outcome ignored | 875 |
| the default escalation id dropped | 101 |
| a fact of the wrong kind read as false, not undecided | 385 |
| an unevaluable ruling refused only when reached (the bug above) | 93 |
