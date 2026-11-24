# The Lean model as test oracle

`oracle` reads cases as JSON lines and writes the verdict the Lean model of Part II gives for each. It is the model's verdict by proof: `OracleCore.lean` computes the deciding rule with `pick` (proved to be the decider, `pick_isDecider` in Completeness.lean) and the gate with a Boolean function proved equal to `GateFires` (`gateB_iff`), and `verdict_is_model` states that the result is the model's. Standard axioms only.

`Main.lean` (JSON reading, and the comparison primitives the model leaves abstract) is ordinary code. It sits outside the proof libraries, which stay core-only.

```
cd papers && lake build oracle
.lake/build/bin/oracle < cases.jsonl > expected.jsonl
```

The vectors built from it, and the checks of the Python and TypeScript evaluators against them, are in `../../oracle-vectors/`.
