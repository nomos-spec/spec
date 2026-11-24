# The Lean model as test oracle

`oracle` reads cases as JSON lines, each an artifact and a fact set, and writes the verdict the Lean model of Part II gives. It reads the artifact's own `when` strings, so the oracle and an implementation read the same text.

| File | What it is | Proved |
|---|---|---|
| `OracleCore.lean` | the verdict: the deciding rule by `pick` (proved the decider, Completeness.lean), the 0.5.0 gate as a Boolean function | `gateB_iff`: the gate equals the model's `GateFires`; `verdict_is_model` |
| `OracleExpr.lean` | Nomos-Expr v1: tokenizer, recursive-descent parser, printer, and the comparison primitives the model leaves abstract | no (transcribed from the references) |
| `ParsePrint.lean` | the parser inverts the printer | `parse_print`: every well-formed condition, printed, parses back to itself, so a printed condition has exactly one reading |
| `Main.lean` | reads artifacts and facts as JSON, writes verdicts | no |

Standard axioms only, no `sorry`. What stays unproved: the tokenizer (text to tokens), JSON reading, and the primitives (`==`, `in`, `between`, ...). `matches()` (regular expressions) is not supported; an artifact that uses it is reported, not evaluated. The proof libraries in `carried-authority/` stay core-only; this directory imports `Lean.Data.Json`.

```
cd papers && lake build oracle ParsePrint
.lake/build/bin/oracle < cases.jsonl > expected.jsonl
```

The vectors built from it, and the checks of the Python and TypeScript evaluators, are in `../../oracle-vectors/`.
