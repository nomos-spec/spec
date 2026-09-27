# Python chain-of-trust verifier (NOMOS-SPEC-007)

A second implementation of the SPEC-007 verifier — §3 certificates, §3.4 scope, §4 the walk,
§5.2 key-revocation cascade, §5.4 certificate revocation, §5.5 freshness staples — in Python,
with `pyca/cryptography` instead of `node:crypto` and its own JCS code.

It was written from the specification text only, without reading the reference TypeScript
(`prototype/chain-of-trust/chain-verify-core.ts`), and then run against
`chain-of-trust-vectors/vectors.json`.

## Result

```
# run from a checkout of github.com/nomos-spec/spec
python3 verify_chain.py chain-of-trust-vectors/vectors.json
14 passed, 0 failed
```

## What this does and does not show

It shows the spec text is sufficient for a separate codebase, in a different language, to
reproduce every reference verdict — decision, reason code, path, leaf kid, effective scope,
revoked kid and revocation confidence.

It is **not** the independent, third-party implementation §8.2 asks for: it was produced for
NOMOS. The §8.2 "single implementation" disclosure should be narrowed, not removed, until an
unaffiliated implementer reports a match.

Run it against the **nomos-spec/spec** copy of the vectors (14 cases). The copy in this repo's
`chain-of-trust-vectors/` is the older 7-case set and still uses `reason` where the spec repo
now uses `reason_code`, so two of its cases report a field mismatch.

This belongs in the nomos-spec/spec repository (`implementations/python-chain-verifier/`); it
lands here first because that organisation blocks third-party app access.

## Findings from implementing the text (for the spec, not fixed here)

1. **§5.5 root confidence vs. the `freshness_staple_full_coverage` vector.** §5.5 says the root
   is computed "once per kid on the resolved path (root included)" and that the root's
   confidence is always `unchecked` without a live source. Read literally, the weakest-link
   aggregate can then never be `staple`, yet the vector expects `staple`. The vector (and its
   note) exclude the root from the aggregate. Run with `--strict-root` to see the literal
   reading fail that one case. Suggest the text say the root is excluded from the aggregate.
2. **§3.4 says "This version defines exactly two" dimensions** but its table defines three
   (`artifact`, `industry`, `jurisdiction`).
3. **No vector covers** `CERTIFICATE_REVOKED`, `jurisdiction` scope, the `artifact` scope
   dimension, an unrecognized scope dimension, a cycle, `not_yet_valid`, or the relative order of
   `SEAL_INVALID` vs `OUT_OF_SCOPE` when both apply. Choices this implementation made where the
   text is silent: seal is checked before scope; malformed scope strings return `OUT_OF_SCOPE`
   with `reason_code: malformed_scope`.

Requires Python 3.9+ and `pip install cryptography`.
