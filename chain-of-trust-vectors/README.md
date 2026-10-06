# NOMOS-SPEC-007 interop test vectors

**Status:** both NOMOS implementations — the pure reference in `../prototype/chain-of-trust/`
and the hosted platform's verifier — pass every case. These vectors are the test a second-party
implementation runs to show it agrees.

## What's here

`vectors.json` — fourteen cases, each an `{ artifact, key_certs, expected }` triple, plus a shared
`root_public_key_pem` and a `check_at` timestamp (the `now` a checker should evaluate against —
the fixtures are pinned to fixed 2026–2030 dates, not wall-clock time, so results stay
reproducible indefinitely rather than silently expiring):

| case | what it proves |
|---|---|
| `allowed` | a full chain resolves from the pinned root to the artifact's signing key |
| `allowed_reversed_order` | the same two certificates, reversed, reach the byte-identical verdict — presentation order carries no trust meaning |
| `issuer_not_recognized_uncertified_key` | an artifact signed by a key absent from the presented chain is rejected, not falsely accepted |
| `issuer_not_recognized_expired` | an expired certificate is rejected with a distinct, machine-readable reason |
| `seal_invalid_tampered_after_sealing` | a chain that resolves fine still rejects an artifact edited after sealing — kept distinct from "not recognized" because the caller's correct next action differs |
| `malformed_chain_over_length_cap` | an oversized `key_certs` array is rejected before any cryptographic work, not silently truncated |
| `malformed_unsealed_artifact` | an artifact with no seal is rejected outright |
| `scope_in_scope` | a scoped delegation allows an artifact that declares a matching industry (§3.4) |
| `scope_out_of_scope` | the same valid chain refuses an artifact outside the delegated industry — reported as `OUT_OF_SCOPE`, never `ISSUER_NOT_RECOGNIZED`, because the issuer IS recognized |
| `scope_undeclared_dimension_fails_closed` | an artifact declaring no `meta.industry` under an industry-scoped delegation is refused, not waved through |
| `scope_widening_rejected` | an intermediate holding `industry:financial` cannot issue `industry:healthcare` — a delegation never grants more than the delegator holds |
| `key_revoked_intermediate` | a revoked intermediate key kills the chain with `KEY_REVOKED`, even though every signature is valid (§5.2) |
| `freshness_staple_full_coverage` | staples from each key's certifying parent raise `revocation_checked` from `unchecked` to `staple` (§5.5) |
| `freshness_staple_partial_coverage_stays_unchecked` | if any hop lacks a staple, `revocation_checked` stays `unchecked` — the weakest hop sets the result |

The private keys used to generate these fixtures (`generate.ts`) are published in the clear on
purpose — they exist only to make the vectors regenerable and auditable, and must never be
treated as real trust material by anything that finds them.

## How to use these

If you're implementing NOMOS-SPEC-007 independently: run each case's `artifact` + `key_certs`
against your implementation, using `root_public_key_pem` as the pinned root and `check_at` as
the evaluation time, and confirm your verdict matches `expected`. If it does, that's real
evidence — open an issue or a PR at this repo noting which implementation you ran and what
matched.

## Verifying self-consistency

```bash
npx tsx chain-of-trust-vectors/check.ts
```

Runs every case through this repo's own reference implementation and confirms the result
matches `expected`.

## Regenerating

```bash
npx tsx chain-of-trust-vectors/generate.ts
```

Deterministic — the same fixed keys and fixed dates produce byte-identical `vectors.json` on
every run.
