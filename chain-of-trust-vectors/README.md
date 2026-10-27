# NOMOS-SPEC-007 interop test vectors

**Status:** the pure references (`../prototype/chain-of-trust/`, `../python/nomosprotocol/chain.py`)
and the hosted platform's verifier pass every case in `vectors.json`; the platform does not yet
implement rev. 1.9 (see below). These vectors are the test a second-party
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

## Rev. 1.9 vectors

`vectors-1.9.json` — 37 cases for NOMOS-SPEC-007 rev. 1.9
(`../spec/drafts/NOMOS-SPEC-007-rev-1.9.0.md`), generated deterministically in Python
(`generate_19.py`, keys from published seeds, RFC 6979 ECDSA). Every `expected` value is written
by hand from the text. Each case lists the presentation `orders` it must give the same answer in,
and has one of two purposes:

- `artifact`: resolve `seal.kid` and verify the seal (§4);
- `statement`: resolve a witness or approver key for a `claim` or `consent` statement under a
  given suite (§4.6).

The cases cover:
- scope-aware path selection, including the R-19 §5.6 example exactly;
- tree-shaped pools in every order;
- ES256 and mixed chains and seals, high-S, compressed keys and suite/key mismatch;
- the `suite` dimension (passkeys can approve and nothing else);
- the `approver` dimension.

A verifier compares `decision`, `reason_code`, `dimension`, `path`, `effective_scope` and
`revoked_kid`. A field absent from `expected` must also be absent from the result.

```bash
python3 chain-of-trust-vectors/python/check_19.py chain-of-trust-vectors/vectors-1.9.json   # Python reference
npx tsx chain-of-trust-vectors/check-1.9.ts                                                 # TypeScript prototype
python3 chain-of-trust-vectors/generate_19.py > chain-of-trust-vectors/vectors-1.9.json     # byte-identical
```

Both pass all 37, in all 91 listed orders. On every artifact verdict in both vector files they
agree on nine fields. A mutant that checks scope only after choosing a path (the rev. 1.8
behaviour) fails exactly the two scope-aware selection cases. Both implementations are by the
authors, so neither is independent. The rev. 1.9 call for an independent implementation stands.

The hosted platform now verifies through `@nomosprotocol/verify`, which implements rev. 1.9 and
passes all 37 cases in every listed order; it no longer selects paths without regard to scope.

## Regenerating

```bash
npx tsx chain-of-trust-vectors/generate.ts
```

Deterministic — the same fixed keys and fixed dates produce byte-identical `vectors.json` on
every run.
