# NOMOS-SPEC-007 interop test vectors

**Status: unverified by any second implementation.** These vectors exist so a real, independent
implementer has something concrete to check their own verifier against — they are not a claim
that interoperability has been demonstrated. As of publishing, exactly one implementation
(`../prototype/chain-of-trust/`, this repo's own reference implementation) has ever produced or
checked these vectors — confirmed self-consistent by `check.ts` (below), which is a different
and much weaker claim than two independent implementations agreeing on the wire format. This
file says so rather than implying otherwise with a green checkmark that wouldn't mean anything
yet.

## What's here

`vectors.json` — eleven cases, each an `{ artifact, key_certs, expected }` triple, plus a shared
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

The private keys used to generate these fixtures (`generate.ts`) are published in the clear on
purpose — they exist only to make the vectors regenerable and auditable, and must never be
treated as real trust material by anything that finds them.

## How to use these

If you're implementing NOMOS-SPEC-007 independently: run each case's `artifact` + `key_certs`
against your implementation, using `root_public_key_pem` as the pinned root and `check_at` as
the evaluation time, and confirm your verdict matches `expected`. If it does, that's real
evidence — open an issue or a PR at this repo noting which implementation you ran and what
matched. Until that happens, treat this as validated against its own reference implementation
only.

## Verifying self-consistency

```bash
npx tsx chain-of-trust-vectors/check.ts
```

Runs every case through this repo's own reference implementation and confirms the result
matches `expected` — proof the vectors aren't simply wrong, not proof of interoperability.

## Regenerating

```bash
npx tsx chain-of-trust-vectors/generate.ts
```

Deterministic — the same fixed keys and fixed dates produce byte-identical `vectors.json` on
every run.
