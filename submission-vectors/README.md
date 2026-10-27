# NOMOS-SPEC-009 conformance

Checks a relying party's HTTP behaviour against [NOMOS-SPEC-009](../spec/drafts/NOMOS-SPEC-009.md): discovery, the
status for every verdict, idempotency, resubmission with consent, and the transport rules. It only
speaks HTTP, so the relying party can be written in any language.

```
npm install
node reference-rp.mjs 4801 &          # a reference relying party (optional)
node run.mjs http://localhost:4801    # or your own relying party, configured with profile.json
```

| File | What it is |
|---|---|
| `profile.json` | What the relying party under test is configured with: its id, the pinned root, one authority (record currency, in-force seal hash), its own fact `vendor_blocked`, a window of at least 600 s. Deterministic (`node profile.mjs`). |
| `run.mjs` | The runner. It builds fresh Acts from the published test keys and checks 17 behaviours. |
| `reference-rp.mjs` | A minimal relying party on `@nomosprotocol/verify` alone, sharing no code with `@nomosprotocol/sdk`. |
| `status.json` | The status for every SPEC-008 verdict (§6.2). |
| `selection.json` | Certificate selection (0.2.0 §6.5): for each case, the certificates a carrier has and the kids its Act relies on, and the closure it must present, as sorted fingerprints. `node selection.mjs --check` runs the reference closure against it; `node selection.mjs > selection.json` regenerates it byte for byte. The expected sizes were checked by hand. |
| `keys.mjs` | The test keys, policy and statement builders shared by the three scripts. |

Two relying parties pass all 17: `reference-rp.mjs`, and `accept()` from `@nomosprotocol/sdk`. They were written separately but share `@nomosprotocol/verify`, so they test the submission binding independently, not the verifier. The keys are
derived from published seeds: never use them as trust material.
