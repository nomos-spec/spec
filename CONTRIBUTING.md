# Contributing to the NOMOS Protocol

Thank you for your interest in improving the NOMOS Protocol specification.

## Governance model

The NOMOS Protocol is maintained by the **NOMOS Protocol Working Group**, currently
administered by SafeHaven LLC. The spec is open for community input via GitHub
Issues and Pull Requests. Major changes (new spec versions, breaking changes to
the artifact format) require Working Group approval.
Who holds a seat, what it means and how to request one: [GOVERNANCE.md](GOVERNANCE.md).

## Types of contributions

### Bug reports and clarifications
Open a GitHub Issue using the **Bug Report** template. Suitable for:
- Ambiguous or contradictory spec language
- Errors in examples or schemas
- Bugs in the reference verifiers

### Spec change proposals
Open a GitHub Issue using the **Spec Change Request** template before opening a PR.
This allows the Working Group to assess scope and backward compatibility before
implementation work begins.

### Pull requests
1. Fork the repo and create a branch: `git checkout -b fix/your-description`
2. Make your changes
3. If changing a `.nomos` example, re-seal it with the public test key, then check it:
   ```bash
   node scripts/seal-example.mjs examples/your_file.nomos
   python verify/verify.py examples/your_file.nomos --key deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
   ```
4. If the change alters what a verifier must conclude, add or change vectors through the folder's
   generator (never by hand-editing the JSON) and commit the regenerated file; CI requires every
   generator to reproduce its committed file byte for byte.
5. Run the checks CI runs (the list is in the README under **Conformance**); at least
   `node scripts/check-links.mjs` and `node scripts/check-spec-index.mjs`.
6. Open a PR against `main` — reference the related Issue

## How a specification advances

| Status | Meaning |
|--------|---------|
| **Draft** | Published for implementation and review. May change in response to implementers; every change is versioned and recorded in `CHANGELOG.md`. NOMOS-SPEC-007 onward stay Drafts until an independent implementation (not by the authors) passes their vectors (SPEC-007 §8, SPEC-008 §10). |
| **Active** | Stable. Changes are backward compatible, or take a new specification number. |
| **Deprecated** | Superseded; kept so older artifacts and decisions stay verifiable ([DEPRECATION.md](DEPRECATION.md)). |

Larger amendments and revisions may be proposed in `spec/drafts/` first, then folded into the
specification itself when accepted. Implementation reports are as welcome as
text changes: tell us which vector files your implementation passes, in an issue or a Discussion,
and it will be listed in the README.

## What changes require a new spec version?

| Change type | Requires new spec version? |
|-------------|---------------------------|
| Clarifying ambiguous language | No |
| Adding a new optional field to the schema | No (backward compatible) |
| Adding a new required field | Yes — a new spec number ([DEPRECATION.md](DEPRECATION.md)) |
| Changing the sealing algorithm | Yes — a new spec number ([DEPRECATION.md](DEPRECATION.md)) |
| Removing or renaming a field | Yes — a new spec number ([DEPRECATION.md](DEPRECATION.md)) |
| Changing operator semantics | Yes — a new spec number ([DEPRECATION.md](DEPRECATION.md)) |

## Style guide

- Spec language: use RFC 2119 keywords (MUST, SHOULD, MAY) consistently
- Examples: all `.nomos` files must be valid JSON and must verify against `schema/artifact.schema.json`
- Markdown: ATX headings (`#`), reference-style links, 100-char line limit

## Code of conduct

Be respectful and constructive. This is a technical standards project — focus
on the spec, not the person. Harassment of any kind is not tolerated. The full
code of conduct, and how to report a problem, is in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Questions?

Open a [Discussion](https://github.com/nomos-spec/spec/discussions) on GitHub or email allan@nomosprotocol.com.
