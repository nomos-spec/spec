# Contributing to the NOMOS Protocol

Thank you for your interest in improving the NOMOS Protocol specification.

## Governance model

The NOMOS Protocol is maintained by the **NOMOS Protocol Working Group**, currently
administered by SafeHaven LLC. The spec is open for community input via GitHub
Issues and Pull Requests. Major changes (new spec versions, breaking changes to
the artifact format) require Working Group approval.

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
3. If changing a `.nomos` example, re-seal it with the public test key:
   ```bash
   python verify/verify.py examples/your_file.nomos --key deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
   ```
4. Open a PR against `main` — reference the related Issue

## What changes require a new spec version?

| Change type | Requires new spec version? |
|-------------|---------------------------|
| Clarifying ambiguous language | No |
| Adding a new optional field to the schema | No (backward compatible) |
| Adding a new required field | Yes — NOMOS-SPEC-002 |
| Changing the sealing algorithm | Yes — NOMOS-SPEC-002 |
| Removing or renaming a field | Yes — NOMOS-SPEC-002 |
| Changing operator semantics | Yes — NOMOS-SPEC-002 |

## Style guide

- Spec language: use RFC 2119 keywords (MUST, SHOULD, MAY) consistently
- Examples: all `.nomos` files must be valid JSON and must verify against `schema/artifact.schema.json`
- Markdown: ATX headings (`#`), reference-style links, 100-char line limit

## Code of conduct

Be respectful and constructive. This is a technical standards project — focus
on the spec, not the person. Harassment of any kind is not tolerated.

## Questions?

Open a Discussion on GitHub or email allan@nomosprotocol.com.
