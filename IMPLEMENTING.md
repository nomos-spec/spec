# Implementing NOMOS

This is for anyone building a NOMOS implementation from the specifications, in any language, without
reading ours. NOMOS-SPEC-007 to -010 are Drafts until someone does. Every implementation so far is
by the authors, and a specification is only proven when a stranger can reproduce its verdicts from
the text. If you do, we want to hear about it (see the end).

Everything you need is in this repository: the specification texts, test vectors with
expectations written by hand, mutant sets that check you agree with the reference on cases nobody
wrote by hand, and an HTTP runner that tests a relying party in any language.

## What to build, in order

Each step uses only the ones before it. Stop wherever your product needs: a verifier alone is
useful, and only a relying party needs steps 5 and 6.

| Step | Build | Specification | Check it with |
|---|---|---|---|
| 1 | Canonical JSON (RFC 8785) | NOMOS-SPEC-001 §8.1 | The seal hashes in every vector file: if a hash you compute differs, start here. ECMAScript number output matters: `4.0` is `4`, `1e-7` is `1e-7`. |
| 2 | Signature suites: Ed25519, ES256 (P1363, low-S), WebAuthn-ES256; canonical keys | `spec/drafts/NOMOS-SPEC-010.md` | `suite-vectors/vectors.json` (30). Small-order Ed25519 keys must be refused at load. |
| 3 | Key certificates and chain resolution: target-first, scope-aware, the per-certificate check order | `spec/NOMOS-SPEC-007.md`, `spec/drafts/NOMOS-SPEC-007-rev-1.8.0.md`, `spec/drafts/NOMOS-SPEC-007-rev-1.9.0.md` | `chain-of-trust-vectors/vectors.json` (1.7.0), then `vectors-1.9.json` (37 cases, each in every listed presentation order) |
| 4 | Revocation sources: statements, the authority rule, lists, `as_of` | `spec/drafts/NOMOS-SPEC-007-rev-1.10.0.md` | `chain-of-trust-vectors/revocation-vectors-1.10.json` (22), then agreement on `revocation-mutants-1.10.json` (349) |
| 5 | The Act verifier: envelope, chain, currency, testimony, fact channels and types, three-valued evaluation, consents counted by person | `spec/drafts/NOMOS-SPEC-008.md` (with `NOMOS-SPEC-001-amendment-2.2.0.md` and `-2.3.0.md`) | `act-vectors/vectors.json` (43 plus two non-finite cases built in memory), then agreement on `act-vectors/mutants.json` (1,693) |
| 6 | Discovery, certificate presentation and the HTTP binding | `spec/drafts/NOMOS-SPEC-009.md` | `submission-vectors/selection.json` (7) for a carrier; `submission-vectors/run.mjs` (17 checks over HTTP) for a relying party |

## Running the checks against your implementation

The vector files are plain JSON. Each one's `_readme` says what to compute and what to compare.

- **Hand-written vectors** (`vectors*.json`, `revocation-vectors-*.json`, `selection.json`): compute
  the result and compare every field `expected` names. A field `expected` leaves out must be
  absent from your result too, where the vector's `_readme` says so.
- **Mutants** (`mutants.json`, `revocation-mutants-1.10.json`): each case is one small change to a
  vector, an attacker's or a faulty presenter's, with the reference's verdict. Agreement on all of
  them is the strongest evidence that your reading of the text matches ours. A disagreement means
  one of us misread the specification. Tell us which case: either can be wrong.
- **The relying-party runner** (`submission-vectors/run.mjs`): configure your relying party with
  `profile.json` (its id, the pinned root, one authority, its own fact `vendor_blocked`, a window
  of at least 600 s). Then:
  ```
  cd submission-vectors && npm install
  node run.mjs https://your-relying-party.example
  ```
  It builds fresh Acts from published test keys and speaks only HTTP, so your relying party can be
  in any language.

Our own runs, for comparison:
```
python3 suite-vectors/check.py suite-vectors/vectors.json                                   # 30 passed
python3 chain-of-trust-vectors/python/check_19.py chain-of-trust-vectors/vectors-1.9.json   # 37 passed
python3 chain-of-trust-vectors/python/check_revocations.py chain-of-trust-vectors/revocation-vectors-1.10.json   # 22 passed
python3 act-vectors/check.py act-vectors/vectors.json                                       # 45 passed
node submission-vectors/selection.mjs --check                                               # 7 passed
```

## Rules that are easy to get wrong

These are each a place where two implementations by the authors once disagreed, or where an
implementation passed every vector and was still wrong.

1. **An absent fact is undecided, never false** (NOMOS-SPEC-008 §6.2). A rule that reads a missing
   fact is UNDECIDED. Nothing commits while a block or escalate rule that outranks the result is
   undecided. `exists(f)` is decided by absence only for `action` and `relying_party` inputs.
2. **Wrong-typed operands are undecided too** (§6.2 rule 3). A string compared with `>` is not
   false. A number is not a boolean.
3. **`open_facts` names only the absent operands.** It does not name a present operand beside them
   (vector 43).
4. **Scope-aware path selection** (SPEC-007 rev. 1.9 §4.2a). A candidate path whose scope refuses
   the purpose is a failed candidate. Try the next one, in certificate-fingerprint order.
5. **The seal is checked after the path is chosen** (rev. 1.9 §4.7), so `OUT_OF_SCOPE` is decided
   before `SEAL_INVALID`.
6. **Consents count people, not keys** (SPEC-008 §4.4). Every admitted path to an approver key must
   carry the same `approver`, or the consent is `CONSENT_INVALID` (`approver_ambiguous`).
7. **Small-order Ed25519 keys** (SPEC-010 0.2.0 §3.1). OpenSSL accepts a signature under the identity
   key that verifies against any message. Refuse the key at load.
8. **Low-S** for every ES256 signature, and exactly one base64 encoding of every value (SPEC-010 §2,
   §4).
9. **A revocation counts only from a parent your root reaches** (SPEC-007 rev. 1.10 §5.1a). The
   parent must really have signed the certificate it revokes. Revocations accumulate: a revoked
   parent's earlier statements still count.
10. **Present the closure, not the pool** (SPEC-009 0.2.0 §6.5). An issuer's certificate pool can be
    far larger than the 20 certificates an Act may carry.

## The reference implementations

When a vector disagrees with you, these let you check what we did.

- **Python:** `python/nomosprotocol/` (`pip install nomosprotocol`). The vectors are generated and
  checked with this code.
- **TypeScript:** `@nomosprotocol/verify` on npm. It agrees with the Python reference on every
  vector and every mutant.
- **Independent checkers written from the text alone:** `suite-vectors/check.mjs` (signature
  suites) and `submission-vectors/reference-rp.mjs` (the HTTP binding).

All of them are by the authors of the specifications. That is exactly why yours matters.

## Telling us

Open an issue titled "Implementation report: <language or product>". Include:
- which steps you built;
- which vector files and runners you ran, with your counts;
- every disagreement, with the case name.

Or email allan@nomosprotocol.com. A report with disagreements is as valuable as a clean one:
disagreements are how ambiguities in the text are found and fixed.
