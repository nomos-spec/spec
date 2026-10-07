# NOMOS-SPEC-007 Revision 1.8.0: Statement Keys, Target-First Resolution

**Status:** Draft (proposed revision)
**Version:** 1.8.0 (revises 1.7.0)
**Extends:** NOMOS-SPEC-001 v2.2.0
**Proposed:** 2026-09-27
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group

---

## Abstract

Version 1.7.0 answers one question: *why should a relying party trust the key that sealed this
artifact?* This revision extends the same certificate machinery to two further kinds of signed
statement that an authority decision depends on:

- **testimony** — a signed assertion of a fact (a credit score, a leave balance), and
- **consent** — a signed human approval of one specific act.

It does so without a new trust object. A key is authorized to testify, or to consent, exactly
the way a key is authorized to seal: by a certificate chain to the relying party's pinned root,
whose accumulated scope says what that key may sign. Two new scope dimensions, `claim` and
`consent`, carry that permission.

This revision also corrects the chain walk of §4.2. The 1.7.0 walk resolves root-first and takes
the first certificate whose parent matches; that is order-independent only when the presented
certificates form a single path. Once a presentation carries certificates for several statement
keys (the normal case under NOMOS-SPEC-008), the certificates form a tree and the 1.7.0 walk can
return `ISSUER_NOT_RECOGNIZED` for a key that is validly certified, depending on the order the
certificates arrived in. §4.2a replaces it with target-first resolution.

Everything in 1.7.0 not named here is unchanged.

---

## Changes at a glance

| Section | Change |
|---|---|
| §3.4 | Adds the `claim` and `consent` dimensions and their set-valued grammar |
| §3.4.1 (new) | Statement scope: what a `claim` or `consent` key may sign, and what it may not |
| §3.5 (new) | Key purpose: a key certified for statements cannot seal rules, and vice versa |
| §4.2a (new, replaces §4.2 walk) | Target-first resolution over an unordered set that may be a tree |
| §4.3 | Invariant restated for tree-shaped presentations |
| §4.6 (new) | Resolving a chain for a statement other than an artifact |
| §8.2 | Known-gap list updated |
| Appendix A | Demonstration of the 1.7.0 ordering defect |

---

## §3.4 Scope — additional dimensions

Add to the dimension table:

| Dimension | Value | Narrowing | Matched against |
|---|---|---|---|
| `claim` | Comma-separated set of fact names, e.g. `claim:credit_score,dti_ratio` | Subset: a child's set MUST be a subset of its parent's | The `claim` field of a testimony statement (NOMOS-SPEC-008 §3) |
| `consent` | Comma-separated set of role identifiers, e.g. `consent:SENIOR_APPROVER` | Subset | The `role` field of a consent statement (NOMOS-SPEC-008 §4) |

Fact names use the NOMOS-SPEC-001 §4.4 field-path syntax. Role identifiers are the `role_id`
values of the authority artifact's `governance.roles`. Neither dimension admits wildcards: a
witness trusted for "all facts" does not exist in this protocol, by design.

The existing grammar rules continue to apply unchanged: a dimension appears at most once per
certificate, a malformed scope is rejected rather than partially parsed, and a certificate that
widens a dimension its parent constrains fails the path with `OUT_OF_SCOPE`.

**Compatibility.** A 1.7.0 verifier that meets a `claim` or `consent` term does not recognize
the dimension and, per §3.4's existing fail-closed rule, returns `OUT_OF_SCOPE`. Older verifiers
therefore reject statement keys; they never silently accept them.

## §3.4.1 Statement scope (new, normative)

A key's **effective scope** is the accumulated scope along its resolved path (§3.4, unchanged).

1. A testimony statement for fact `f` is in scope if and only if the signing key's effective
   scope contains a `claim` term whose set includes `f`. A key with no `claim` term — including a
   key with *unrestricted* scope — MUST NOT be accepted as a witness for any fact.
2. A consent statement for role `r` is in scope if and only if the signing key's effective scope
   contains a `consent` term whose set includes `r`. A key with no `consent` term MUST NOT be
   accepted as an approver.
3. The artifact-matching dimensions (`artifact`, `industry`, `jurisdiction`) MAY also appear on a
   statement key's path. For a statement, they are matched against the authority artifact of the
   act the statement is presented with (NOMOS-SPEC-008 §2), using the §3.4 comparison rules. This
   lets an institution certify a witness for one policy, one industry or one jurisdiction only.
4. Any other dimension on a statement key's path — including `consent` on a key presenting
   testimony, or `claim` on a key presenting consent — fails the statement closed.

Rule 1 is the point of this revision. Unrestricted scope means *unrestricted authority to issue
rules*. It does not mean authority to state facts. The party that writes the rules and the parties
permitted to testify to the facts those rules read are separated by construction; an issuer that
is also a legitimate source of some facts (an HR system attesting leave balances under its own
institution's leave policy) receives a separate, `claim`-scoped key for that purpose.

## §3.5 Key purpose (new, normative)

A key whose effective scope contains a `claim` or `consent` term is a **statement key**. When a
verifier resolves a chain for an *artifact* (§4, unchanged purpose) and the sealing key's effective
scope contains either term, the verifier MUST return `OUT_OF_SCOPE` with the offending dimension.
A statement key cannot seal rules; a sealing key cannot testify or consent (§3.4.1 rules 1–2).

## §4.2a Target-first resolution (new, normative; replaces the §4.2 walk)

The presented `key_certs` are an unordered set that MAY contain certificates for several keys:
the artifact's sealing key, and each witness and approver key that signed a statement presented
alongside it. Such a set is generally a tree, not a path.

To resolve key `T` against pinned root `R`, a verifier MUST:

1. If `kid(R)` has been revoked (§5), return `KEY_REVOKED`.
2. Enumerate candidate paths **from `T` toward `R`**: the candidate parents of a key `K` are the
   certificates in the set whose `child_kid` equals `K`. Recurse on each candidate's `parent_kid`
   until `kid(R)` is reached. A key already on the current path MUST NOT be revisited (cycle), and
   a path longer than 20 certificates MUST be abandoned (§4.5).
3. Try candidate certificates in ascending order of their §5.4 fingerprint, so the first path
   tried never depends on presentation order.
4. Validate each candidate path root-first with the unchanged §3.3 per-certificate checks, the
   §5.4 certificate-revocation check and the §5.2 key-revocation check at every hop.
5. The first path that validates resolves `T`. Its hops determine the effective scope.
6. If no path validates, return the failure of the first path tried (in step-3 order). If no
   structural path exists at all, return `ISSUER_NOT_RECOGNIZED` with reason `chain_broken` when
   the set contains at least one certificate issued by `R`, and `no_certificate_for_root`
   otherwise.

For a presentation that forms a single path, §4.2a and the 1.7.0 walk return the same verdict.

## §4.3 Order independence (restated)

A relying party presented the same certificate set in any order MUST reach an identical verdict
**for every key it resolves from that set**, including when the set is a tree. The 1.7.0 walk
meets this only for single-path sets (Appendix A); §4.2a meets it for all sets.

## §4.6 Resolving a chain for a statement (new, normative)

A testimony or consent statement is resolved exactly as an artifact is, with three substitutions:

| Artifact (§4) | Statement (§4.6) |
|---|---|
| target key: `seal.kid` | target key: the statement's `kid` |
| final check: the artifact's seal (NOMOS-SPEC-001 §8) | final check: the statement's own signature (NOMOS-SPEC-008 §3.2, §4.2) |
| scope matched per §3.4 | scope matched per §3.4.1 |

Statement resolution failures are reported by the calling specification (NOMOS-SPEC-008 §6) as
`TESTIMONY_INVALID`, `TESTIMONY_OUT_OF_SCOPE`, `CONSENT_INVALID` or `CONSENT_OUT_OF_SCOPE`, never
as the artifact-level `ISSUER_NOT_RECOGNIZED`: an unrecognized witness and an unrecognized rule
issuer call for different remedies.

## §8.2 Known gaps (updated)

- **Implementations of §4.6.** The statement resolution in this revision is implemented in
  `act-vectors/act_verify.py` and in the hosted platform's verifier, both by the authors, and
  exercised by twenty-four test vectors (`act-vectors/vectors.json`). The same disclosure as
  1.7.0 §8.2 applies.
- **Earlier-revision verifiers remain vulnerable to the §4.2 ordering defect** on tree-shaped
  sets. A presenter can avoid triggering it by sending one artifact's path only, but a relying
  party that accepts NOMOS-SPEC-008 acts MUST implement §4.2a.
- **Witness quality is out of scope.** Certification says a key *may* testify to a fact. Whether
  that witness is accurate is a governance question for whoever issues the certificate.

---

## Appendix A — The 1.7.0 ordering defect (non-normative)

Take a certificate set with one root and two children: the policy issuer and a credit-bureau
witness. Resolve the issuer's sealing key with the 1.7.0 walk.

- Presented as `[root→issuer, root→bureau]`: the walk takes `root→issuer` first and resolves.
  Verdict `ALLOWED`.
- Presented as `[root→bureau, root→issuer]`: the walk takes `root→bureau` first (its parent
  matches), finds no certificate issued by the bureau, and stops. Verdict
  `ISSUER_NOT_RECOGNIZED`, reason `chain_broken`.

Same certificates, same root, different verdict. This was reproduced by running the Python
SPEC-007 verifier (`chain-of-trust-vectors/python/verify_chain.py`, written from the 1.7.0 text)
against NOMOS-SPEC-008 vectors `authorized_by_rule` and `tree_pool_presented_in_reverse`. Under
§4.2a both resolve.

## Changelog

- **1.8.0 (proposed)** — `claim` and `consent` scope dimensions; statement scope and key purpose;
  target-first resolution replacing the §4.2 walk; §4.3 restated for trees; §4.6 statement
  resolution; §8.2 updated.
