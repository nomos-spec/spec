# NOMOS-SPEC-008 rev. 0.8.0: An Act Under Several Laws

**Status:** Draft (proposed revision)
**Version:** 0.8.0 (amends 0.7.0)
**Proposed:** 2026-11-14
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group
**Uses:** NOMOS-SPEC-014 (Resolution)

---

## Abstract

An Act carries one authority (§2). NOMOS-SPEC-014 lets a relying party work out every authority
that governs an act from registrars it pins, and requires every one of them to be satisfied
(SPEC-014 §4). Under 0.7.0 an act governed by two laws could therefore never commit: whichever law
the presenter carried, the other was not presented. A DIFC firm acting in mainland Dubai, governed
by DIFC and UAE data protection law at once, could be refused correctly but never authorized.

This revision lets one Act carry several authorities. The change is additive: an Act with no
further authorities is unchanged, verifies exactly as under 0.7.0 and has the same binding digest,
so every 0.7.0 vector and mutant is unaffected. The presenter still carries every proof; the
relying party still decides alone.

## Change to §2: further authorities (normative)

Add an OPTIONAL field:

```jsonc
"further_authorities": [
  { "artifact": { /* sealed .nomos */ }, "in_force": { /* OPTIONAL, §5.5 */ } }
]
```

| Field | Required | Meaning |
|---|---|---|
| `further_authorities` | OPTIONAL | Further sealed artifacts this Act acts under, in addition to `authority.artifact`. When present it MUST be a non-empty array of at most 7 entries, each with an `artifact`. |

`authority.key_certs` remains the one certificate pool for the whole Act: every key whose
statement is in the Act, for every carried authority (the pool limit of NOMOS-SPEC-007 rev. 1.9
§4.5 applies to it as a whole). Testimony and consents remain single lists, shared by all carried
authorities.

The **carried authorities** are `authority` followed by each entry of `further_authorities`. Two
carried authorities with the same `seal.hash`, or the same `meta.artifact_id`, make the Act
`MALFORMED` (`duplicate_authority`). Order carries no meaning.

## Change to §4.3: the binding digest (normative)

When `further_authorities` is present, `binding_core` gains one member:

```
artifact_hashes: the seal.hash of every carried authority, sorted
```

When it is absent, `binding_core` is exactly as in 0.7.0. An approval is thereby bound to the exact
set of laws it was given under: it cannot be lifted onto an Act that adds or drops one.

## New §6.3: verification under several authorities (normative)

Steps 1–4 of §6 (envelope, audience, window, replay) are checked once for the Act. Then:

1. **Each carried authority** is checked as §6 step 5 and §5.4–5.5 check the one authority today
   (chain to the pinned root, seal, revocation, currency, unambiguous escalations). The first
   failure decides the Act, reported with that authority's `artifact_id`.
2. **Which authority reads a fact.** An authority reads exactly the inputs its `data_contract`
   declares. Every fact the Act supplies, through any channel (§7), MUST be declared by at least
   one carried authority, or the Act is refused `FACT_SOURCE_VIOLATION` (`undeclared_input`). Where
   two carried authorities both declare a fact, their declared `source` and `type` MUST be equal;
   otherwise the channel would depend on which law is read, and the Act is refused
   `FACT_SOURCE_VIOLATION` (`conflicting_declarations`). Each supplied fact is then checked against
   its declaration as §7 and §7.1 require.
3. **Testimony** is verified once (§3.3: signature, window, subject). Its key MUST be admitted
   (§3.3 item 2) under every carried authority that declares the statement's `claim`.
4. **Evaluation.** Each carried authority's rules are evaluated, three-valued (§6.2), over exactly
   the facts it declares, as under 0.7.0.
5. **Consents** are checked as §4.4 requires: every consent presented is validated (resolution,
   signature, binding digest) under each carried authority whose escalation requires its `role`,
   or under `authority` when none does. For each authority that returns `ESCALATED`, consents are
   counted against that authority's own escalation (`role_required`, `required_consents`). Two
   authorities that both escalate are satisfied separately.
6. **The verdict** combines the authorities' outcomes, by the rule NOMOS-SPEC-014 §4 uses for a
   resolved set:
   - `DENIED` if any authority denies;
   - otherwise `INCOMPLETE` if any authority is undecided (no consent stands in for a missing fact);
   - otherwise `ESCALATED` if any escalation is not yet satisfied;
   - otherwise `AUTHORIZED`, and the Act commits.

   The result lists each authority's own outcome (`laws`: `artifact_id`, `decision`, `rule`, and
   for an escalation the consents counted and required), so the presenter can see which law
   withheld the act and why.

## New §6.4: under a resolution (normative)

A relying party that resolves the applicable set 𝒜 under NOMOS-SPEC-014:

1. evaluates **exactly** the carried authorities that are members of 𝒜. A carried authority outside
   𝒜 is verified for shape only and otherwise ignored, and so are the facts and testimony only it
   declares: they are neither checked nor evaluated. A presenter cannot change the verdict by adding
   a law that does not govern the act. Its seal hash stays in the binding digest.
2. holds the Act `INCOMPLETE` (`laws_not_presented`), naming the missing members, when a member of
   𝒜 is not carried. Nothing is committed.
3. holds the Act `INCOMPLETE` (`law_not_accepted`), naming the member, when a member of 𝒜 is one the
   relying party does not accept (it has no configuration to verify it). This is the relying
   party's gap, not the presenter's: a presenter MUST NOT retry it by gathering more proof.

Without a resolution, every carried authority is evaluated.

## Presenters

A presenter that receives `laws_not_presented` MAY assemble a new Act carrying the named
authorities as `further_authorities`, gathering their testimony and consents, with a fresh nonce,
and submit it. It SHOULD do so at most once per action, and SHOULD stop on any other refusal.

## Compatibility

- An Act without `further_authorities` is unchanged in every respect, including its binding
  digest. `act-vectors/vectors.json` and `act-vectors/mutants.json` are unchanged.
- A 0.7.0 relying party that receives `further_authorities` ignores a field it does not know and
  evaluates `authority` alone, exactly as it would today: it does not know the act is governed by
  more than one law. Where consents are needed they do not verify there (the binding digest
  differs), so such an Act fails closed (`CONSENT_INVALID`, `binding_mismatch`). A relying party
  that resolves the applicable set (NOMOS-SPEC-014) MUST implement this revision.

## Test

`act-vectors/multi-authority-vectors.json` (generated by `act-vectors/generate_multi.py`, checked
by `act-vectors/check.py`): two laws allowing; one denying; one undecided; a fact undeclared by
both; conflicting declarations; a duplicate law; per-law consents, one law satisfied and the other
not; a consent lifted from a one-law Act; and the binding digest of a one-law Act unchanged.

Draft, per the house rule: no interoperability claim until an independent implementation passes
these vectors.
