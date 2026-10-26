# NOMOS-SPEC-001 Amendment 2.3.0: Unambiguous Escalation

**Status:** Draft (proposed amendment)
**Version:** 2.3.0 (amends 2.2.0)
**Proposed:** 2026-10-26
**Implements:** RFC-0001 change 7
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group

---

## Abstract

When two `escalate` decisions of equal `priority` both apply and name different escalations, the
first one listed governs (NOMOS-SPEC-008 0.5.0 §6.2). The rule is deterministic and sealed, so a
presenter cannot exploit it. It does carry an authoring hazard (R-19 §7.5): an institution that
happens to list its dual-approval rule second gets single approval whenever both rules apply. A
reviewer reading the two rules sees no difference in rank between them.

This amendment makes the ambiguous form unsealable, so the author resolves it at the point where
a human already reviews the authority.

---

## §4.2 Decisions — unambiguous escalation (new, normative)

A producer MUST NOT seal an artifact in which two decisions:
- have `then[0].type` equal to `escalate`;
- have equal `priority`;
- name different `escalation_id` values.

The author resolves the ambiguity by giving the two decisions distinct priorities, so the
escalation that should govern when both apply outranks the other.

A relying party evaluating such an artifact for a **new authorization** MUST reject it as
`MALFORMED`, reason `ambiguous_escalation` (NOMOS-SPEC-008 0.6.0 §6 step 5b). Historical
verification of decisions made under an artifact sealed before this amendment is unaffected. The
two questions are kept apart exactly as NOMOS-SPEC-008 §5.4 keeps them apart for supersession.

Two equal-priority `escalate` decisions that name the *same* escalation are not ambiguous and
remain valid.

## Producer lint

A producer SHOULD run the check above as a sealing gate, reported with the two decision ids and
their shared priority. In the reference platform this is the `AMBIGUOUS_ESCALATION` error of
`scripts/lint-artifact.ts`, which runs `--strict` before publication.

## Compatibility

Additive for producers. It is breaking for any sealed artifact that contains the pattern, and
then only for new authorizations. Before this amendment we checked, read-only, the platform's 139
repository artifacts, its 5 public demonstration authorities and its EU AI Act authority (851
rules). None contains the pattern (R-19 §7.5).

## Changelog

- **2.3.0 (proposed)** — Two `escalate` decisions of equal priority naming different escalations
  cannot be sealed, and are refused for new authorizations.
