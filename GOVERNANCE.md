# Governance: the NOMOS Protocol Working Group

The NOMOS Protocol is maintained by the **NOMOS Protocol Working Group**. SafeHaven LLC administers
it: it holds this repository, its settings and the publication of every specification. The Working
Group is where the people who implement the specifications have a voice in how they change.

## Who holds a seat

A seat is earned by work that the specifications can check, not by affiliation:

- **An independent implementation.** You built, without copying or wrapping this repository's
  reference code, an implementation that passes every published vector of a specification, in your
  own public CI. This is the same bar that takes a specification out of Draft
  ([CONTRIBUTING.md](CONTRIBUTING.md#how-a-specification-advances)).
- **A substantial accepted contribution.** A change to a specification, its vectors or its proofs
  that was merged and changed what a conforming implementation must do (for example, an erratum that
  closed a gap a vector now tests).

## What a seat means

- **A voice on advancement.** Before a specification moves between Draft, Active and Deprecated, the
  members are asked, and their views are recorded in the change.
- **Review of what you built on.** You are asked to review changes to the specifications and vectors
  your work rests on.
- **Credit.** You are listed below, with what earned the seat.

A seat does not give the right to merge, to change repository settings, or to publish a
specification; those stay with the administrator. No member holds or manages any seal key
([SECURITY.md](SECURITY.md)). Members speak for themselves, not for the Working Group, unless the
Working Group has agreed a statement.

## How a seat is granted

1. Open an issue titled **Working Group seat request**, saying what you built or changed, with links
   (the implementation and its passing CI run, or the merged change).
2. The administrator checks it against the criteria above and answers on the issue.
3. If granted, the member is added to the table below in a pull request, with the date and the basis,
   and invited to the `working-group` team of the `nomos-spec` organisation with Triage access
   (label, review and comment; not merge).

A seat ends when a member steps down, or after twelve months with no review, comment or contribution,
on notice. The record of what earned it stays in this file's history.

## Members

| Member | Since | Basis | Area |
|--------|-------|-------|------|
| SafeHaven LLC (Allan Sendagi) | 2026-01-15 | Administrator; author of the specifications | All |
| [SvvBot](https://github.com/SvvBot) | 2026-11-13 | Independent NOMOS-SPEC-014 resolver ([SvvBot/nomos-spec014-resolver](https://github.com/SvvBot/nomos-spec014-resolver)) passing every published 0.3.0 vector and all eight necessity ablations; the first exit from Draft ([#40](https://github.com/nomos-spec/spec/pull/40)) | NOMOS-SPEC-014 Resolution |
