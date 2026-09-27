# NOMOS-SPEC-001 Amendment 2.2.0: Unmatched Outcome, Fact Sources, Consent Counts

**Status:** Draft (proposed amendment)
**Version:** 2.2.0 (amends 2.1.0)
**Proposed:** 2026-09-27
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group

---

## Abstract

Version 2.1.0 does not say what a runtime returns when no decision in `logic.decisions`
matches. The reference deployment answers "permit" for public demo artifacts
(`evaluation_model: deny_list`), which is a reasonable choice for a deny-list policy and the wrong
one for authority that must be proven before an action can happen. This amendment makes the
unmatched outcome an explicit, sealed property of each artifact, and adds the two fields
NOMOS-SPEC-008 needs from the artifact: where each fact is allowed to come from, and how many
consents an escalation requires.

All three changes are additive. An artifact valid under 2.1.0 remains valid under 2.2.0.

---

## §3.5 `data_contract` — `source` values (amended)

`data_contract.inputs.<name>.source` is OPTIONAL. When present it MUST be one of:

| Value | The fact may only come from |
|---|---|
| `action` | The parameters of the action being decided (NOMOS-SPEC-008 §7) |
| `testimony` | A signed statement by a witness certified for this fact (NOMOS-SPEC-007 rev. 1.8 §3.4.1) |
| `relying_party` | The deciding system's own state |
| `presenter` | The requester's own assertion |

Runtimes that do not implement NOMOS-SPEC-008 MAY ignore `source`. A NOMOS-SPEC-008 relying party
MUST enforce it and MUST reject facts for inputs that declare none.

Producers SHOULD declare a source for every input, and SHOULD declare `presenter` only for
low-stakes inputs. Declaring sources in the sealed artifact makes the institution's trust model
reviewable: a reader can see, per fact, whose word the rules accept.

## §3.7 `governance.escalations` — `required_consents` (added)

Each escalation object MAY carry `required_consents`, a positive integer, default `1`. It is the
number of distinct approver keys, each holding the escalation's `role_required`, whose consent
satisfies the escalation under NOMOS-SPEC-008 §4.4. Dual control is `required_consents: 2`.

## §4.6 When no decision matches (new, normative)

`logic.resolution` MAY carry:

| Field | Values | Meaning |
|---|---|---|
| `default_outcome` | `allow`, `block`, `escalate` | The outcome when no decision's `when` evaluates true |
| `default_escalation_id` | an escalation `id` | REQUIRED when `default_outcome` is `escalate` |

Rules:

1. A runtime MUST apply `default_outcome` when present. It is part of the sealed payload, so it
   cannot be changed without re-sealing.
2. When `default_outcome` is absent, a runtime implementing only this document MAY keep its
   existing behavior, and MUST report which default it applied (e.g. `outcome_code:
   "NO_MATCHING_RULE"` together with the resulting verdict), so that a permitted-by-default
   result is never presented as permitted-by-rule.
3. A NOMOS-SPEC-008 relying party MUST treat an absent `default_outcome` as `block`.
4. Producers SHOULD set `default_outcome` explicitly on every artifact. For any artifact that
   governs an action with financial, legal, safety or privacy consequences, `block` or
   `escalate` is RECOMMENDED.

**Migration note for the public demo catalog.** Every public demo artifact currently permits
unmatched requests. Under this amendment they should either declare `default_outcome: allow`
explicitly, so the behavior is visible in the sealed file, or move to `escalate`.

## Changelog

- **2.2.0 (proposed)** — `source` values for inputs; `required_consents` on escalations;
  §4.6 unmatched outcome.
