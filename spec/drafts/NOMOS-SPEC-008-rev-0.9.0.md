# NOMOS-SPEC-008 rev. 0.9.0: Intake Questions in an Act

**Status:** Draft (proposed revision)
**Version:** 0.9.0 (amends 0.8.0)
**Proposed:** 2026-11-14
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group
**Defines:** `data_contract.gates` (for NOMOS-SPEC-001 at its next amendment)

---

## Abstract

A sealed authority that encodes a whole statute reads hundreds of facts. A data protection law of
199 rules reads 271, of which a single ordinary act touches a handful; the rest belong to breach
reporting, fines, accreditation and the like. Under 0.8.0 an Act supplies facts one by one, so an
ordinary act under such a law is held `INCOMPLETE` on facts that have nothing to do with it.

Authorities already carry the remedy in their sealed content: **intake questions**
(`data_contract.gates`), each a plain yes/no question whose "no" settles every fact a group of
provisions turns on ("Does this send personal data outside the jurisdiction?"). Implementations
apply them when answering queries; this revision defines them normatively and lets an Act answer
them. Answered, the same law decides an ordinary act in about a dozen answers.

The change is additive: an authority without gates, and an Act that answers none, verify exactly as
under 0.8.0. Every earlier vector and mutant is unchanged.

## Gates (normative)

An authority MAY declare, in `data_contract`:

```jsonc
"gates": {
  "q_cross_border": {
    "question": "Does this send personal data outside the jurisdiction?",
    "source": "presenter",                          // the channel its answer arrives through (§7)
    "when_false": { "transfer_abroad": false }      // the facts a "no" settles, and their values
  }
}
```

| Field | Required | Meaning |
|---|---|---|
| `question` | REQUIRED | The question, in plain words. "No" MUST mean none of the provisions it covers applies to the act. |
| `source` | REQUIRED for use in an Act | The channel its answer arrives through: `action`, `testimony`, `relying_party` or `presenter`. A gate without one cannot be answered in an Act (`undeclared_input`), exactly as an input without one. |
| `when_false` | REQUIRED | Fact name → the value a "no" sets it to. |

The authority is `MALFORMED` (`bad_gates`) when `gates` is not an object; when a gate is not an
object or its `when_false` is not an object; when a gate's name is an input the authority declares,
or `action_type`; or when a `when_false` names another gate.

An issuer SHOULD choose `when_false` values that make every restricting comparison on the fact false,
so that answering "no" can never make a rule deny or escalate. The reference tooling computes them
that way and proves it on the payload before sealing.

## Change to §6–§7: answering a gate (normative)

1. **The answer is a fact.** A gate's answer is supplied under the gate's name, through the channel
   the gate declares, and checked as any fact is (§7): an answer through another channel is
   `FACT_SOURCE_VIOLATION`; a non-boolean answer is `FACT_TYPE_VIOLATION`. Rules never read it.
2. **"No" settles.** After the supplied facts are checked (§7, §7.1) and before the rules are
   evaluated (§6.2), for every gate answered `false`, in order of gate name: each fact in its
   `when_false` takes that value. If that fact was supplied with a different value (compared as JCS),
   or already set by another gate to a different value, the Act is refused
   `FACT_SOURCE_VIOLATION` (`contradicts_gate`, naming the `field` and the `gate`). A settled fact
   takes the gate answer's channel; its own declared source is not consulted.
3. **"Yes", or no answer, settles nothing.** The covered facts arrive through their own channels.
4. **Open questions are named.** An `INCOMPLETE` result for an authority that declares gates
   carries `open_gates`: the names, sorted, of the unanswered gates whose `when_false` names at least
   one of its `open_facts`. A presenter can answer them in a new Act.

## Several laws (0.8.0 §6.3)

Each carried authority applies its own gates, over the facts it declares (its inputs and its gates),
and reports its own `open_gates` in its row of `laws`. A name declared as a gate by two carried
authorities MUST be declared identically by both (question, source and `when_false`), and a name
declared as a gate by one and an input by another is a conflict: either is refused
`FACT_SOURCE_VIOLATION` (`conflicting_declarations`). One answer never stands for two questions.

Under a resolution (§6.4), the gates of a carried authority that does not govern are ignored with its
facts.

## Who answers

The issuer chooses each gate's channel. A gate about the act itself ("Does this send data abroad?")
is naturally the presenter's or the action's; a gate about the relying party's own state ("Is a
security incident open?") the relying party's; a gate whose answer a third party must vouch for, a
witness's. A presenter's answer is a declaration, recorded with the Act and its receipt, not a
proof: where a false "no" would matter, the issuer should declare the gate `testimony` or
`relying_party`, or leave the facts to their own channels.

## Compatibility

- An authority without `gates`, and an Act that answers none, verify exactly as under 0.8.0.
  `vectors.json`, `mutants.json` and `multi-authority-vectors.json` are unchanged.
- An 0.8.0 relying party refuses a gate answer (`undeclared_input`): it fails closed.

## Test

`act-vectors/gate-vectors.json` (generated by `act-vectors/generate_gates.py`, checked by
`act-vectors/check.py`): questions unanswered (named); both answered "no" (authorized); one answered;
an answer contradicted in the same Act; "yes" with the facts denying and allowing; an answer through
the wrong channel; a non-boolean answer; a gate named like a fact (`bad_gates`); and two laws, one
with an open question.

Draft, per the house rule: no interoperability claim until an independent implementation passes
these vectors.
