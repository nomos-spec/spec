# NOMOS-SPEC-001 Amendment 2.5.0: Derived Values — Classifications and Their Legal Relations

**Status:** Draft (proposed amendment)
**Version:** 2.5.0 (amends 2.4.0)
**Proposed:** 2026-11-13
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group

---

## Abstract

Laws define a status and then attach duties to it. Under the EU AI Act, a general-purpose AI model
trained with more than 10^25 floating-point operations is presumed to have high-impact capabilities
(Art. 51(2)). A model with those capabilities has systemic risk (Art. 51(1)(a)) unless the Commission
accepts the provider's arguments that, exceptionally, it does not (Art. 52(2)–(3)). A model the
Commission designates has systemic risk whatever its compute (Art. 51(1)(b)). And a provider of a
model with systemic risk must evaluate it (Art. 55).

A producer writes the classification as a decision whose outcome records the status, and writes the
duties as decisions whose conditions read it. Under 2.4.0 nothing connected the two. The status was
an input, so the person seeking authorisation supplied the fact that decided which duties applied.
A provider who stated "2×10^25 operations" but not "systemic risk" was never held to Article 55, and
anyone could call an Annex III system "not high-risk".

This amendment makes a classification part of the law's logic. Three things are specified:

- how a classification records its legal relations in the sealed artifact;
- how a producer carries the law's classifications into the conditions that read them;
- what a producer must refuse to seal.

No runtime changes. Every decision still carries a `when` string (§4.1), and a NOMOS-SPEC-008
verifier evaluates it exactly as before.

## Change to §4.3 (normative): the classification record

Add after the outcome table:

> **A classification** is an `emit` outcome with `event: "classify"` and a payload:
>
> ```json
> { "type": "emit", "event": "classify",
>   "payload": {
>     "variable":   "<variable name>",
>     "value":      { "lit": <string | number | boolean> },
>     "definition": { "scope": "<the provisions within which this classification is complete>" },
>     "overrides":  ["<decision id>", "..."] } }
> ```
>
> `variable` and `value` are REQUIRED. `definition` and `overrides` are OPTIONAL.
>
> - `overrides` names the other classifications **of the same variable** that this one sets aside:
>   a derogation names the provision it derogates from; an exclusion of a derogation names the
>   derogation.
> - `definition.scope` states that the classifications of this variable carrying it are, together,
>   **every** way the status arises within that scope. A producer MUST NOT state a scope the source
>   does not support. Where completeness is unclear, it is omitted.
>
> Under NOMOS-SPEC-008 §6.0 a classification is an obligation: it takes no part in evaluation or
> resolution. Its effect is carried by the conditions that read the variable (§4.7).

## New §4.7 (normative): derived values

> **4.7.1 Effective classification.** A classification C of variable V is *effective* on a set of
> facts when C's condition holds and no effective classification of V that names C in `overrides`
> holds. Overrides chain: an exclusion of a derogation restores what the derogation set aside.
>
> **4.7.2 Routes.** The law *classifies V as v* when some classification giving v is effective.
> A classification that names others in `overrides` (a derogation) is a route to its value only
> where no effective classification of V giving another value, which it does not name and which does
> not name it, applies. A derogation sets aside only what it names: Art. 6(3) ("by derogation from
> paragraph 2") never makes an Annex I system under Art. 6(1) not high-risk.
>
> **4.7.3 Closed definitions.** Where any classification of a boolean variable V carries
> `definition`, V's definition is **closed**: the law classifies V as `true` exactly where a route
> to `true` applies and as `false` exactly where none does. Within a closed definition the law alone
> decides. A stated value of V adds nothing, and V MUST NOT appear in `data_contract.inputs` when no
> decision reads it after compilation (§4.7.5).
>
> The legally recognised ways into the status, such as a designation by an authority or arguments
> an authority accepted, are classifications like any other. They are written as routes or
> overrides, so closing a definition never shuts them out.
>
> **4.7.4 Presumptions.** Where no classification of V carries `definition`, a stated value still
> counts where the law does not classify V otherwise. A condition `V == v` holds when the law
> classifies V as v, or when V is stated as v and the law does not classify V as any other value.
>
> **4.7.5 Compilation.** A conformant producer MUST rewrite every condition `V == v`, `V != v`,
> `V in "v1,v2"` and `V not_in "v1,v2"` on a variable some classification gives (a *derived variable*)
> into the law's classification under §4.7.1–4.7.4. It expands recursively through chains (compute →
> high-impact → systemic risk). Comparisons of quantities are not rewritten. A cycle of
> classifications (V derived from W, W from V) is not expanded past its first repetition. The result
> is an ordinary `when` string (§4.1).
>
> A producer SHOULD record each definition in `logic.variables` as an expression keyed `V` (the
> condition under which the law classifies V as `true`) or `V=v` (any other value). A runtime MUST
> NOT require these entries. They explain the chain, and no verdict depends on them.
>
> Compiling an artifact again (a fork, an extension, a re-composition per NOMOS-SPEC-004) MUST yield
> the same `when` strings. A producer recognises conditions it already expanded, and reads each
> classification's relations back from its payload.
>
> An extension's inherited decision that the extender did not change is the publisher's sealed
> decision. It is kept exactly as sealed, not recompiled (NOMOS-SPEC-004).
>
> **4.7.6 What a producer MUST refuse to seal**, for any derived variable a decision reads:
> - two classifications of V that give different values, neither naming the other in `overrides`,
>   that can both hold on some set of facts (a producer MAY treat two conditions as exclusive only
>   when one requires a fact the other requires to have a different value);
> - a name in `overrides` that is not another classification of the same variable;
> - a cycle of `overrides`.
>
> Precedence between classifications is a legal relation the source states. It is never inferred
> from `priority` or from order. An extension is not refused for its publisher's unchanged
> decisions.

## Change to §4.1 (normative): negation is three-valued

Add after the paragraph on arithmetic:

> `not X` holds only when X is false on the facts given. When X is undecided because a fact it reads
> is absent, `not X` is undecided too, as under NOMOS-SPEC-008 §6.2. A runtime MUST NOT read an
> absent fact as false beneath a negation. Under that reading, a decision such as "open-source
> systems that are not high-risk are excluded" fired before anyone had said whether the system
> profiles people.

## Compatibility

- **Artifacts.** An artifact whose classifications carry no `definition` or `overrides` compiles as
  2.4.0 described, apart from §4.7.4: a dependent condition now also holds when the law classifies
  the variable, even if nobody stated it.
- **Runtimes.** No runtime change is needed for §4.3 and §4.7. Both are producer-side, and the
  payload fields are ignored by NOMOS-SPEC-008 evaluation.
- **Callers of a closed definition.** The variable is no longer an input. A SPEC-008 Act that
  carries it is refused as `undeclared_input` (§7), because a presenter cannot assert what the law
  decides. Callers supply the facts the definition's routes read.
- **Negation (§4.1).** This changes the verdict of a non-conformant runtime that read absent facts
  as false beneath `not`. SPEC-008 verifiers already read negation three-valued.

## Test

In the reference deployment:

- `scripts/test-derived-facts.ts`: chains, relations (a derogation sets aside only what it names,
  exclusions of derogations), closed definitions, presumptions, the payload round trip from
  extraction answer to sealed artifact and back, idempotent recompilation, extensions, the three
  refusals, and three-valued `not`. The server evaluator and `@nomosprotocol/verify` must agree.
- `scripts/test-eu-legal-answer-key.ts`: the EU AI Act's Art. 6 and Art. 51–52 classifications
  against a 26-case answer key, in both evaluators. The key is marked `unreviewed` until a qualified
  reviewer signs it off. Passing shows the sealed law gives the key's answers, not that the key is
  right.

An independent producer conforms when, for the same classifications and relations, it seals
conditions that decide every case of both tests identically.
