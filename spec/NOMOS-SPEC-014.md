# NOMOS-SPEC-014: Resolution

**Status:** Active
**Version:** 0.3.0
**Proposed:** 2026-11-11
**Revised:** 2026-11-12 (0.2.0: closure agreement, view age, the C7 attack restated; see §10)
**Active since:** 2026-11-13 — a second, independent resolver passed every published vector (§10)
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group
**Uses:** NOMOS-SPEC-001, NOMOS-SPEC-006, NOMOS-SPEC-007, NOMOS-SPEC-008, NOMOS-SPEC-013

---

## Abstract

Every specification so far answers questions about a **given** authority: is it genuine
(NOMOS-SPEC-007), does it permit this exact act on these facts (NOMOS-SPEC-008), where is it
published (NOMOS-SPEC-013). The authority is an input, supplied by the same adversarial carrier
those specifications otherwise disarm. This specification defines the function before all of
them:

> **R(context, t)** — which authorities govern an act in a context at a time, with evidence that
> the enumeration is complete relative to the registrars the relying party pinned.

Without it, a carrier complies with one convenient authority and stays silent about the one that
would refuse — every presented artifact genuine, every prior specification satisfied, the wrong
complete before verification begins. §8 names this attack (*applicability hiding*) and its three
siblings; each is a published vector in [`resolution-vectors/`](../resolution-vectors/).

Out of scope, deliberately: ordering sovereigns whose claims conflict (surfaced, never settled —
§5.3), interpretation of what an authority's rules mean, and who may operate shared resolution
roots (the NOMOS-SPEC-007 §9 governance question, inherited here in stronger form).

This specification left Draft on 2026-11-13, when a second, independent resolver —
[`SvvBot/nomos-spec014-resolver`](https://github.com/SvvBot/nomos-spec014-resolver) (Python,
standard library only), built from this text and the published vectors with no involvement of
the authors — passed every published vector and every necessity ablation on its own CI. The key
words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119.

## 1. Terminology

- **Registrar:** a party that makes applicability claims and closure statements over a scope it
  is certified for. The machine form of the gazette office.
- **Scope:** a predicate over context fields, written in the NOMOS-SPEC-008 §6 condition grammar
  (comparisons of a field with a value; `and` / `or` / `not`; no field-to-field arithmetic).
  The literal `always` covers every context.
- **Context:** the properties that attach law to an act. The v0 vocabulary is `jurisdiction`,
  `action_type`, `sector`, `party_role`; a registrar MUST NOT assume fields outside the
  vocabulary it publishes.
- **Applicable set 𝒜:** the authorities whose verdicts must all be satisfied for the act.
- **Closure statement:** a registrar's signed assertion that a list of in-force authorities over
  a scope is complete as of a time. The authenticated denial of existence for law. A later closure
  over the same scope, or under the same label (the entry's `name`), replaces an earlier one from
  the later one's `at`; the label lets a re-signed list whose scope was narrowed replace the one it
  corrects.
- **View:** the folded registrar record a resolver reads, and the time its log head was signed or
  read (`head_at`). A view read live from the chain has age zero; a mirrored or cached one does not.
- **Relying party ρ:** as in NOMOS-SPEC-008, extended with a set of **pins**: the registrars
  whose law it undertakes to honor.

## 2. The registrar log

A registrar's statements live in an append-only, hash-chained log with a signed head. This
specification reuses NOMOS-SPEC-013 §3's chain discipline unchanged (entry hash = SHA-256 of the
JCS of `{ seq, kind, name, version, seal_hash, entry, at, prev_hash }`; genesis `prev_hash` is 64
zeros; the signed head as there). Four entry kinds are added:

| `kind` | `name` | `entry` | Meaning |
| --- | --- | --- | --- |
| `applies` | authority name | `{ scope, exclusive?, until? }` | the authority governs `scope` from this entry's `at` |
| `recognizes` | registrar id | `{ scope }` | defer `scope` to the registrar rooted at `name` |
| `closed` | a label | `{ scope, authorities[], max_age_days? }` | as of `at`, the complete in-force list over `scope` is `authorities` |
| `superseded` | old authority name | `{ by }` | replaced by `entry.by` from this entry's `at` |

**Folding rules (normative).** Entries fold in `seq` order into the registrar's state. An
`applies` opens a claim for `name` from its `at` (re-stating an authority closes the prior
claim at the new entry's `at` and opens the new terms). A NOMOS-SPEC-013 `withdrawn` entry
closes the named authority's open claim at its `at`. A NOMOS-SPEC-013 `revoked` entry adds the
authority to the registrar's revoked set. `closed` statements accumulate, and a later closure
over the same scope or under the same label replaces an earlier one from its `at`; `superseded` records the edge from its
own `at`. A resolver MUST derive the registrar's state only by this fold —
never from a side channel the chain does not witness.

`exclusive: true` on a claim asserts the registrar's sole precedence over the claim's scope. It
exists so conflicts are *detectable* (§5); it grants nothing.

## 3. Resolution

### 3.1 The query

`R(world, query)` where `world = { pins, registrars }` (ρ's pinned registrar ids and each one's
folded record) and `query = { context, at }`. `at` is an RFC 3339 instant; membership, windows,
supersession and closure freshness are all judged at `at`.

The query MAY carry `witnessed`: a map from context field to the list of **witness classes**
under which its value was attested (e.g. `{ "jurisdiction": ["geo"] }`). How a value is attested
is out of band for this specification — the expected transport is a NOMOS-SPEC-008 witness
statement whose key is certified (NOMOS-SPEC-007) for that class, verified by the caller before
resolving. This specification governs only the consequence: when an unwitnessed value may
decide, and what happens when it may not.

### 3.2 Scope evaluation is three-valued, by the NOMOS-SPEC-008 evaluator

A scope predicate over a context is TRUE, FALSE or UNDECIDED with exactly NOMOS-SPEC-008 §6.2's
semantics: an absent context field makes the atoms reading it UNDECIDED (never FALSE), except
`action_type`, which is `act`-channel and decided by absence; connectives are Kleene's strong
logic. A predicate that cannot be parsed is UNDECIDED and MUST surface a distinguishable marker
(the reference uses the pseudo-fact `__scope_unparseable__`) — a malformed scope MUST NOT
silently widen or narrow the law.

A conforming resolver MAY implement this by delegating to any conforming NOMOS-SPEC-008
evaluator: construct, per predicate, a two-decision artifact — the predicate as an `allow` at
priority 1 and as a `block` at priority 2, default outcome `escalate` — and read `block` as
TRUE, `escalate` as FALSE, `undecided` as UNDECIDED.

**CF — context fidelity.** A claim MAY carry `witness_required`: a map from context field to the
witness class whose attestation that field's value needs before this claim's scope may read it
(e.g. `{ "jurisdiction": "geo" }`). The registrar, who knows what its law turns on, decides which
fields are too load-bearing for anyone's say-so. When a resolver evaluates that claim's scope, a
field named in `witness_required` counts only if the query's `witnessed` lists it under the
required class; otherwise the field is treated as ABSENT for that evaluation — UNDECIDED, never
FALSE — and the resolution MUST surface it both among the missing context facts and in
`missing.unwitnessed` as `{ fact, class }`. An unwitnessed value MUST NOT evaluate a scope to
FALSE: FALSE removes the law, and removal is exactly what an unverified value must never buy.
Fields not named in `witness_required` read bare values as before; other claims' evaluations of
the same field are unaffected.

Why this cannot live downstream: an artifact's own data contract can demand witnessed facts, but
it is consulted only after resolution has put that artifact's law in the set — a false context
fact deletes the law whose contract would have demanded the proof. The demand must sit on the
registrar's claim, upstream of every law it selects.

### 3.3 The algorithm (normative)

Starting from the pins, walk registrars breadth-first, following each `recognizes` edge whose
scope is TRUE on the context (an UNDECIDED edge scope contributes its open facts; a FALSE edge
is not followed and imposes no obligations on its target). For each reached registrar:

1. **C6 — claim authority.** Evaluate the registrar's certified scope on the context. A claim
   contributes a member only if the claim's scope AND the certified scope are both TRUE. A claim
   whose certificate does not cover the context is not a weaker claim; it is no claim.
2. **C7 — currency.** Skip claims not in force at `at` (window), superseded at `at`, or revoked.
   Skipped claims SHOULD be reported in the proof with their reason.
3. **C8 — closure or silence.** The registrar MUST have at least one closure statement whose
   scope is TRUE on the context and whose age at `at` is within its freshness bound
   (`max_age_days`, default 90). A pinned registrar that is unreachable, or has no fresh
   covering closure, makes the resolution INCOMPLETE naming it. A closure dated after `at` does
   not cover `at` — a later enumeration does not speak for an earlier moment; a closure replaced
   by a later one over the same scope or under the same label (signed at or before `at`) does not
   speak either.

   **Closure agreement.** A closure is the registrar's own statement of what is in force, so it
   MUST NOT contradict the registrar's chain. Among the registrar's fresh, unreplaced closures
   whose scope is TRUE on the context: (a) every authority a closure names MUST have a claim that
   survives step 2 (in force, not superseded, not revoked), and (b) every claim that survives
   step 2 and whose scope is TRUE on the context MUST be named by at least one of them. Either
   failure makes the resolution INCOMPLETE naming the registrar, the authority and which of (a)
   (`closed_but_not_claimed`) or (b) (`claimed_but_not_closed`) failed. Without agreement, a
   withdrawal, supersession or revocation drops law silently while a closure that still names it
   stays fresh; with it, hiding law requires signing a closure that omits it. A registrar SHOULD
   sign a new closure whenever law it names stops being in force; the reference registrar does so
   automatically for removals, keeping the closure's original expiry, so a removal never extends
   a review.

   **View age.** A relying party that resolves against mirrored or cached views MUST set a bound
   on their age (`max_head_age_seconds`); a view whose `head_at` is absent or older than the bound
   at `at` makes the resolution INCOMPLETE naming the registrar. A stale view can carry a closure
   still inside its own bound while the live log has moved on; no other check sees it.
4. Any UNDECIDED scope anywhere (claim, certificate, edge, closure) contributes its open context
   facts to the resolution's missing set.

**C5 — resolution independence** is architectural: nothing the carrier presents is an input to
R. A relying party MUST compute 𝒜 from its own pins and the registrars' chains; an Act or
request listing "the authorities checked" MUST NOT influence membership.

### 3.4 The three results

Exactly one of, with precedence INCOMPLETE > CONFLICT > RESOLVED:

- **INCOMPLETE** — any open context fact, unreachable pinned registrar, missing or stale
  closure, closure disagreement, a witness-required context field whose value arrived
  unwitnessed (CF), or view older than the relying party's bound. Each MUST be
  named. For a consequential act, INCOMPLETE MUST NOT be read as
  permission, and a resolver MUST NOT return the subset it could establish as if it were the
  answer. (Precedence: a missing fact could still dissolve an apparent conflict.)
- **CONFLICT** — `exclusive` claims from two or more distinct registrars all cover the context.
  Both chains MUST be surfaced; a resolver MUST NOT order sovereigns by any tie-break of its
  own. Registrars dissolve conflicts in advance with `recognizes` edges and scope carve-outs —
  treaties, in machine form — and the log records which conflicts have been so dissolved.
- **RESOLVED(𝒜, π)** — otherwise. 𝒜 is the surviving members; an EMPTY 𝒜 is a valid answer
  ("no pinned law applies"), permitted only under closure. The proof π MUST carry, at minimum:
  the pins, `at`, each consulted registrar's log head, the closure statements relied on, and the
  dropped claims with reasons — enough for a third party holding the chains to recompute 𝒜.

Resolution MUST be deterministic and order-independent: the same world and query give the same
result whatever order registrars, claims, edges or pins are presented in. The vectors test this
under shuffling.

## 4. Combination

Where a relying party evaluates every member of 𝒜 (each per NOMOS-SPEC-008 or NOMOS-SPEC-005),
the combined verdict is:

1. any member DENIED → **DENIED**, naming the denying authorities;
2. else any member INCOMPLETE — or any member that could not be evaluated or consulted at all →
   **INCOMPLETE**, carrying the union of open facts. A member that could not be asked MUST hold
   the combination open, never pass silently;
3. else any member ESCALATED → **ESCALATED**, carrying the UNION of escalations, each preserved
   with its authority and escalation identity (the NOMOS-SPEC-008 0.5.0 gate-clause-(ii) lesson,
   lifted across authorities: safety preserves *who* approves, not only whether);
4. else **AUTHORIZED** — unanimity only.

Combination MUST be associative and commutative. The severity order is deliberate: an INCOMPLETE
member outranks escalation, because acting on a partial enumeration's escalation could paper
over a deny the missing member would have returned.

## 5. What a record carries

A relying party that commits an act after resolution SHOULD bind the resolution into the act's
record: the registrar log heads consulted (from π) under the record's integrity mechanism. A
record so bound proves not only each member's verdict but *which enumeration* the act answered
to as of `t` — forum shopping becomes provable from the record rather than merely preventable.

## 6. Conformance

[`resolution-vectors/vectors.json`](../resolution-vectors/vectors.json) carries, for each
vector, a world, a query, and the expected result; vectors with an `ablate` field additionally
carry `expect_ablated` — the behavior of an implementation missing exactly that condition, i.e.
the attack succeeding. The C7 ablation judges membership at the vector's `ablate_at` while
closures are still judged at `at`; the C8 ablation reads no closure, no closure contents and no
view age; the CF ablation reads witness-required fields as if bare values counted. A conforming resolver MUST produce every `expect`, MUST NOT produce any
`expect_ablated` (except in an explicit test-only ablation mode), and MUST be order-independent
under shuffling of every list in the world. An implementation offering ablation modes SHOULD also
show that each attack succeeds under its own ablation and under no other.

## 7. Privacy considerations

A resolution query reveals intent. Registrar chains are public by design; queries need not be.
Relying parties SHOULD resolve against locally mirrored chains where query privacy matters;
private information retrieval is an open direction.

## 8. Security considerations: the four attacks

Each attack uses only genuine, correctly signed artifacts. Each is a published vector.

- **Applicability hiding** (defeats a resolver without C5): the carrier presents an Act under
  the permissive authority and never mentions the sanctions régime; a relying party that takes
  the set from the presentation commits a wrongful act on genuine artifacts.
- **Jurisdiction squatting** (without C6): a correctly certified registrar key appends a claim
  outside its certified scope; a resolver that checks signatures but not scope imports foreign
  law into strangers' transactions. Under the strict combination of §4 an added authority can
  only add refusals, so C6 prevents wrongful refusals and foreign law imposed on strangers; it is
  not what prevents a wrongful commit (supersession and revocation act only on a registrar's own
  claims, so squatting cannot remove law).
- **The zombie authority** (without C7): a superseded authority, cryptographically valid
  forever, is satisfied after its replacement took force because membership is judged at a
  stale instant rather than at `at`. The wrong lives in the set's staleness, not the artifact's
  validity. (Ignoring currency altogether is not this attack: it only adds law.)
- **The starved resolver** (without C8): no one lies — a pinned registrar's log is merely
  unreachable, or its closure stale. Answering with the reachable subset reproduces hiding
  without touching the carrier. Silence of a log, like silence of a witness in NOMOS-SPEC-008,
  must cost the proposer the verdict, never buy it. Two further arms: **withdrawal under a
  closure** (a genuine withdrawal while a fresh closure still names the law; closure agreement
  stops it) and the **stale view** (a cached copy whose closure is inside its own bound; the
  view-age bound stops it).
- **The misdescribed act** (without CF): no forged key, no hidden law — the carrier's side simply
  states a context field conveniently (`jurisdiction: QA` about an act that lands in the EU), or
  the relying party fills it from records that are the same say-so one hop removed. The scope
  reads the bare value, evaluates FALSE, and the law leaves the set with every signature intact.
  Under CF a witness-required field without its attestation is UNDECIDED: the answer is held
  open naming the fact and the class, and lying stops being an exit from the law — at worst it
  stops the act. What CF does not solve is the witness's own truthfulness: NOMOS-SPEC-008's A4
  assumption, relocated one layer up and shrunk to one named, certified, revocable attester per
  fact.

Containment. An added applicability claim, from any key, never removes a member: the worst case
is wrongful refusal, the safe direction. Removing law takes one of withdrawal, supersession or
revocation, all signed by the registrar's key; under closure agreement each holds every
resolution it touches open until the registrar also signs a closure that omits the law. So hiding
law requires a signed closure that, read against the registrar's own append-only chain, shows
exactly what was dropped and when: not prevented, but attributable and permanent. A registrar
that separates the key for `closed` entries from the key for other entries makes that a
two-key act.

## 9. Open problems

Inherited and stated, not hidden: registrar governance (who may close a scope — the
NOMOS-SPEC-007 §9 question squared); characterization of context fields beyond the v0
vocabulary; the witness-class vocabulary and who certifies context witnesses per class (CF's
residue); private-law resolution (contracts as authorities); freshness economics per scope
class, now two bounds (closure age and view age). The Draft-exit condition — a second,
independent implementation agreeing on every vector — was met on 2026-11-13 and is recorded in
§10.

## 10. Changes

**Active (2026-11-13).** Status Draft → Active. The exit condition was met by
[`SvvBot/nomos-spec014-resolver`](https://github.com/SvvBot/nomos-spec014-resolver): an
independent Python resolver whose test suite pins `resolution-vectors/vectors.json` by SHA-256
(`7dfd2fca73398f6346c84c7ab90d4076c3b07adf92c4d67b2af6ed7fc7f240bb`), passes all 23 vectors by
exact `expect` match, reproduces all 8 necessity ablations (C5, C6, C7, C8×4, CF), and holds
order-independence under shuffling — green on its own CI (`main` @ `8fca15c`, Python 3.10–3.13).
Scope of the independence claim, stated precisely: the SPEC-014 resolution algorithm is an
independent construction; the SPEC-008 condition evaluator beneath it derives from this
repository's published Python reference (`python/nomosprotocol/act.py`), which is why
NOMOS-SPEC-008's own Draft-exit remains open ([#32](https://github.com/nomos-spec/spec/issues/32)).

**0.3.0 (2026-11-12).** Context fidelity (CF): the last self-description. C5 stopped the carrier
choosing the law; the context the scopes evaluate over was still anyone's say-so, and a false
value does not merely mislead — it deletes the very law whose own data contract would have
demanded proof (a demand placed downstream is removed by the lie it guards against). Claims gain
`witness_required`, queries gain `witnessed`, and a witness-required field without its
attestation is UNDECIDED for that claim's scope — never FALSE — surfacing in
`missing.unwitnessed`. Three new vectors including the attack (`attack-misdescribed-act`,
ablation `CF`).

**0.2.0 (2026-11-12).** Found by mechanizing the resolver
([`papers/resolution/lean/Resolution.lean`](../papers/resolution/lean/Resolution.lean)):

- Closure agreement (§3.3, C8). In 0.1.0 a closure's freshness was read but never its list, so a
  genuine withdrawal hid law while an older closure still named it.
- View age (§3.3, C8). 0.1.0 gave no way to tell a stale copy of a log from the live one.
- A later closure over the same scope, or under the same label, replaces an earlier one (§1, §2).
- §8: C6 is restated as protection against wrongful refusal; the C7 attack is restated as
  membership judged at a stale instant; containment is restated as attribution.
- Vectors: 20 (from 16); the zombie vector judges membership at `ablate_at`; new vectors for a
  withdrawal under a closure, a stale view, a claim no closure names, and overlapping closures
  that agree.

**0.1.0 (2026-11-11).** First draft.
