# NOMOS-SPEC-005: Public Query Extension

**Status:** Draft
**Version:** 1.5.0
**Extends:** NOMOS-SPEC-001 v1.0.0
**Published:** 2026-07-22
**Authors:** SafeHaven LLC / NOMOS Protocol Working Group
**spec_version string:** `"NOMOS-SPEC-005"`

---

## Abstract

NOMOS-SPEC-001 §6 defines an authenticated execution model: an API key or
session, `domain_id` scoping, `caller.agent_id` — the right shape for verifying
a decision against a private or custom-sealed artifact. It is not the right
shape for a large, real class of usage: asking a **public** artifact — a
published, sealed policy anyone should be able to query — whether an action is
allowed, with zero setup.

This document specifies that mode. It is wholly additive: nothing in
NOMOS-SPEC-001–004 changes, no existing required field is touched, and a
runtime that implements only the authenticated model remains fully conformant
without this extension. A runtime MAY implement any subset of §1–4 below; §1–2
are the normative core (MUST), §3–4 are companion capabilities (RECOMMENDED /
OPTIONAL) for runtimes that want to support progressive intake or full-rule
browsing.

Four capabilities are specified:

1. **Public query** (§1, MUST) — a keyless request/response shape for asking a
   public artifact a question and receiving a verdict.
2. **Transcript retrieval** (§2, MUST) — fetching a previously-minted public
   query transcript by id, unchanged, any time.
3. **Guided interaction** (§3, RECOMMENDED) — a stateless endpoint that
   compiles an artifact's own rules into progressive, plain-language questions,
   for callers who don't already know every field name.
4. **Decision atlas** (§4, OPTIONAL) — the artifact's whole rule set as
   browsable data, grouped by verdict.

None of these change how a sealed artifact evaluates. Public query mode is an
alternative **transport and authentication mode** around the same evaluation
semantics NOMOS-SPEC-001 §6.4 already defines (scope validation, seal
verification, rule evaluation in priority order, verdict emission); it does not
redefine evaluation itself.

---

## 1. Public Query

### 1.1 Request

Submit a query to a conformant runtime via `POST /query` against a public
artifact identifier (the runtime's own route prefix and artifact-resolution
scheme — by id or human-readable slug — are implementation-defined; this
section specifies the request/response contract, not the URL shape):

```json
{
  "inputs": { "<field>": "<value>", ... },
  "action": "<string, optional, ≤ 200 chars>"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `inputs` | REQUIRED | Key/value map of decision factors. Field names SHOULD match the artifact's data contract (NOMOS-SPEC-001 §3.9); a runtime MUST NOT reject unknown keys, and MUST NOT silently default a field absent from `inputs` to `false`/`0`/`""` when evaluating a condition that depends on it (see §1.4). |
| `action` | OPTIONAL | Human-readable label for what is being asked. Recorded verbatim in the transcript (§2). Does not affect rule evaluation. |

No API key, session, `domain_id`, or `caller` object is required or accepted.
A conformant runtime MUST NOT require authentication for this request.

### 1.2 Response

```json
{
  "verdict":                     "AUTHORIZED | DENIED | ESCALATED",
  "verdict_description":         "<string>",
  "matched_rule_id":              "<string | null>",
  "open_higher_priority_count":  "<integer>",
  "query_id":                    "<string>",
  "audit_hash":                  "<string>",
  "queried_at":                  "<ISO 8601 UTC>",
  "latency_ms":                  "<integer>"
}
```

| Field | Type | Description |
|-------|------|--------------|
| `verdict` | enum | `AUTHORIZED` — permitted under the artifact's rules. `DENIED` — a blocking rule matched; MUST NOT proceed. `ESCALATED` — no rule reached a definitive outcome, OR a rule explicitly requires human review. |
| `verdict_description` | string | Human-readable explanation. SHOULD name the matched rule. |
| `matched_rule_id` | string \| null | The rule that decided the verdict, if any. `null` when a default/catch-all outcome applied. |
| `open_higher_priority_count` | integer | See §1.4. `0` means every rule with priority higher than the matched rule was fully resolved by the given `inputs`. |
| `query_id` | string | Permanent, addressable transcript identifier (§2). MUST be unguessable (e.g. ≥ 80 bits of entropy) — it is a bearer capability to a specific past query, not a sequential id. |
| `audit_hash` | string | A content hash binding `query_id`, the artifact's seal hash, `inputs`, `verdict`, and `queried_at`. Independently re-computable by any holder of the transcript, without calling the runtime (see §2.2). |
| `queried_at` | string | ISO 8601 UTC timestamp of evaluation. |
| `latency_ms` | integer | Wall-clock evaluation time in milliseconds. |

### 1.3 Evaluation

A conformant runtime evaluates a public query using the same pipeline as
NOMOS-SPEC-001 §6.4 (scope validation, seal verification, rule evaluation in
priority order, verdict emission), with two differences:

- Steps requiring `domain_id` or `caller` scoping (§6.4 step 1, partially) are
  skipped — a public artifact is not domain-scoped.
- The verdict vocabulary is `AUTHORIZED | DENIED | ESCALATED` rather than
  NOMOS-SPEC-001 §6.6's `allowed | blocked | escalated | deferred | error`. A
  runtime MAY map between the two vocabularies internally; it MUST NOT expose
  both inconsistently for the same evaluation.

### 1.4 Completeness disclosure (`open_higher_priority_count`)

A public query MAY be submitted with `inputs` that do not resolve every rule
condition in the artifact — deliberately, so a caller who does not yet know
every fact can still receive a real, honest verdict rather than being forced
through an exhaustive form first.

`open_higher_priority_count` MUST be computed as: walking the artifact's rules
in priority order (same ordering as NOMOS-SPEC-001 §6.4 step 6), the count of
rules with priority strictly higher than the matched rule whose condition
evaluates to **unknown** — neither definitively true nor definitively false —
given the supplied `inputs`. It MUST be computed once, at the moment of
evaluation, from the exact rule set used for that evaluation (i.e. the artifact
version bound in `audit_hash`) — never recomputed later against a possibly
revised rule set, since the artifact a past transcript was sealed against may
since have been superseded.

A runtime MUST NOT default an absent field to a value in order to force a rule
to resolve. `open_higher_priority_count > 0` is not an error condition and MUST
NOT block returning a verdict — it is a disclosure, not a gate. This is the
mechanism by which two structurally different situations are told apart without
inventing a new verdict value: a verdict reached with every relevant fact known
(`open_higher_priority_count == 0`), and a verdict reached with the caller
choosing to proceed despite open conditions (`open_higher_priority_count > 0`)
— both are valid, both are sealed, and the transcript is honest about which
happened.

`open_higher_priority_count` MUST NOT be included in the `audit_hash`
computation (§2.2) — it discloses completeness at evaluation time, it is not
itself a fact being attested to, and it is independently re-derivable by any
party holding the artifact's rules and the transcript's `inputs`.

### 1.5 Idempotency

Unlike NOMOS-SPEC-001 §6.9, a public query has no `caller.correlation_id` and
is not deduplicated — each request mints a new `query_id` and a new transcript.
A runtime MAY offer client-side idempotency via a request-scoped key, but this
is not part of the public query contract.

---

## 2. Transcript Retrieval

### 2.1 Request

```
GET /queries/{query_id}
```

No authentication. `query_id` is the value returned from §1.2.

### 2.2 Response

The same object as §1.2, unchanged, at any point after the original query —
transcripts are permanent and MUST NOT be mutated or deleted by the runtime
once minted (subject to the artifact publisher's own retention policy, which is
out of scope for this specification).

`audit_hash` MUST be computed as a content hash — e.g. SHA-256 — over a
canonical serialization of exactly:

```json
{
  "query_id":   "<string>",
  "seal_hash":  "<the artifact's seal hash, or null>",
  "inputs":     { ... },
  "verdict":    "<string>",
  "queried_at": "<ISO 8601 UTC>"
}
```

A holder of a transcript MAY independently recompute this hash — using the
artifact's publicly-known seal hash and the transcript's own `inputs`,
`verdict`, and `queried_at` — and compare it to the stored `audit_hash` to
verify the transcript has not been altered since it was sealed, without calling
the runtime. This is a spot-check of transcript integrity; it is not the
artifact's own seal (NOMOS-SPEC-001 §8.1) and does not substitute for it.

### 2.3 Non-existent or unpublished queries

`GET /queries/{query_id}` for an id the runtime has never minted, or one whose
artifact has since been withdrawn from public access, MUST return HTTP 404. A
runtime MUST NOT fabricate a plausible-looking response for an unknown id.

---

## 3. Guided Interaction (RECOMMENDED)

### 3.1 Purpose

A caller who does not already know which fields an artifact's rules depend on
should not be required to read the artifact's rule set (or a policy PDF) to
find out. This section specifies a **stateless** endpoint that compiles the
artifact's own rules into a small number of screens, so a form, wizard, or chat
flow can be built without hardcoding field names.

Statelessness is normative: the response depends **only** on which fact keys
are present in the request's `inputs` (a field being `null` counts as present —
"asked, not sure" — distinct from absent). A runtime MUST NOT require session
state, a cookie, or a prior call's response to interpret the next call.

### 3.2 Request

```json
{ "inputs": { "<field>": "<value | null>", ... } }
```

Same `inputs` semantics as §1.1. Start with `{}`.

### 3.3 Response — three screens

A conformant runtime MUST choose exactly one of the following screens per
request, and the choice MUST be a pure function of which fields in `inputs`
are already present:

**`situation`** — offered when none of the artifact's ranked situation fields
are yet present in `inputs`. A situation field SHOULD be an enum-valued field
referenced by a high number of the artifact's decision rules (a runtime MAY
rank by rule-reference count or an equivalent discriminating measure).

```json
{
  "screen": "situation",
  "fields": [
    {
      "field": "<field name>",
      "label": "<human label for the field>",
      "rule_count": "<integer — how many rules this field affects>",
      "options": [
        {
          "value": "<the exact value to submit>",
          "label": "<plain-language label>",
          "definition": "<verbatim source text, if traceable — OPTIONAL>",
          "source": "definition | annex | rule_graph | authored | unsourced"
        }
      ],
      "none_sentinel": "<a value guaranteed to never equal a real option, e.g. \"__none_of_the_listed\">"
    }
  ]
}
```

`source` MUST honestly reflect how a label/definition was derived:
`definition` (the artifact's own defined-term text), `annex` (a referenced
section/annex of the source document), `rule_graph` (derived from the rules
that use the value, when no lexical definition exists), `authored` (a
human-reviewed gloss with no direct source backing), or `unsourced` (no
grounding found — a signal for upstream review, not something to hide). A
runtime MUST NOT present a `rule_graph`, `authored`, or `unsourced` label as if
it were sourced from `definition` or `annex`. Labels MUST be produced
deterministically from the artifact's own contents (its rules, its declared
definitions, its referenced source text) — **not** generated by a language
model at request time. `none_sentinel` is a value the runtime guarantees will
never equal any real option for that field, used by the caller to positively
assert "none of the listed options apply" as a known fact — distinct from
`null`, which means "unknown."

**`checklist`** — offered when situation fields are resolved but single-
condition gate rules remain unanswered. Each item corresponds to exactly one
rule whose condition depends on exactly one not-yet-present boolean field.

```json
{
  "screen": "checklist",
  "groups": [
    {
      "consequence": "blocks | requires_review | permits",
      "label": "<human label for this consequence group>",
      "items": [
        { "rule_id": "<string>", "field": "<string>", "description": "<the rule's own text>", "firing_value": "<boolean>" }
      ]
    }
  ]
}
```

A runtime SHOULD group items by consequence and MUST use the rule's own
description text, not a paraphrase.

**`conditional_verdict`** — offered once situation and checklist fields are
resolved (or directly, if the artifact has few enough rules that no
`situation`/`checklist` screen is needed). Carries a provisional or firm
verdict and every still-open higher-priority condition as an independently
resolvable caveat:

```json
{
  "screen": "conditional_verdict",
  "firm": "<boolean>",
  "verdict": "AUTHORIZED | DENIED | ESCALATED",
  "rule_id": "<string | null>",
  "description": "<string | null>",
  "caveats": [
    {
      "rule_id": "<string>",
      "description": "<string>",
      "consequence": "blocks | requires_review | permits",
      "questions": [
        { "field": "<string>", "label": "<string>", "value_type": "boolean | number | string", "options": ["<value>", ...] }
      ]
    }
  ]
}
```

`firm` MUST be `true` if and only if `caveats` is empty, and a runtime MUST
guarantee that when `firm` is `true`, submitting the same `inputs` to §1
produces the identical `verdict` and `matched_rule_id` — the conditional
verdict MUST NOT diverge from the real evaluation it summarizes. `caveats`
MUST list every rule of higher priority than the provisional match whose
condition is still unknown, each with enough structure (`questions`) to resolve
it inline without leaving this screen.

### 3.4 No fact assertion without confirmation

A runtime MUST NOT expand one caller choice into multiple asserted facts unless
each resulting fact is independently shown and confirmable. (For example: a
single "I'm a startup that deploys AI" choice MUST NOT silently assert both
`entity_type=startup` AND `entity_role=deployer` as a bundle if the caller only
confirmed the first.) This is the same principle as NOMOS-SPEC-001 §6.4's
prohibition on defaulting missing fields — a fact enters `inputs` only when a
caller actually provided it.

---

## 4. Decision Atlas (OPTIONAL)

### 4.1 Request

```
GET /atlas
```

No authentication, no request body.

### 4.2 Response

```json
{
  "total_rules": "<integer>",
  "outcomes": [
    {
      "verdict": "AUTHORIZED | DENIED | ESCALATED",
      "count": "<integer>",
      "rules": [
        { "rule_id": "<string>", "description": "<string>", "priority": "<integer>", "fields": ["<string>", ...] }
      ]
    }
  ]
}
```

Every decision-bearing rule in the artifact, grouped by the verdict it
produces if matched. A runtime MUST use the rule's own description text.
Informational/non-decision rules (logging, side-effect-only actions) MUST be
excluded from `total_rules` and from every group.

This endpoint deliberately carries no provenance/citation data unless the
runtime has independently verified that provenance against the source
document — an unverified citation is worse than none.

---

## 5. Conformance

A runtime MAY implement any subset of §1–4. A runtime that implements §1–2
MAY describe itself as "NOMOS-SPEC-005 §1–2 conformant." A runtime that also
implements §3 and/or §4 MAY additionally cite those sections. Implementing any
part of this specification has no effect on conformance with NOMOS-SPEC-001–004
— a runtime that implements only the authenticated model in NOMOS-SPEC-001 §6
is unaffected by this document's existence.

## 6. Security Considerations

- **No authentication is not no accountability.** A public query still mints a
  permanent transcript (§2); the absence of an API key does not mean the
  absence of a record. Runtimes SHOULD apply IP-based or similar rate limiting
  independent of this specification.
- **`open_higher_priority_count` must not be gameable into false confidence.**
  Because it is excluded from `audit_hash` (§1.4), a runtime MUST compute it
  server-side at evaluation time from the authoritative rule set — never accept
  it as caller-supplied input, and never omit it to imply completeness that
  was not verified.
- **Guided interaction must not assert unconfirmed facts.** See §3.4. A
  progressive-intake feature that silently bundles facts undermines the
  disclosure guarantee in §1.4: a caller who never confirmed a fact should never
  see it treated as resolved.
- **Unguessable `query_id`.** Since transcript retrieval (§2) requires no
  authentication, `query_id` is the only access control on a specific
  transcript. It MUST have sufficient entropy that enumeration is infeasible.
