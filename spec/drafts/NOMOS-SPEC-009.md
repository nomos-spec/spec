# NOMOS-SPEC-009: Discovery and Submission

**Status:** Draft
**Version:** 0.1.0
**Extends:** NOMOS-SPEC-008 0.6.0, NOMOS-SPEC-007 rev. 1.9.0, NOMOS-SPEC-010 0.2.0
**Proposed:** 2026-10-26
**Implements:** RFC-0001 change 8
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group

---

## Abstract

NOMOS-SPEC-008 makes an Act verifiable by any relying party. It does not say how a carrier that has
never met a relying party finds it, learns what it accepts, gathers the testimony and approvals an
Act needs, or hands the Act over.

This document specifies four things:
- **Discovery documents** (§3). A relying party, an issuer and a witness each publish one at a
  well-known path.
- **The statement request** (§4). A carrier asks a witness for testimony.
- **The approval request** (§5). A carrier asks an approver for consent over one exact Act.
- **The submission binding** (§6). An Act is sent to a relying party over HTTP, and each verdict
  comes back as one status code and one body.

**The principle (§2).** A discovery document tells a carrier where to go and what to bring. It
never decides anything. Everything in it that bears on a verdict is checked again by the verifier,
so a false document can make an Act fail, never succeed. Discovery is therefore not an input to
the verdict, and carrier indifference (R-19, Definition 1) is unchanged.

---

## 1. Terminology

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are as in RFC 2119.

**Relying party**, **carrier**, **witness**, **approver**, **issuer**, **Act**, **testimony** and
**consent** are as in NOMOS-SPEC-008 §1.

A **document** is a JSON object served over HTTPS at a well-known path on its owner's origin
(RFC 8615).

## 2. Documents are hints (normative)

1. A carrier MAY use any field of a document to plan, gather and submit an Act. The relying party
   MUST NOT treat the presence of a document, or anything in it, as evidence for a verdict.
   SPEC-008 §6 is evaluated over the Act alone.
2. A relying party MUST generate its own document from the same configuration its verifier
   enforces, so the document cannot advertise a root, an authority or a policy the verifier does
   not apply.
3. A document SHOULD carry `valid_until`. A carrier SHOULD refetch a document after that time,
   and MUST NOT treat an expired document as authoritative for anything. Because documents decide
   nothing, an expired document can cause no wrong verdict; it can only send an Act to a place
   that refuses it.
4. Every document carries `nomos_document`, naming its kind, and `version`, which is `"1"` in
   this version. A reader MUST reject a document whose `nomos_document` or `version` it does not
   recognize.

## 3. Discovery documents (normative)

### 3.1 Relying party — `/.well-known/nomos-relying-party`

```jsonc
{
  "nomos_document":     "relying-party",
  "version":            "1",
  "relying_party_id":   "acme-bank:core-ledger",        // the Act's `relying_party` (SPEC-008 §5.3)
  "act_endpoint":       "https://ledger.acme.example/nomos/acts",
  "roots": [ { "kid": "…", "public_key_pem": "…" } ],   // the roots it pins (SPEC-007)
  "authorities": [
    {
      "artifact_id":        "acme-purchasing",
      "issuer":             "https://policy.acme.example", // origin of the issuer document (§3.2)
      "actions":            ["purchase"],                  // action types it commits under this authority
      "currency_policy":    "record",                      // SPEC-008 §5.5
      "in_force_seal_hash": "…"                            // its record, when currency_policy is "record"
    }
  ],
  "local_facts":        ["vendor_blocked"],              // facts it supplies itself (source relying_party)
  "max_window_seconds": 900,                             // SPEC-008 §5.1, its own maximum
  "max_act_bytes":      1048576,
  "consent_suites":     ["Ed25519", "ES256", "WebAuthn-ES256"],
  "valid_until":        "2026-11-02T00:00:00.000Z"
}
```

`relying_party_id`, `act_endpoint`, `roots`, `authorities` and `max_window_seconds` are REQUIRED.
`act_endpoint` MUST be an `https` URL, except on a loopback host during development.

### 3.2 Issuer — `/.well-known/nomos-issuer`

```jsonc
{
  "nomos_document": "issuer",
  "version":        "1",
  "issuer_id":      "acme",
  "authorities": [
    {
      "artifact_id":  "acme-purchasing",
      "version":      "1.3.0",
      "seal_hash":    "…",
      "artifact_url": "https://policy.acme.example/authorities/acme-purchasing/1.3.0.nomos",
      "in_force_url": "https://policy.acme.example/authorities/acme-purchasing/in-force"   // OPTIONAL (SPEC-008 §5.4)
    }
  ],
  "key_certs":      [ /* SPEC-007 certificates for the issuer's sealing key, its witnesses and approvers */ ],
  "witnesses":      ["https://finance.acme.example"],   // origins whose witness documents (§3.3) serve this issuer's authorities
  "approvals":      [ { "role": "MANAGER", "endpoint": "https://approve.acme.example/requests" } ],
  "revocations_url": "https://policy.acme.example/.well-known/nomos-revocations",
  "valid_until":    "2026-11-02T00:00:00.000Z"
}
```

- `artifact_url` serves the sealed artifact. Its seal is verified exactly as in the Act, so a
  substituted artifact fails SPEC-008 §6 step 5.
- `key_certs` is the certificate set a carrier presents as `authority.key_certs`. It is the set
  NOMOS-SPEC-007 calls a pool: unordered, possibly a tree.
- `in_force_url`, when present, serves a current in-force statement (SPEC-008 §5.4) on `GET`.

### 3.3 Witness — `/.well-known/nomos-witness`

```jsonc
{
  "nomos_document":     "witness",
  "version":            "1",
  "witness_id":         "acme-finance",
  "kid":                "…",                          // the key its statements are signed with
  "claims":             ["budget_remaining"],
  "statement_endpoint": "https://finance.acme.example/nomos/statements",
  "access":             "Bearer token issued by acme-finance to its own systems",   // human-readable
  "valid_until":        "2026-11-02T00:00:00.000Z"
}
```

Whether a witness discloses a subject's facts to a given requester is the witness's own
access-control decision, not the protocol's. `access` says, for people, what a requester must
bring.

## 4. The statement request (normative)

`POST statement_endpoint` with body `application/json`:

```json
{ "claim": "budget_remaining", "about": "DEPT-17", "valid_for_seconds": 900 }
```

| Outcome | Status | Body |
|---|---|---|
| Statement issued | 200 | `{ "testimony": <SPEC-008 §3 statement> }` |
| Claim not served, or subject unknown | 404 | `{ "error": "…" }` |
| Requester not entitled | 401 or 403 | `{ "error": "…" }` |

The witness chooses `as_of` and `valid_until`. `valid_for_seconds` is a request, not a demand. A
carrier MUST check that the statement it receives names the claim and subject it asked for, and
SHOULD check that `valid_until` covers the window of the Act it will build (§6.3).

## 5. The approval request (normative)

`POST` to the endpoint listed for the role in the issuer document (§3.2), with body
`application/json`:

```json
{ "role": "MANAGER", "act": { /* the Act, consents not required */ } }
```

The approver MUST compute the binding digest from the Act itself (SPEC-008 §4.3), MUST show the
exact change to the person approving, and MUST sign nothing but a consent statement over that
digest, for that role.

| Outcome | Status | Body |
|---|---|---|
| Request accepted, pending a person | 202 | `{ "approval_id", "status": "pending", "poll_url", "approval_url" }` |
| Approved at once (an automated approver) | 200 | `{ "status": "approved", "consent": <SPEC-008 §4 statement> }` |
| Role not served | 404 | `{ "error": "…" }` |

`GET poll_url` returns `{ "status": "pending" | "approved" | "refused" | "expired" }`, with
`consent` when approved. `approval_url` is a page for the person; a carrier MAY show it to its
user. The approver MUST answer `expired` once the Act's `expires_at` has passed.

## 6. The submission binding (normative)

### 6.1 Request

`POST act_endpoint` with `Content-Type: application/nomos-act+json` and one Act as the body. A
relying party MUST answer 415 to any other media type and 413 to a body longer than its
`max_act_bytes`.

### 6.2 Response

Every response body is JSON and carries `decision`. The status follows from the verdict:

| Verdict | Status | Body (in addition to `decision`) |
|---|---|---|
| `AUTHORIZED`, committed | 201 | `receipt` (SPEC-008 §9), and `result`: what the commit returned, if anything |
| `ESCALATED` | 202 | `act_digest`, `escalation_id`, `role`, `consents_valid`, `consents_required`, `retry_until` (the Act's `expires_at`) |
| `INCOMPLETE` | 422 | `open_rules`, `open_facts` |
| `DENIED` | 403 | `rule`, and `reason_code` when the verifier gives one |
| `REPLAYED` | 409 | `act_id`, and `receipt`: the receipt stored when that Act was committed |
| `NOT_ACCEPTED`: an authority or action type this relying party does not take (§3.1) | 400 | `reason_code` `authority_not_accepted` or `action_not_accepted` |
| Any other SPEC-008 §6 outcome | 400 | Exactly the fields the verifier returned (`reason_code`, `dimension`, `claim`, `role`, `field`, …) |

The normative fields of every body are those the SPEC-008 verifier returns, unchanged. A relying
party MAY add `hint` (a sentence a developer can act on) and `docs` (a URL). Neither may change a
verdict, and a carrier MUST NOT branch on either.

### 6.3 Idempotency and escalation (normative)

- **The nonce is the idempotency key.** Only a committed Act's nonce is recorded (SPEC-008 §8). A
  relying party MUST store the receipt of every committed Act, and MUST answer a resubmission of
  that Act with 409 and the stored receipt, never with a second commit.
- **Resubmitting with consents.** An Act answered with 202 was not committed, so its nonce is
  unrecorded. A carrier MAY resubmit the same Act, with consents added, while it is unexpired. The
  binding digest does not cover consents, so the approvers' signatures bind exactly that Act.
  After `expires_at`, the carrier MUST build a new Act, and approvals are requested again.
- **Leaving time to approve.** A carrier that expects escalation SHOULD choose a window up to the
  relying party's `max_window_seconds` (§3.1), and SHOULD request testimony whose `valid_until`
  covers that window. A relying party that commits under human approval SHOULD advertise a
  `max_window_seconds` long enough for a person to approve. The SPEC-008 §5.1 recommendation of
  300 seconds suits Acts that need no person.

### 6.4 The commit (normative)

On `AUTHORIZED`, a relying party MUST apply SPEC-008 §8 exactly, in one transaction:
1. record the nonce;
2. re-read its own facts, and re-verify if any differ from those evaluated;
3. apply exactly `action`;
4. store the receipt.

The code that applies the change MUST receive only the verified `action`. Nothing else from the
request may reach it.

## 7. Planning (non-normative)

A carrier derives what to bring from the authority's own `data_contract`:
- inputs with `source: action` come from the action;
- inputs with `source: testimony` come from a witness whose document lists the claim;
- inputs with `source: relying_party` are supplied by the relying party (§3.1 `local_facts`);
- inputs with `source: presenter` come from the carrier itself.

The carrier evaluates the rules with the SPEC-008 verifier. An `INCOMPLETE` result names exactly
the facts still missing, and an `ESCALATED` result names the role whose approval is needed. Because
planning runs the verifier's own logic, a carrier and a relying party cannot disagree about what an
Act needs. Planning is advisory: only the relying party's verdict commits.

## 8. Security considerations

- **Documents.** A forged document misdirects; it cannot authorize. Serve documents over HTTPS,
  and treat them as caches of information that the Act itself proves or the verifier rechecks.
- **Witness and approver endpoints are where facts and consent are disclosed or signed.** Both
  must authenticate requesters as their owners require (§3.3). An approver must render the Act
  from the Act itself, never from text the carrier supplies, or a carrier could show one change and
  get approval for another.
- **Denial of service.** `max_act_bytes`, the SPEC-007 20-certificate bound and ordinary rate
  limiting bound the cost of a submission. Verification is local and needs no outbound call.

## 9. Conformance

- **Schemas.** `schema/nomos-relying-party.schema.json`, `nomos-issuer.schema.json` and
  `nomos-witness.schema.json`.
- **Status vectors.** `submission-vectors/status.json` maps every SPEC-008 §6 outcome to its
  status (§6.2).
- **A relying-party conformance runner.** `submission-vectors/run.mjs` builds fresh Acts from
  published test keys and submits them to any relying party configured with the conformance
  profile:
  - an authorization;
  - an escalation, then a resubmission with consent;
  - an incomplete Act;
  - a denial;
  - a replay;
  - a wrong media type and an oversized body;
  - a tampered action.

  It works in any implementation language.

## Changelog

- **0.1.0 (Draft)** — First version: discovery documents, statement and approval requests, the
  submission binding, idempotency and escalation, the commit, schemas, status vectors and the
  conformance runner.
