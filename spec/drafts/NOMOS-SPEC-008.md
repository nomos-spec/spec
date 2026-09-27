# NOMOS-SPEC-008: Act Binding

**Status:** Draft
**Version:** 0.1.0
**Extends:** NOMOS-SPEC-001 v2.2.0, NOMOS-SPEC-007 v1.8.0
**Proposed:** 2026-09-27
**Authors:** Safehaven AI Corp. / NOMOS Protocol Working Group

---

## Abstract

NOMOS-SPEC-001 makes an institution's rules a sealed, portable object. NOMOS-SPEC-007 lets a
system that has never met the institution establish that those rules are genuine. Neither says
anything binding about the *action*: a verdict is computed over caller-supplied facts, and nothing
ties it to the change that is later made.

That leaves three gaps an autonomous agent can exploit without breaking any cryptography:

1. **It can skip the check.** A verdict is advice unless the system that makes the change
   refuses changes that lack one.
2. **It can lie to the check.** If the agent supplies the facts, the rules evaluate the agent's
   story, not the world.
3. **It can change the action after the check.** A verdict for $4,000 is not a verdict for
   $400,000 unless it is bound to the amount.

This document defines the **Act**: a self-verifying package that carries an exact change together
with everything needed to prove the change is legitimate — the sealed rules, the certificates,
facts as signed testimony from authorized witnesses, and human consents signed over this Act
alone. The **relying party** — the ledger, registry or API that would commit the change — verifies
the Act itself, locally and deterministically, and commits exactly the change it verified or
nothing.

The consequence is a different security property from a gateway's. An agent is free to bypass
every NOMOS component. Its act still cannot take effect, because the only system able to make the
change is the one that demands the proof.

**Status of this document.** Draft, published with a reference implementation and nineteen test
vectors (§10). One implementation exists; no interoperability claim is made.

---

## Table of Contents

1. Terminology
2. The Act
3. Testimony
4. Consent and the binding digest
5. Validity, audience and replay
6. Verification at the relying party
7. Facts and their sources
8. The commit rule
9. Receipts
10. Conformance and implementation status
11. Security considerations
12. Example

---

## 1. Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, **RECOMMENDED**, **MAY**
and **OPTIONAL** are to be interpreted as described in RFC 2119.

**Act** — a signed-statement bundle proposing one exact change to one relying party (§2).

**Presenter** — whoever assembles and submits an Act, typically an AI agent. The presenter's own
assertions carry no authority except over facts the rules explicitly let it supply (§7).

**Relying party** — the system that would commit the change: the system of record for the state
being changed. It pins its own root (NOMOS-SPEC-007 §4.1), holds its own identifier, its own state
and its own nonce ledger.

**Witness** — the holder of a key certified with `claim` scope (NOMOS-SPEC-007 rev. 1.8 §3.4.1).

**Approver** — the holder of a key certified with `consent` scope.

**Commit** — the relying party's application of the Act's `action` to its state.

---

## 2. The Act

```jsonc
{
  "act_version":   "1",
  "act_id":        "act-7f3c…",
  "nonce":         "<base64, at least 128 bits of entropy>",
  "issued_at":     "2026-10-01T11:59:00.000Z",
  "expires_at":    "2026-10-01T12:04:00.000Z",
  "relying_party": "acme-bank:core-ledger",
  "action": {
    "type":    "approve_loan",
    "subject": "APP-1042",
    "params":  { "amount": 75000, "loan_purpose": "home_improvement", "has_cosigner": false }
  },
  "authority": {
    "artifact":  { /* sealed .nomos (NOMOS-SPEC-001), status "sealed" */ },
    "key_certs": [ /* NOMOS-SPEC-007 certificates for the sealing key, every witness and every approver */ ]
  },
  "testimony":       [ /* §3 */ ],
  "consents":        [ /* §4 */ ],
  "presenter_facts": { /* OPTIONAL, §7 */ }
}
```

| Field | Required | Meaning |
|---|---|---|
| `act_version` | REQUIRED | `"1"`. Any other value MUST be rejected as `MALFORMED`. |
| `act_id` | REQUIRED | Presenter-chosen identifier, for logs and receipts. |
| `nonce` | REQUIRED | Single-use value (§5.2). |
| `issued_at`, `expires_at` | REQUIRED | Validity window (§5.1). |
| `relying_party` | REQUIRED | The one system allowed to commit this Act (§5.3). |
| `action.type` | REQUIRED | The kind of change, e.g. a tool or operation name. |
| `action.subject` | OPTIONAL | Who or what the change is about. Testimony that names an `about` MUST match it (§3.3). |
| `action.params` | REQUIRED (may be empty) | The exact parameters of the change. These are both what gets committed and facts in their own right (§7). |
| `authority.artifact` | REQUIRED | The sealed rules. |
| `authority.key_certs` | REQUIRED | One unordered set of certificates covering every key whose statement is in the Act. |
| `testimony` | OPTIONAL | Signed facts. |
| `consents` | OPTIONAL | Signed approvals of this Act. |
| `presenter_facts` | OPTIONAL | Facts the presenter asserts itself; accepted only where §7 allows. |

An Act has no presenter signature. Who assembled it is irrelevant to whether it is legitimate; a
relying party MAY log presenter identity from its transport, but MUST NOT let it affect the
verdict.

---

## 3. Testimony

### 3.1 The statement

```jsonc
{
  "claim":       "dti_ratio",
  "value":       0.31,
  "about":       "APP-1042",
  "as_of":       "2026-10-01T11:30:00.000Z",
  "valid_until": "2026-10-02T11:30:00.000Z",
  "kid":         "<witness key id>",
  "algorithm":   "Ed25519",
  "signature":   "<base64>"
}
```

### 3.2 Signed payload (normative)

`JCS({ claim, value, about, as_of, valid_until, kid })`, with `about` as `null` when absent.
`algorithm` and `signature` are not signed.

### 3.3 Validity (normative)

A relying party MUST reject the Act if any testimony statement:

1. has a `kid` that does not resolve (NOMOS-SPEC-007 rev. 1.8 §4.6) — `TESTIMONY_INVALID`;
2. is signed by a key whose effective scope does not permit this `claim` (§3.4.1) —
   `TESTIMONY_OUT_OF_SCOPE`;
3. has an invalid signature — `TESTIMONY_INVALID`, reason `bad_signature`;
4. is outside `[as_of, valid_until]` at verification time — `TESTIMONY_INVALID`, reason `stale`;
5. names an `about` different from `action.subject` — `TESTIMONY_INVALID`, reason
   `wrong_subject`.

Invalid testimony rejects the whole Act. It is never silently dropped: a presenter that includes
a forged or stale statement has shown something about itself that the relying party should record.

Testimony is not bound to one Act. A witness attests a fact about the world; the same statement
MAY support several Acts within its validity window. What binds testimony to a particular Act is
the binding digest (§4.3), which covers every testimony statement the Act carries.

---

## 4. Consent and the binding digest

### 4.1 The statement

```jsonc
{
  "binding_digest": "<hex SHA-256, §4.3>",
  "role":           "SENIOR_APPROVER",
  "decision":       "approve",
  "signed_at":      "2026-10-01T11:59:30.000Z",
  "kid":            "<approver key id>",
  "algorithm":      "Ed25519",
  "signature":      "<base64>"
}
```

### 4.2 Signed payload (normative)

`JCS({ binding_digest, role, decision, signed_at, kid })`.

### 4.3 The binding digest (normative)

```
binding_core = {
  act_version, act_id, nonce, issued_at, expires_at, relying_party,
  action,
  artifact_hash:    authority.artifact.seal.hash,
  testimony_digest: SHA-256( JCS( testimony, sorted by the JCS encoding of each statement ) )
}
binding_digest = hex( SHA-256( JCS(binding_core) ) )
```

The binding digest fixes the exact change, the exact rules, the exact facts, the audience and the
single-use nonce. An approver's signature over it approves that combination and nothing else.
Changing any parameter, swapping the rules, substituting a fact or re-addressing the Act produces
a different digest and invalidates every consent (reason `binding_mismatch`).

### 4.4 Counting consents (normative)

When the rules return `ESCALATED` with escalation `E` (§6 step 9), let `role` be
`E.role_required` and `n` be `E.required_consents` (NOMOS-SPEC-001 v2.2.0 §3.7; default 1). The
escalation is satisfied when at least `n` consent statements:

- resolve and are in `consent` scope for `role` (NOMOS-SPEC-007 rev. 1.8 §3.4.1),
- carry a valid signature and a `binding_digest` equal to this Act's,
- have `decision: "approve"` and `role` equal to `E.role_required`,
- and come from **`n` distinct keys**. The same approval presented twice counts once.

A consent that fails signature, scope or binding checks rejects the Act (`CONSENT_INVALID`,
`CONSENT_OUT_OF_SCOPE`) rather than being ignored. A valid consent for a different role is
ignored.

---

## 5. Validity, audience and replay

### 5.1 Window

`expires_at` MUST be later than `issued_at`, and the window SHOULD NOT exceed 300 seconds. A
relying party MUST reject an Act before `issued_at` (`NOT_YET_VALID`) or after `expires_at`
(`EXPIRED`), and MAY reject windows longer than its own configured maximum (`MALFORMED`).

### 5.2 Nonce

A relying party MUST keep a ledger of the nonces of committed Acts for at least as long as those
Acts could still be valid, and MUST reject an Act whose nonce is in the ledger (`REPLAYED`).
Recording the nonce and committing the action MUST be one atomic operation (§8).

### 5.3 Audience

A relying party MUST reject an Act whose `relying_party` is not its own identifier
(`WRONG_RELYING_PARTY`). An Act approved for one ledger cannot be replayed against another.

---

## 6. Verification at the relying party (normative)

A relying party MUST perform these steps in order and stop at the first failure:

| Step | Check | Failure |
|---|---|---|
| 1 | Envelope well-formed; `act_version` known; artifact sealed; certificate set ≤ 20 | `MALFORMED` |
| 2 | `relying_party` is this system | `WRONG_RELYING_PARTY` |
| 3 | Now is inside the window | `NOT_YET_VALID`, `EXPIRED` |
| 4 | Nonce not already used | `REPLAYED` |
| 5 | The artifact's sealing key resolves (NOMOS-SPEC-007 rev. 1.8 §4.2a), the seal verifies, the scope admits the artifact, and the sealing key is not a statement key | Any NOMOS-SPEC-007 §4.4 outcome, e.g. `ISSUER_NOT_RECOGNIZED`, `SEAL_INVALID`, `OUT_OF_SCOPE` |
| 6 | Every testimony statement is valid (§3.3) | `TESTIMONY_INVALID`, `TESTIMONY_OUT_OF_SCOPE` |
| 7 | Every fact arrived through its declared channel (§7) | `FACT_SOURCE_VIOLATION` |
| 8 | Evaluate the sealed rules over exactly those facts (NOMOS-SPEC-001 §4, including §4.6) | — |
| 9 | If the result is `ESCALATED`, count consents (§4.4) | `CONSENT_INVALID`, `CONSENT_OUT_OF_SCOPE` |

The verdict:

| Verdict | Meaning | Commit? |
|---|---|---|
| `AUTHORIZED` | The rules permit the action, or an escalation was satisfied by consent (`by_consent: true`) | Yes, exactly `action` |
| `DENIED` | The rules forbid the action, or no rule matched under `default_outcome: block` | No |
| `ESCALATED` | Consent is required and not yet sufficient; the response reports `consents_valid` and `consents_required` | No |
| any failure above | The Act could not be established | No |

The presenter can resubmit an escalated action with consents added, as a new Act with a new
nonce. Approvers sign that new Act's binding digest.

### 6.1 No rule matched (normative)

When no decision matches, the outcome is the artifact's `logic.resolution.default_outcome`
(NOMOS-SPEC-001 v2.2.0 §4.6). **If the field is absent, a SPEC-008 relying party MUST treat it as
`block`.** An Act that proves nothing commits nothing.

---

## 7. Facts and their sources (normative)

Every fact the rules read arrives through exactly one of four channels:

| Channel | Where it comes from | Who controls it |
|---|---|---|
| `action` | `action.params`, plus `action_type` = `action.type` | The presenter proposes it, and it is exactly what gets committed |
| `testimony` | Valid testimony statements (§3) | Certified witnesses |
| `relying_party` | The relying party's own state at verification time | The system of record |
| `presenter` | `presenter_facts` | The presenter alone |

The artifact declares the permitted channel of each input in
`data_contract.inputs.<name>.source` (NOMOS-SPEC-001 v2.2.0 §3.5). A relying party MUST reject the
Act with `FACT_SOURCE_VIOLATION` if:

- a fact arrives through a channel other than the one its input declares;
- a fact name arrives through more than one channel;
- a fact is supplied for an input that declares no `source`.

This is what closes the lying-presenter gap. A presenter can still *propose* any change it likes,
and the proposed amount is a trustworthy fact precisely because it is what will be committed. What
a presenter can no longer do is supply the facts that decide whether that change is legitimate,
unless the institution's own rules say it may.

Relying-party facts take a particular role. At the point where a change lands, the system of
record already knows much of what the rules need: the balance, the leave already taken, whether
this is a first loan. Declaring those inputs `relying_party` means no one supplies them at all;
they are read from the state being changed.

---

## 8. The commit rule (normative)

On `AUTHORIZED`, the relying party MUST:

1. apply exactly `action` — the same `type`, `subject` and `params` the verification evaluated —
   and nothing else;
2. record the nonce in the same atomic operation as the change;
3. re-read any `relying_party` facts inside that same operation, and abort if they differ from
   the values evaluated.

Step 3 closes the time-of-check to time-of-use gap for the system's own state: if the balance
moved between verification and commit, the Act is re-verified or refused.

On any other verdict, the relying party MUST NOT apply any part of `action`.

---

## 9. Receipts

A relying party SHOULD append a receipt for every verification to its audit trail:

```jsonc
{ "act_id": "act-7f3c…", "act_digest": "<binding digest>", "decision": "AUTHORIZED",
  "rule": "R6", "by_consent": true, "committed_at": "2026-10-01T11:59:41.000Z" }
```

Because the Act is self-contained, the receipt plus a retained copy of the Act lets any third
party re-run §6 later and reach the same verdict — an auditor needs no access to the agent, the
presenter or any NOMOS service.

---

## 10. Conformance and implementation status

A conformant relying party implements §5–§8 in full. A conformant presenter produces Acts that
follow §2–§4.

**Reference implementation.** `act-vectors/act_verify.py`: a self-contained Python verifier
(NOMOS-SPEC-007 rev. 1.8 target-first resolution, statement scope, a Nomos-Expr v1 evaluator, and
§6 in full).

**Test vectors.** `act-vectors/vectors.json`, generated deterministically by
`act-vectors/generate.py` from published seeds; `act-vectors/check.py` runs them. Nineteen
cases: authorization by rule; denial by rule; a presenter asserting a testimony fact; the rule
issuer attempting to testify; a witness outside its claim set; escalation with zero, one and a
duplicated consent; dual consent; an action altered after consent; an approver claiming a role it
lacks; no rule matching under default deny; expiry; wrong audience; replay; stale testimony;
testimony about another subject; rules from an uncertified issuer; and a tree-shaped certificate
set presented in reverse.

**Known gaps (disclosed).**

- One implementation, by the authors of this document. No interoperability claim.
- Revocation freshness for witness and approver keys follows NOMOS-SPEC-007 §5 unchanged; freshness
  staples for statement keys are not yet specified.
- Effects that are not state changes — sending a message, publishing a statement — need a relying
  party at the outbound gateway. This document does not specify one.
- Relying parties that cannot run §6 themselves need an adapter in front of them. The adapter then
  holds the only credential that can change that system, and inherits the relying party's duties.

---

## 11. Security considerations

**11.1 The relying party is the enforcement point.** Every property here depends on the system of
record refusing changes that do not arrive as a verified Act. A relying party that also accepts
unverified changes through another interface has not adopted this specification for that
interface.

**11.2 The presenter is untrusted by design.** Nothing in §6 depends on the presenter's honesty,
competence or identity. A hallucinating, compromised or adversarial agent can at worst submit Acts
that fail.

**11.3 Separation of issuing rules, stating facts and approving acts.** A sealing key cannot testify
or consent (NOMOS-SPEC-007 rev. 1.8 §3.4.1, §3.5). Compromise of the rule issuer alone cannot
fabricate the facts the rules read, and compromise of a witness alone cannot change the rules.

**11.4 Witness honesty is a governance question.** Certification bounds *which* facts a key may
assert, not whether its assertions are true. Institutions choose their witnesses; this document
makes that choice explicit, signed and revocable.

**11.5 Presenter facts are an explicit, visible risk.** A `presenter` source is the institution
saying "we accept the agent's word for this". Rules SHOULD use it only for low-stakes inputs, and
reviewers can find every such input by reading the artifact's data contract.

---

## 12. Example

The vectors walk one policy — consumer lending — through every case. Three illustrate the whole
design:

- `denied_by_rule` — a $250,000 loan; the credit bureau testifies a DTI of 58%; rule R3 denies it.
- `agent_asserts_a_testimony_fact` — the same loan, but the agent omits the bureau's DTI and
  supplies 38% itself. `FACT_SOURCE_VIOLATION`: the rules declare DTI a testimony fact, so the
  agent's number is never evaluated.
- `action_altered_after_consent` — a $75,000 loan approved by two senior approvers; the agent then
  changes the amount to $750,000 and resubmits with the same consents. `CONSENT_INVALID`,
  `binding_mismatch`: the approvals were for a different change.
