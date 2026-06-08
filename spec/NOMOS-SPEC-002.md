# NOMOS-SPEC-002: Multi-Agent Governance Extension

**Status:** Active  
**Version:** 1.1.0  
**Extends:** NOMOS-SPEC-001 v1.0.0  
**Published:** 2026-06-05  
**Authors:** SafeHaven LLC / NOMOS Protocol Working Group  
**spec_version string:** `"NOMOS-SPEC-002"`

---

## Abstract

NOMOS-SPEC-001 defines a portable governance artifact and a deterministic
execution model. It specifies *what* decisions to make. It does not specify
*who* may request those decisions.

This document extends NOMOS-SPEC-001 with an `agents` manifest — a top-level
field that registers the per-agent permissions, deny lists, constraints, and
audit requirements that a compliant runtime MUST enforce before rule
evaluation begins. It also defines the runtime guard algorithm, the
permissive-mode default for artifacts that omit the manifest, and the
conformance requirements for NOMOS-SPEC-002 runtimes.

NOMOS-SPEC-001 artifacts remain valid under a NOMOS-SPEC-002 runtime without
modification. The `agents` field is optional and defaults to permissive mode.

---

## Table of Contents

1. Conventions and Terminology
2. Motivation
3. Artifact Extension
4. Agent Identifier
5. `AgentDefinition` Schema
6. Runtime Guard Algorithm
7. Permissive Mode
8. Audit Level Semantics
9. Execution Request Extension
10. Reserved Fields
11. Immutability
12. Conformance
13. Security Considerations
14. Examples

---

## 1. Conventions and Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**,
**RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be
interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

All examples use JSON. All other conventions from NOMOS-SPEC-001 §1 apply.

Additional terms defined in this document:

**Agent** — A software process that submits execution requests to a NOMOS
runtime. An agent is identified by a stable string (`agent_id`).

**Agents manifest** — The `agents` field at the top level of a `.nomos`
artifact, mapping agent identifiers to their `AgentDefinition`.

**Guard** — The six-phase runtime check executed before rule evaluation.

**Permissive mode** — The behavior of a NOMOS-SPEC-002 runtime when the
`agents` field is absent or empty. All callers proceed without verification.

**Advisory mode** — Guard enforcement mode where violations are recorded but
execution is not blocked (except explicit deny list hits, which always block).

**Enforce mode** — Guard enforcement mode where all violations terminate
execution.

---

## 2. Motivation

### 2.1 The Caller Verification Gap

A sealed `.nomos` artifact in NOMOS-SPEC-001 is callable by any process that
possesses the artifact ID. The rules evaluate, a verdict is produced, and an
audit event is emitted — but the caller's identity is never checked against
the artifact's authorization intent.

A loan approval policy designed to be invoked by a supervised `loan-processor`
agent is equally callable by an unsupervised `bulk-processor`, a
misconfigured pipeline, or a direct API call with no agent context. This is
not a bug in the execution model — the rules still evaluate correctly. It is
a structural gap: the *semantics of caller authorization* are invisible to
the runtime. They live in system documentation, deployment configs, and
institutional memory — not in the artifact.

### 2.2 Multi-Agent Pipelines

Modern AI systems are pipelines, not monoliths. A decision may pass through
a `document-verifier`, a `risk-scorer`, a `fraud-detector`, and a
`compliance-checker` before reaching the NOMOS runtime. Each agent adds
context, transforms the payload, and hands off to the next.

A NOMOS-SPEC-001 artifact cannot express that the `fraud-detector` is allowed
to flag and escalate but not approve; that the `compliance-checker` must log
at forensic level; that no agent may call `auto_approve` without prior
risk scoring. These are governance constraints on the *pipeline*, not on the
rules. They belong in the artifact.

### 2.3 Permissive Mode as a Deliberate Default

The extension is designed so that v1.0 artifacts run unchanged under a v1.1
runtime. An artifact with no `agents` key runs in permissive mode: any caller
may act. This is an auditable, deliberate choice — not a security failure.
Compliant tools SHOULD warn when producing a permissive-mode artifact. They
MUST NOT prevent sealing.

---

## 3. Artifact Extension

A NOMOS-SPEC-002 artifact extends the NOMOS-SPEC-001 structure with one
optional top-level field:

```json
{
  "artifact_id": "...",
  "spec_version": "NOMOS-SPEC-002",
  "agents": {
    "<agent-id>": { ... }
  },
  "rules": [ ... ],
  "seal": { ... }
}
```

The `spec_version` field MUST be set to `"NOMOS-SPEC-002"` when the `agents`
field is present and non-empty. A NOMOS-SPEC-001 runtime that encounters
`spec_version: "NOMOS-SPEC-002"` MUST refuse to execute and return a
`spec_version_unsupported` error, per NOMOS-SPEC-001 §3.3.

The `agents` field, when present, MUST be included in the seal hash
computation. See §11.

---

## 4. Agent Identifier

The key in the `agents` map is the **agent identifier** — the stable string
used by callers to identify themselves in execution requests.

**Syntax:**

```
agent-id = 1*( ALPHA / DIGIT / "-" / "_" )
```

Implementations MUST reject agent identifiers that contain whitespace, dots,
or path separators. Maximum length: 128 characters.

Agent identifiers SHOULD be:
- Stable across deployments (do not use UUIDs or timestamps)
- Lowercase (e.g. `risk-scorer`, not `Risk_Scorer`)
- Descriptive of the agent's role in the pipeline

---

## 5. `AgentDefinition` Schema

Each value in the `agents` map MUST conform to the following schema:

```json
{
  "display_name": "<string>",
  "permissions":  [ "<action-name>", ... ],
  "cannot_call":  [ "<action-name>", ... ],
  "authority":    { "<scope>": true|false },
  "output_contract": {
    "required_fields": [ "<field>", ... ],
    "schema": { }
  },
  "constraints":  [
    { "field": "<field-path>", "operator": "lt|lte|gt|gte|eq|neq", "value": <number|boolean|string> }
  ],
  "audit_level":  "minimal" | "standard" | "forensic"
}
```

### 5.1 `display_name` (OPTIONAL)

Human-readable label for this agent role. MUST NOT be used by the runtime for
any guard decision. Maximum 256 characters.

### 5.2 `permissions` (REQUIRED)

An array of action names from the artifact's `execution.actions` that this
agent MAY propose. Any action not in this list is blocked in Phase 4 of the
guard. An empty array means the agent may not trigger any action.

Values MUST be strings. Duplicate values MUST be deduplicated by runtimes (no
error). Action names not present in `execution.actions` SHOULD generate a
warning but MUST NOT cause a seal or validation failure.

### 5.3 `cannot_call` (OPTIONAL)

An explicit deny list. Actions in this array are blocked regardless of
`permissions`. The deny list takes precedence over the allow list. This is
enforced in Phase 3 of the guard — the only phase that produces a hard block
in advisory mode.

Rationale: the deny list handles cases where an agent has broad permissions
but must be explicitly prevented from a specific high-risk action. Downgrading
deny list violations to advisory defeats its purpose.

### 5.4 `authority` (OPTIONAL, RESERVED)

Named authority overrides this agent holds. Keys are authority scope names;
values indicate whether the agent holds the authority. **Runtimes MUST store
and expose this field but MUST NOT gate execution on it in this version.**
The authority evaluation model is defined in a future specification.

### 5.5 `output_contract` (OPTIONAL, RESERVED)

Declares the fields this agent MUST include in its output before the runtime
passes it downstream. **Not evaluated by the runtime in this version.** Stored
and exposed for tooling use only.

### 5.6 `constraints` (OPTIONAL)

An array of `SpecAgentConstraint` objects evaluated by the runtime guard
(Phase 5) against the incoming request payload before any rule fires.

Each constraint has three fields:

| Field | Type | Notes |
|---|---|---|
| `field` | string | Path to the input field to check (e.g. `"risk_score"`) |
| `operator` | string | One of `lt`, `lte`, `gt`, `gte`, `eq`, `neq` |
| `value` | number \| boolean \| string | Threshold or target value |

Operator semantics:

| Operator | Meaning | Types |
|---|---|---|
| `lt` | input strictly less than value | number |
| `lte` | input less than or equal to value | number |
| `gt` | input strictly greater than value | number |
| `gte` | input greater than or equal to value | number |
| `eq` | input equals value | number, boolean, string |
| `neq` | input does not equal value | number, boolean, string |

Constraints are evaluated independently. Constraints are ANDed — if any
constraint is violated, Phase 5 emits `guard_constraint_violated` and returns.

**Missing fields are skipped.** If `request.input_data[c.field]` is absent,
the constraint does not fire. This is intentional: partial-schema callers are
not rejected. Runtimes that require field presence SHOULD use `output_contract`
on the upstream agent.

**Type mismatch is skipped.** Numeric operators (`lt`, `lte`, `gt`, `gte`)
only fire when both `inputValue` and `c.value` are numbers. A string-encoded
number (e.g. `"0.7"`) does not satisfy a numeric constraint. Callers MUST
send numeric values for numeric fields.

```json
"constraints": [
  { "field": "risk_score",   "operator": "lt",  "value": 0.6 },
  { "field": "review_tier",  "operator": "eq",  "value": "standard" },
  { "field": "is_retry",     "operator": "neq", "value": true }
]
```

### 5.7 `audit_level` (OPTIONAL)

Overrides `governance.compliance.logging_level` for all calls by this agent.
Valid values: `"minimal"`, `"standard"`, `"forensic"`. Defaults to
`"standard"`. See §8 for field definitions at each level.

---

## 6. Runtime Guard Algorithm

A NOMOS-SPEC-002 compliant runtime MUST execute the following six phases, in
order, before calling the rule evaluation pipeline. The guard runs on every
execution request.

### 6.1 Modes

The guard operates in one of two modes, controlled by runtime configuration:

- **Advisory mode** (RECOMMENDED default): Phase 3 hard-blocks; Phases 2, 4,
  and 6 escalate. Execution proceeds with `guard_advisory_fail: true` tagged
  on the result.
- **Enforce mode**: All BLOCK results terminate execution. No downgrade.

Runtimes MUST document which mode is active. Mode switching MUST NOT require
artifact re-sealing.

### 6.2 Phase Definitions

```
PROCEDURE NomosGuard(artifact, request):

  // Phase 1 — Manifest presence
  IF artifact.agents IS NULL OR artifact.agents == {}:
    EMIT guard_event(type="guard_permissive", agent=request.agent_id)
    RETURN PASS

  // Phase 2 — Agent registration
  agent_def = artifact.agents[request.agent_id]
  IF agent_def IS NULL:
    EMIT guard_event(type="guard_unknown_agent", agent=request.agent_id)
    RETURN ESCALATE(phase=2, reason="unregistered_agent")
    // Advisory: proceed. Enforce: BLOCK.

  // Phase 3 — Deny list (hard block in both modes)
  IF request.action IN agent_def.cannot_call:
    EMIT guard_event(type="guard_deny_list_hit",
                     agent=request.agent_id,
                     action=request.action)
    RETURN BLOCK(phase=3, reason="deny_list")

  // Phase 4 — Allow list
  IF request.action NOT IN agent_def.permissions:
    EMIT guard_event(type="guard_permission_denied",
                     agent=request.agent_id,
                     action=request.action)
    RETURN BLOCK(phase=4, reason="permission_not_granted")
    // Advisory: proceed with advisory tag. Enforce: BLOCK.

  // Phase 5 — Structured constraints
  FOR EACH constraint c IN agent_def.constraints:
    input_val = request.input_data[c.field]
    IF input_val IS UNDEFINED: CONTINUE  // missing field → skip
    violated = EVALUATE(input_val, c.operator, c.value)
    IF violated:
      EMIT guard_event(type="guard_constraint_violated",
                       agent=request.agent_id,
                       field=c.field,
                       operator=c.operator,
                       expected=c.value,
                       actual=input_val)
      RETURN BLOCK(phase=5, reason="constraint_violated")
      // Advisory: ESCALATE. Enforce: BLOCK.

  // Phase 6 — Audit level
  required_level = agent_def.audit_level ?? "standard"
  IF NOT request.audit_context SATISFIES required_level:
    EMIT guard_event(type="guard_audit_insufficient",
                     agent=request.agent_id,
                     required=required_level)
    RETURN ESCALATE(phase=6, reason="insufficient_audit_context")
    // Advisory: proceed with advisory tag. Enforce: BLOCK.

  EMIT guard_event(type="guard_pass",
                   agent=request.agent_id,
                   action=request.action)
  RETURN PASS
```

### 6.3 Guard Events

All guard decisions MUST be emitted to the artifact's audit stream. Guard
events use the `guard_` type prefix.

| Event type | Phase | Condition |
|---|---|---|
| `guard_permissive` | 1 | No agents manifest; permissive pass-through |
| `guard_unknown_agent` | 2 | `agent_id` not in manifest |
| `guard_deny_list_hit` | 3 | Action in `cannot_call` |
| `guard_permission_denied` | 4 | Action not in `permissions` |
| `guard_constraint_violated` | 5 | Input field fails a `constraints` check |
| `guard_audit_insufficient` | 6 | Call does not meet audit level |
| `guard_pass` | — | All phases passed |

Guard events MUST be included even in `minimal` audit level. The guard audit
trail MUST NOT be suppressible.

---

## 7. Permissive Mode

An artifact with `agents: {}` or no `agents` key runs in permissive mode.

In permissive mode, a NOMOS-SPEC-002 runtime:

- MUST skip Phases 2–6
- MUST emit a `guard_permissive` event for each execution
- MUST tag the execution result with `guard_mode: "permissive"`
- MUST NOT reject the execution request

Permissive mode is appropriate for development environments, single-tenant
deployments with a known, trusted caller, and early-stage artifacts. It is
not appropriate for production multi-agent pipelines or artifacts distributed
to third parties.

Compliant authoring tools SHOULD present a non-blocking advisory to the
author when producing a permissive-mode artifact. The advisory MUST NOT
prevent sealing.

---

## 8. Audit Level Semantics

The `audit_level` field overrides the global logging level for calls by that
agent. Levels are cumulative.

| Level | Minimum required fields |
|---|---|
| `minimal` | `artifact_id`, `agent_id`, `action`, `outcome`, guard event |
| `standard` | All `minimal` + `decision_trace`, `constraint_trace`, `timestamp` |
| `forensic` | All `standard` + full input payload, all rule evaluations, guard phase results, hash chain entry |

A runtime MUST NOT downgrade the audit level below what the agent's definition
requires, regardless of the global artifact setting.

---

## 9. Execution Request Extension

Execution requests to a NOMOS-SPEC-002 runtime MUST include an `agent_id`
field when the artifact's `agents` manifest is non-empty.

```json
{
  "artifact_id": "art_1c76283d-fecc-4dd6-b33e-0e3a13407933",
  "agent_id":    "risk-scorer",
  "action":      "escalate",
  "context":     { ... }
}
```

If `agent_id` is absent and the artifact has a non-empty agents manifest:
- In advisory mode: the call is treated as an unregistered agent (Phase 2
  escalate) and proceeds.
- In enforce mode: the call is blocked at Phase 2.

If `agent_id` is absent and the artifact is in permissive mode: the call
proceeds normally. `agent_id` is recorded as `null` in the audit trail.

---

## 10. Reserved Fields

The following fields are defined in §5 but NOT evaluated by the runtime in
this version. Implementations:

- MUST store these fields when present in a sealed artifact
- MUST expose them via the artifact read API without modification
- MUST NOT gate execution or produce errors based on their values
- MAY surface them in authoring tooling for informational purposes

| Field | Future use |
|---|---|
| `authority` | Multi-agent authority override evaluation |
| `output_contract` | Downstream field validation before propagation |

---

## 11. Immutability

The `agents` manifest is included in the seal hash. A v1.1 sealed artifact's
agent permissions, deny lists, and audit levels are cryptographically bound to
the same hash as the rules.

Consequence: changing an agent's permissions requires creating a new sealed
version of the artifact with a new `artifact_id` or incremented `version`.
The audit trail can then unambiguously record which agents manifest was in
effect for any historical decision.

A future specification MAY define a **mutable agents manifest** — a separately
signed document linked to an artifact by `artifact_id` but excluded from the
seal hash. This would allow the caller set to evolve without re-sealing the
rules. Until that specification is published, compliant runtimes MUST treat
the `agents` field as sealed and immutable.

---

## 12. Conformance

A runtime is NOMOS-SPEC-002 conformant if it satisfies all NOMOS-SPEC-001
conformance requirements AND:

**MUST:**
- Execute the six-phase guard before every rule evaluation call
- Hard-block on Phase 3 (deny list) in both advisory and enforce mode
- Emit all guard event types defined in §6.3
- Include guard events in the audit trail at all audit levels
- Tag permissive-mode executions with `guard_mode: "permissive"`
- Store and expose `authority` and `output_contract` without modification
- Evaluate `constraints` in Phase 5 per §5.6
- Emit `guard_constraint_violated` on any constraint failure
- Include the `agents` field in seal hash computation

**MUST NOT:**
- Gate execution on `authority` or `output_contract` values
- Suppress guard audit events
- Allow `agent_id` omission to bypass Phase 2 in enforce mode

**SHOULD:**
- Default to advisory mode
- Warn authoring tools when sealing a permissive-mode artifact
- Validate `permissions` and `cannot_call` values against `execution.actions`
  at seal time (warning, not error)

---

## 13. Security Considerations

### 13.1 Agent ID Spoofing

The `agent_id` field in execution requests is caller-supplied. A malicious
caller can claim any agent identity. The guard does not authenticate the caller
— it only checks whether the claimed identity is allowed to perform the
requested action.

Authentication of the caller's claimed identity is outside the scope of this
specification. Deployments requiring caller authentication SHOULD use
transport-layer credentials (API keys, mutual TLS, signed JWTs) to bind the
authenticated identity to the `agent_id` field before the execution request
reaches the runtime.

### 13.2 Permissive Mode Exposure

Artifacts sealed in permissive mode provide no caller verification. The audit
trail records all calls, but there is no mechanism to detect unauthorized
callers — only to observe their behavior after the fact. Operators SHOULD
monitor the `guard_permissive` event rate and migrate to a registered agents
manifest when the caller set stabilizes.

### 13.3 Deny List Completeness

The deny list (`cannot_call`) is only as complete as the author makes it.
An agent with `permissions: ["approve", "escalate"]` and an empty `cannot_call`
is not blocked from `approve` — it is explicitly permitted. The allow list is
the primary control. The deny list is an additional belt-and-suspenders check
for high-risk actions where the author wants a hard guarantee that overrides
any future permission additions.

---

## 14. Examples

### 14.1 Artifact with Two Agents

```json
{
  "artifact_id":  "art_1c76283d-fecc-4dd6-b33e-0e3a13407933",
  "spec_version": "NOMOS-SPEC-002",
  "version":      "1.0.0",
  "confidence":   "CERTIFIED",
  "agents": {
    "loan-processor": {
      "display_name": "Loan Processing Agent",
      "permissions":  ["flag", "hold", "calculate"],
      "cannot_call":  ["auto_approve"],
      "audit_level":  "standard"
    },
    "compliance-reviewer": {
      "display_name": "Compliance Review Agent",
      "permissions":  ["auto_approve", "reject", "escalate"],
      "cannot_call":  [],
      "audit_level":  "forensic"
    }
  },
  "rules": [ "..." ],
  "seal": {
    "status":    "sealed",
    "hash":      "2aaa093c9d96f86830c3472e967c3425420ff2fff16daf34b01a077fc7f027ad",
    "algorithm": "SHA-256",
    "sealed_at": "2026-06-05T14:34:26.988Z"
  }
}
```

In this configuration:
- `loan-processor` can flag, hold, and calculate. It can NEVER call
  `auto_approve` regardless of rule outcome (Phase 3 hard block).
- `compliance-reviewer` can approve, reject, and escalate. Every call is
  logged at forensic level.
- Any agent not listed (e.g. `bulk-processor`) is unregistered: blocked in
  enforce mode, escalated in advisory mode.
- A call with no `agent_id` is treated as unregistered.

### 14.2 Permissive Artifact (NOMOS-SPEC-001 backward compatibility)

```json
{
  "artifact_id":  "art_legacy_001",
  "spec_version": "NOMOS-SPEC-001",
  "rules": [ "..." ],
  "seal": { "..." }
}
```

A NOMOS-SPEC-002 runtime receiving this artifact skips Phases 2–6, emits
`guard_permissive` on every call, and tags results `guard_mode: "permissive"`.
No error. No modification to the artifact.

---

## Changelog

| Version | Date | Change |
|---|---|---|
| 1.1.0 draft | 2026-06-05 | Initial publication |
