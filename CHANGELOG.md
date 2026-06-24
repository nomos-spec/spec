# Changelog

All notable changes to the NOMOS Protocol specification are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Spec versions follow [Semantic Versioning](https://semver.org/).

---

## [NOMOS-SPEC-003 v1.3.0] — 2026-06-24

Deterministic replay — closes the regulatory audit requirement.

### Added (NOMOS-SPEC-003 v1.3.0)

- **§8 Deterministic replay** — `execution_at` optional field in the execution
  request; runtime uses that timestamp for all temporal bound checks; future
  timestamps rejected with `INVALID_EXECUTION_AT` (422); determinism guarantee:
  same artifact + same inputs + same `execution_at` → identical verdict always;
  replay executions marked `replay: true` in response and audit trail; SHOULD NOT
  increment staleness deltas or drift metrics
- **§9.1 Conformance** — updated to include deterministic replay as requirement 7;
  conformance levels updated: Full now requires §3–§8
- **§10.3 Security** — replay integrity considerations: future timestamp rejection,
  audit marking, determinism transparency
- **`schema/execution-response.schema.json`** — added `replay` boolean and
  `execution_at` string fields; added `expired_rules` string array

---

## [NOMOS-SPEC-003 v1.2.0] — 2026-06-24

Temporal validity and staleness signalling — Spec 3 foundations.

### Added (NOMOS-SPEC-003)

- **`spec/NOMOS-SPEC-003.md`** — new spec document: temporal bounds on rules + staleness signal
- **§3 Temporal validity** — `valid_from` and `valid_until` optional fields on Rule; half-open interval `[valid_from, valid_until)`; rules outside active window are skipped without error
- **§4 Runtime algorithm** — execution instant captured once per call; all temporal bounds evaluated against the same instant; expired rules do not contribute to verdict
- **§5 Audit trace extension** — `result: "expired"` added to the decision trace result union; every skipped rule produces a trace entry so the audit record reflects the complete rule set at decision time
- **§6 Staleness signal** — triangulation baseline (`triangulated_at`, `decision_volume_at_triangulation`) recorded at seal time; staleness delta computed after each execution; advisory emitted when delta ≥ threshold (default 500)
- **§7 Response extension** — `staleness_advisory` optional object in execution response: `triangulated_at`, `decisions_since_triangulation`, `threshold`, `recommendation`; never affects verdict

### Updated (schemas)

- **`schema/rule.schema.json`** — added `valid_from` and `valid_until` optional string (date-time) fields
- **`schema/execution-response.schema.json`** — added `staleness_advisory` optional object with required sub-fields

---

## [Repository] — 2026-06-11

World-class gap closure: error catalog, data contract formalization, conformance test vectors, artifact versioning semantics, idempotency guarantee, five new domain examples, and deprecation policy.

### Added (NOMOS-SPEC-001)

- **§3.2 Version lifecycle** — normative rules for when to increment MAJOR / MINOR / PATCH; in-flight execution behaviour; re-sealing requirements
- **§3.9 `data_contract`** — formal definition of the optional `data_contract` field (previously implemented in the runtime but absent from the spec); `required_fields` is the normative constraint; `field_types` is informational
- **§6.5 Idempotency** — `request_id` is the idempotency key; duplicate within dedup window returns `cached: true` without a new audit entry; `request_id` as primary key is now normative
- **§11 Error Catalog** — comprehensive table of all machine-readable error codes (`spec_version_unsupported`, `seal_verification_failed`, `artifact_not_found`, `data_contract_violation`, `confidence_tier_invalid`, `duplicate_request_id`, `chain_corruption`, `unsupported_operator`, `unknown_agent`, `deny_list_violation`); standard error response envelope (`code`, `message`, `hint`, `doc_url`, `request_id`)

### Added (schemas)

- **`schema/artifact.schema.json`** — `data_contract` optional object with `required_fields: string[]` and `field_types: object`

### Added (conformance)

- **`conformance/vectors/`** — 12 deterministic test vectors for SDK authors:
  - v01–v03: verdict correctness (`eq` allow, `gt` deny, no-match default)
  - v04–v06: conflict resolution (`first_match`, `collect_and_resolve`, `highest_priority`)
  - v07–v09: missing context / escalation (`data_contract_violation`, unknown operator, AND branch partial)
  - v10–v12: seal security (tampered payload, unknown spec_version, duplicate `request_id`)
- **`conformance/vectors/README.md`** — vector format spec and usage guide
- **`conformance/run.ts`** — extended to run vector suite; 22 total tests (10 structural + 12 vectors)

### Added (examples)

- **`examples/insurance_underwriting_v1.nomos`** — property insurance; `in`, `gte`, `collect_and_resolve`; 6 rules; includes `data_contract`
- **`examples/procurement_approval_v1.nomos`** — B2B procurement; monetary thresholds, multi-level escalation, `first_match`; 6 rules
- **`examples/content_moderation_v1.nomos`** — trust & safety; `in`, `nin`, `and`; repeat-violator escalation; 6 rules
- **`examples/access_control_v1.nomos`** — IAM / zero-trust; `in` for role arrays, `highest_priority`; nested AND conditions; 6 rules
- **`examples/credit_scoring_v1.nomos`** — consumer credit; `CERTIFIED` confidence; `data_contract`; intentional contradiction in `contradiction_report`; 6 rules

### Added (governance)

- **`DEPRECATION.md`** — formal deprecation policy: 3-year minimum support window, 12-month notice before End of Life, per-stakeholder guidance, artifact migration steps

---

## [NOMOS-SPEC-001] — 2026-01-15

Initial public release of the NOMOS Protocol specification.

### Added

- **§1–2** Conventions and terminology (RFC 2119 keywords, full glossary)
- **§3** Artifact structure: `artifact_id`, `version`, `spec_version`, `confidence`, `domain`, `rules`, `contradiction_report`, `readiness`, `seal`
- **§4** Rule Expression Language: condition AST with leaf nodes (`eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `nin`, `exists`, `regex`) and branch nodes (`and`, `or`, `not`); conflict resolution modes (`first_match`, `collect_and_resolve`, `highest_priority`)
- **§5** Confidence classification: `DECLARED` (policy-only) and `CERTIFIED` (triangulated against behavioral data)
- **§6** Execution model: request format, 6-step evaluation pipeline, verdict schema, missing context handling
- **§7** Audit trail: entry schema, SHA-256 hash chain, chain verification requirements
- **§8** Sealing procedure: JCS/RFC 8785 canonicalization → SHA-256 → HMAC-SHA256; verification steps; key rotation guidance
- **§9** Conformance requirements for runtimes and artifact producers
- **§10** Security considerations: seal key protection, replay attacks, context injection, audit trail integrity, confidence tier integrity
- `schema/artifact.schema.json` — JSON Schema (Draft 2020-12) for `.nomos` artifacts
- `schema/rule.schema.json` — JSON Schema for rule objects including recursive condition AST
- `examples/lending_policy_v1.nomos` — DECLARED example (public library lending policy, 5 rules)
- `examples/healthcare_triage_v1.nomos` — CERTIFIED example (emergency department triage, 5 rules)
- `examples/minimal_v1.nomos` — minimal DECLARED example (2 rules, for onboarding)
- `verify/verify.py` — reference verifier, Python stdlib only
- `verify/verify.ts` — reference verifier, Node.js built-in crypto only

---

## [NOMOS-SPEC-002] — 2026-06-05 (Active)

Multi-agent governance extension. Adds caller-identity verification to the
NOMOS execution model. NOMOS-SPEC-001 artifacts remain valid without
modification — the `agents` field is optional and defaults to permissive mode.

### Added

- **`agents` manifest** — top-level optional field mapping agent identifiers
  to `AgentDefinition` objects; included in seal hash
- **`AgentDefinition`** — `permissions` (allow list), `cannot_call` (deny
  list), `constraints` (Phase 5 evaluated), `audit_level` override, plus
  reserved fields `authority` and `output_contract` for future versions
- **Runtime guard** — six-phase algorithm executed before rule evaluation:
  manifest presence → agent registration → deny list → allow list →
  constraints → audit level
- **Phase 3 hard-block** — deny list violations block in both advisory and
  enforce mode; cannot be downgraded
- **Phase 5 constraints evaluation** — structured `SpecAgentConstraint[]`
  array evaluated against request payload before rule execution
- **Permissive mode** — artifacts with no agents manifest pass through the
  guard untouched; every call tagged `guard_mode: "permissive"` in audit trail
- **Advisory / enforce modes** — advisory (default) escalates violations
  without blocking; enforce mode terminates on any violation
- **Guard audit events** — `guard_permissive`, `guard_unknown_agent`,
  `guard_deny_list_hit`, `guard_permission_denied`, `guard_constraint_violated`,
  `guard_audit_insufficient`, `guard_pass`; emitted at all audit levels
  including `minimal`
- **Audit level semantics** — `minimal`, `standard`, `forensic` field sets
  defined; per-agent override of global logging level
- **Conformance checklist** — MUST/SHOULD requirements for SPEC-002 runtimes
- **`spec/NOMOS-SPEC-002.md`** — full specification document

### Changed — 2026-06-08

- **`constraints` field type** — changed from `Record<string, number|boolean|string>`
  (untyped key-value bag) to `SpecAgentConstraint[]` (structured array).
  **Breaking change for any implementation that used the old Record format.**
  Migration: replace `{ "require_risk_score_below": 0.6 }` with
  `[{ "field": "risk_score", "operator": "lt", "value": 0.6 }]`.
- **Phase 5 is now evaluated** — runtimes MUST evaluate `constraints` in
  Phase 5. Prior requirement to skip Phase 5 is removed.
- **New guard event** — `guard_constraint_violated` added for Phase 5 failures.
- **Status** — moved from Draft to Active.

### Reserved (defined, not evaluated in this version)

- `authority` — multi-agent authority override evaluation
- `output_contract` — downstream field validation before propagation

---
