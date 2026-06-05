# Changelog

All notable changes to the NOMOS Protocol specification are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Spec versions follow [Semantic Versioning](https://semver.org/).

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

## [NOMOS-SPEC-002] — 2026-06-05 (Draft)

Multi-agent governance extension. Adds caller-identity verification to the
NOMOS execution model. NOMOS-SPEC-001 artifacts remain valid without
modification — the `agents` field is optional and defaults to permissive mode.

### Added

- **`agents` manifest** — top-level optional field mapping agent identifiers
  to `AgentDefinition` objects; included in seal hash
- **`AgentDefinition`** — `permissions` (allow list), `cannot_call` (deny
  list), `audit_level` override, plus reserved fields `authority`,
  `output_contract`, and `constraints` for future versions
- **Runtime guard** — six-phase algorithm executed before rule evaluation:
  manifest presence → agent registration → deny list → allow list →
  constraints (reserved) → audit level
- **Phase 3 hard-block** — deny list violations block in both advisory and
  enforce mode; cannot be downgraded
- **Permissive mode** — artifacts with no agents manifest pass through the
  guard untouched; every call tagged `guard_mode: "permissive"` in audit trail
- **Advisory / enforce modes** — advisory (default) escalates violations
  without blocking; enforce mode terminates on any violation
- **Guard audit events** — `guard_permissive`, `guard_unknown_agent`,
  `guard_deny_list_hit`, `guard_permission_denied`, `guard_audit_insufficient`,
  `guard_pass`; emitted at all audit levels including `minimal`
- **Audit level semantics** — `minimal`, `standard`, `forensic` field sets
  defined; per-agent override of global logging level
- **Conformance checklist** — MUST/SHOULD requirements for SPEC-002 runtimes
- **`spec/NOMOS-SPEC-002.md`** — full specification document

### Reserved (defined, not evaluated in this version)

- `authority` — multi-agent authority override evaluation
- `output_contract` — downstream field validation before propagation
- `constraints` — input constraint DSL (syntax undefined)

---
