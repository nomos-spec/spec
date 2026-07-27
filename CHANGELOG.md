# Changelog

All notable changes to the NOMOS Protocol specification are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Spec versions follow [Semantic Versioning](https://semver.org/).

---

## [NOMOS-SPEC-001 v2.0.0] — 2026-07-27 (Breaking correction)

### Why

An EU AI Act artifact sealed and published on the reference deployment (nomosprotocol.com)
failed validation against this repo's own `schema/artifact.schema.json`. Investigation found
that §3 (Artifact Structure) and §4 (Rule Expression Language) of v1.1.0 described a structure
— top-level `artifact_id`/`version`/`rules`/`domain`/`confidence`/`readiness`/
`contradiction_report`, and a condition-tree object (`{op, field, value, left, right}`) — that
no conformant producer had ever actually emitted. It was written independently of the fielded
implementation and never reconciled against it. This release replaces §3/§4 with the structure
real sealed artifacts actually have, verified directly against the live artifact that failed.
Per `DEPRECATION.md` principle 2, this increments the spec version rather than being published
as editorial errata, because it changes what a conformant producer or runtime must accept.

### Changed (breaking)

- **§3 Artifact Structure** — top-level keys are now `nomos_version, meta, scope, data_contract,
  logic, governance, execution, audit, seal` (plus optional `agents`, `provenance`,
  `attestations`). The v1.1.0 shape (`artifact_id, version, spec_version, confidence, domain,
  rules, contradiction_report, readiness, seal`) is no longer the schema this repo validates
  against.
- **§4 Rule Expression Language** — a decision's `when` is a Nomos-Expr v1 **string**
  (`"invoice_amount > 25000"`), not a condition-tree object. Outcomes are a `then`/`else` array
  of typed objects (`allow | block | escalate | set | emit | action`), not a single
  `action: "ALLOW"|"DENY"|"ESCALATE"` field. §4.5 documents the old tree format as a deprecated,
  internal-only representation — conformant producers MUST NOT emit it.
- `schema/artifact.schema.json`, `schema/rule.schema.json` — rewritten to match.
- All 8 `examples/*.nomos` — rewritten to the new structure and properly re-sealed
  (HMAC-SHA256, the same published test key documented in the README: `deadbeef…`).
- `verify.py`, `verify.ts`, `cli/nomos.ts` — updated wherever they read the artifact's own
  structure (`meta.artifact_id`/`meta.version` instead of top-level; hash computation now
  additionally excludes `attestations`, not just `seal`, per §8.2 — a real, separate bug found
  during this pass, since an artifact with any attestation would previously fail integrity
  verification for a reason unrelated to tampering). `cli/nomos.ts`'s `exec` command now
  includes a real Nomos-Expr v1 tokenizer/evaluator in place of the old condition-tree walker.
  `verify.py`'s HMAC check now falls back from `seal.sig` to `seal.signature` — it previously
  only checked the legacy `sig` field name, unlike `verify.ts`/`cli/nomos.ts`, so it silently
  failed to verify any seal using the newer field name.
- `conformance/` — all 12 test vectors and 6 fixtures converted to the corrected structure;
  `run.ts`'s in-process evaluator rewritten around the real Nomos-Expr v1 parser instead of
  the condition-tree walker; `schema/execution-response.schema.json` corrected (`verdict:
  "proceed"/"escalate"/"deny"` was never real — the real `/api/v1/verify` response uses
  `outcome: "auto_approved"/"auto_rejected"/"escalated"`, and `contradictions` is always an
  empty array in the current implementation, not a live count). Added a new fixture,
  `sealed_no_signature.nomos`, and test `P2-neg`, asserting that `status: "sealed"` with
  `signature: null` is detectable as non-conformant — the exact defect this spec version
  exists to correct, now directly covered by the conformance suite itself.

### Corrected (non-breaking, real-vs-documented gaps found during this pass)

- **§6** — the `ExecutionReceipt` response documented in v1.1.0 is real and matches
  `POST /api/nomos/execute` (Domain execution) almost field-for-field; it was NOT rewritten.
  What was corrected: the endpoint citation in §6.1 (v1.1.0 attributed this receipt to
  `/api/v1/verify-decision`, which is a separate, real endpoint with its own different response
  shape — both are now documented, distinctly, in §6.1/§6.2). §6.9 (idempotency) previously
  asserted `correlation_id`-based response caching that does not exist in either
  implementation — now disclosed as a known gap rather than documented as working behavior.
- **§5** — `DECLARED/VALIDATED/CERTIFIED/PROVEN/SOVEREIGN` and `compiled/proven/sovereign` are
  two separate, real, non-interchangeable vocabularies (public demo artifacts vs. sealed
  Studio/Exchange artifacts respectively) that v1.1.0 conflated into one five-tier ARI-gated
  system. Both are now documented as what they actually are.
- **§7** — the audit-trail hash formula is now `SHA-256(previousHash + "|" + JCS(eventData) +
  "|" + timestamp)`, matching `server/lib/decision-audit.ts` in the reference deployment;
  v1.1.0's formula (`SHA-256(entry_id || artifact_id || ts || verdict || prev_hash)`) did not
  match any real implementation.
- **§11** — the reference deployment's two execution APIs use two different, real error-code
  vocabularies (one has no machine-readable `code` field at all). v1.1.0's unified error catalog
  didn't match either; both are now documented separately, honestly, as inconsistent.
- **§12.3** — `pub_lending_v1` is `DECLARED` tier in the real public-artifact registry, not
  `PROVEN` as v1.1.0's table claimed. The full, real five-artifact list is now given.

---

## [NOMOS-SPEC-001 §3.0] — 2026-07-27 (Clarification)

### Added

- **File extension and media type (§3.0)** — a `.nomos` artifact SHOULD use the `.nomos`
  extension and media type `application/vnd.nomos+json`, not a bare `.json` file with generic
  `Content-Type: application/json`. No change to artifact structure or sealing — this
  clarifies delivery/storage convention only, prompted by a hosted implementation that was
  serving sealed artifacts as `artifact.nomos.json` with `application/json`.

---

## [NOMOS-SPEC-005 v1.5.0] — 2026-07-22 (Draft)

A new, wholly optional capability area: querying **public** artifacts without
authentication. Nothing in NOMOS-SPEC-001–004 changes; a runtime implementing
only the authenticated model in NOMOS-SPEC-001 §6 is unaffected.

### Added (NOMOS-SPEC-005)

- **Public query (§1, MUST)** — `POST /query`-shaped request/response for
  asking a public artifact whether an action is allowed. No API key, no
  `domain_id`. Verdict vocabulary `AUTHORIZED | DENIED | ESCALATED`.
- **Transcript retrieval (§2, MUST)** — `GET /queries/{query_id}`, unchanged,
  any time. `audit_hash` independently re-computable from `{ query_id,
  seal_hash, inputs, verdict, queried_at }` without calling the runtime.
- **Completeness disclosure (`open_higher_priority_count`, §1.4)** — how many
  higher-priority rule conditions were still unresolved at the exact moment a
  verdict was sealed. Lets two structurally different situations — every fact
  known vs. proceeding with facts still missing — stay distinguishable on a
  permanent transcript instead of looking identical. Excluded from
  `audit_hash` (it discloses completeness, it isn't itself an attested fact).
- **Guided interaction (§3, RECOMMENDED)** — a stateless endpoint compiling an
  artifact's own rules into progressive `situation` / `checklist` /
  `conditional_verdict` screens, so a caller doesn't need to already know every
  field name. Labels/definitions MUST be derived deterministically from the
  artifact's own contents — normatively, not from a language model at request
  time. §3.4 prohibits asserting a bundle of facts from one caller choice
  unless each fact is independently confirmable.
- **Decision atlas (§4, OPTIONAL)** — the artifact's full rule set as browsable
  data, grouped by verdict.
- **`schema/public-query-request.schema.json`**, **`schema/public-query-response.schema.json`** — new, additive schemas.

---

## [NOMOS-SPEC-004 v1.4.0] — 2026-07-13

Two optional, backward-compatible capabilities: composable artifacts and third-party attestations. Neither changes how a sealed artifact evaluates — composition is a pre-seal transform, attestation is a post-seal annotation.

### Added (NOMOS-SPEC-004)

- **Composable artifacts (`extends`)** — a base artifact owns shared rules; a child declares an overlay (override / add / remove) and is composed at BUILD time into a single self-contained sealed artifact. §1.2 pins the deterministic merge algorithm (walk base in order; override in place; drop `removed`; append locals; merge variables). A `composition` provenance block (inherited / overridden / removed / local, `extends.seal_hash`) is written before sealing, so it is covered by the seal. "Change once, everywhere" is realised by **re-composition** against a new base with the overlay re-applied. §1.5 requires contradiction detection over the merged set (cross-tree conflicts).
- **Third-party attestations (`attestations`)** — a detached signature by a party OTHER than the issuer (regulator / auditor / authority), made with the attester's OWN key over the artifact's seal hash. Binds to one version, travels with the file, verified with the attester's public key by `kid` at `/.well-known/nomos-signing-keys`. §2.4 mandates BOTH a signature check and a binding check (`artifact_hash == seal.hash`) to block replay. Revocable via `revoked_at`.
- **Seal-hash exclusion (normative)** — the seal now covers the artifact minus **both** `seal` and `attestations`, so an attestation can be appended or removed without invalidating the seal. Backward compatible: a v1.0 artifact has no `attestations`, so the computation is unchanged for all existing artifacts.
- **`schema/artifact.schema.json`** — added optional `composition` and `attestations`; `spec_version` enum extended to include `NOMOS-SPEC-003` and `NOMOS-SPEC-004`.

---

## [Repository] — 2026-07-13

Publicly verifiable seals: asymmetric signing so any party can verify a sealed `.nomos` offline with a public key — no shared secret and no call to the sealing authority. Backward compatible (existing HMAC seals still verify).

### Added / Changed (NOMOS-SPEC-001)

- **§8 Sealing** — **Ed25519 asymmetric signing is now RECOMMENDED.** The authority signs with a private key; anyone verifies with the published public key, which cannot forge a seal. HMAC-SHA256 reclassified as LEGACY (symmetric — not third-party verifiable). The signed message is `JCS({hash, signed_by})`; the seal gains `signature_algorithm`, `signed_by`, `signature` (base64), and `kid`.
- **§8.1 Verification** — restated as two independent, offline checks that both MUST pass: integrity (recompute JCS/SHA-256 hash) and authenticity (Ed25519 against the public key by `kid`, or HMAC with the secret). Clarified why both are required.
- **§8.2 Public key discovery** — `GET /.well-known/nomos-signing-keys` (a key **set**), and `kid = base64url(SHA-256(SPKI-DER(pubkey)))[:16]`.
- **§8.3 Key rotation** — asymmetric keys MAY rotate without invalidating old seals, provided retired public keys stay published; each seal names its signer via `kid`.
- **§9.2 Conformance** — a producer claiming "publicly verifiable" MUST use an asymmetric algorithm and publish its public key; HMAC MUST NOT be represented as publicly verifiable.
- **§10 Security** — private-key vs public-key protection; key-provenance guidance (TLS/DNS today, transparency log for a stronger anchor).
- **`schema/artifact.schema.json`** — the `seal` object is now a `oneOf` of the asymmetric (recommended) and legacy-HMAC forms.
- **Reference verifiers** — `verify/verify.ts` (zero-dep, Node-native Ed25519) and `verify/verify.py` (`cryptography` for Ed25519) upgraded to verify Ed25519 seals via `--url` (fetch published key) or `--pubkey` (offline). Both verify a production-sealed artifact against the published key and reject tampered artifacts.

---

## [NOMOS-SPEC-003 v1.3.1] — 2026-06-24

Closes three underspecification gaps identified in implementer review.

### Changed (NOMOS-SPEC-003 v1.3.1)

- **§6.1 Triangulation baseline** — promoted from two-field hint to a normative
  record schema with four required fields (`artifact_id`, `artifact_version`,
  `triangulated_at`, `decision_volume_at_triangulation`); keyed by
  `artifact_id + artifact_version`; immutability guarantee added ("MUST NOT be
  modified after it is written"); fork semantics defined (forked artifacts have
  no inherited baseline)
- **§6.2 Staleness delta** — "approximate counting is acceptable" clause added;
  exact global counter consistency is not required; implementations MUST NOT
  block responses to achieve it; delta is now keyed per `artifact_id + version`
- **§10.1 Clock integrity** — distributed / microservice skew mitigation pattern
  added: initiating service captures a single timestamp and propagates it via
  `execution_at`; policy runtime uses caller-supplied instant for all temporal
  checks, eliminating inter-service skew

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
