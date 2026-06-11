# NOMOS Protocol — Deprecation Policy

This document defines the support and deprecation lifecycle for NOMOS Protocol specification versions.

---

## Principles

1. **Sealed artifacts are forever valid.** A `.nomos` artifact sealed under a given spec version remains valid under that spec version in perpetuity. Deprecation of a spec version never invalidates existing sealed artifacts.

2. **Breaking changes require a new spec number.** A published specification (e.g. NOMOS-SPEC-001) is immutable once Active. Corrections to the active spec that do not change normative requirements are published as editorial errata. Any change that alters runtime behaviour requires a new spec number.

3. **Minimum 3-year support window.** Each spec version is supported for at least 3 years from its `Published` date, as listed in its header.

4. **12 months' deprecation notice.** Before a spec version transitions from Active to Deprecated, a minimum 12-month notice is given via the CHANGELOG and a pinned notice in the spec document itself.

---

## Spec Version Lifecycle

```
Draft → Active → Deprecated → End of Life
```

| Status | Meaning |
|--------|---------|
| **Draft** | Specification is under development; normative requirements may change |
| **Active** | Specification is stable; runtime implementors SHOULD support it |
| **Deprecated** | Specification will be End-of-Life in ≤ 12 months; new artifacts SHOULD NOT be sealed under it |
| **End of Life** | Conformant runtimes are no longer required to support this spec version; existing artifacts sealed under it remain valid |

---

## Current Status

| Spec Version | Status | Published | Minimum Support Until |
|--------------|--------|-----------|-----------------------|
| NOMOS-SPEC-001 | Active | 2026-01-15 | **2029-01-15** |
| NOMOS-SPEC-002 | Active | 2026-06-05 | **2029-06-05** |

---

## What Deprecation Means for Each Stakeholder

**Artifact producers (NOMOS Studio, CLI seal tool):**
- During Active: freely seal artifacts under this spec version.
- During Deprecated: existing artifacts remain valid; new artifacts SHOULD use the current Active spec version.
- At End of Life: the Studio will warn but not block sealing under the legacy version.

**Runtime implementors:**
- During Active: MUST support this spec version per conformance requirements.
- During Deprecated: MUST continue to support it (runtime support persists until End of Life).
- At End of Life: MAY remove support; MUST document removal in a minor/major release.

**Callers (agents, integrations):**
- During Active: no action required.
- During Deprecated: plan migration to the current spec version before End of Life.
- At End of Life: runtimes are not required to execute artifacts sealed under this version; ensure your artifacts have been re-sealed under an Active spec.

---

## How to Migrate an Artifact to a Newer Spec Version

1. Retrieve the source artifact (unsealed form or Studio project).
2. Update `spec_version` to the target version.
3. Apply any normative changes required by the new spec version (described in CHANGELOG.md).
4. Re-run triangulation and contradiction detection if applicable.
5. Re-seal: increment `version` by at least PATCH and generate a new seal block.
6. Deploy the new artifact and retire the old `artifact_id` + `version` combination from your routing layer.

---

*Last updated: 2026-06-11*
