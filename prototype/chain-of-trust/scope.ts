/**
 * Delegation scope (NOMOS-SPEC-007 §3.4, rev. 1.8 §3.4.1, rev. 1.9 §3.6–§3.8) — the algebra
 * behind "under what conditions".
 *
 * Pure and dependency-free. Nothing here touches rule evaluation: scope constrains WHO MAY SIGN
 * WHAT, never what an artifact's rules decide once the signer is accepted.
 *
 * ── Grammar ──────────────────────────────────────────────────────────────────────────────────
 * A scope is a space-separated set of `dimension:value` terms, ALL of which must hold (AND), at
 * most one per dimension, parsed whole or rejected whole. An absent or empty scope is
 * UNRESTRICTED — authority to seal rules, and nothing else (rev. 1.8 §3.4.1).
 *
 *   artifact:<id>                exactly one artifact
 *   industry:<path>              that industry or a descendant (financial/lending/mortgages)
 *   jurisdiction:<ISO 3166>      that code, or a subdivision of a country code
 *   claim:<f1,f2>                may testify to these facts           (rev. 1.8)
 *   consent:<r1,r2>              may consent in these roles           (rev. 1.8)
 *   suite:<s1,s2>                may sign under these suites          (rev. 1.9 §3.6)
 *   approver:<id>                these keys belong to one person      (rev. 1.9 §3.7)
 *
 * ── Fail closed, twice ───────────────────────────────────────────────────────────────────────
 * 1. A scope that constrains a dimension the artifact does not declare puts it OUT of scope.
 * 2. An UNRECOGNIZED dimension is out of scope, never skipped (X.509's critical-extension rule).
 */
import { isSuite, type Suite } from "./suites.js";

export interface ScopeTerms {
  /** Insertion-ordered: the order of first appearance along the path, root first (§3.8). */
  terms: Record<string, string>;
}

export const ARTIFACT_DIMENSIONS = ["artifact", "industry", "jurisdiction"] as const;
const SET_DIMENSIONS = ["claim", "consent", "suite"];
export const UNRESTRICTED: ScopeTerms = { terms: {} };

export type ScopeParseResult = { ok: true; scope: ScopeTerms } | { ok: false; detail: string };

export function parseScope(raw: string | null | undefined): ScopeParseResult {
  if (raw === undefined || raw === null || raw.trim() === "") return { ok: true, scope: UNRESTRICTED };
  const terms: Record<string, string> = {};
  for (const token of raw.trim().split(/\s+/)) {
    const sep = token.indexOf(":");
    if (sep <= 0 || sep === token.length - 1) return { ok: false, detail: `Scope term ${JSON.stringify(token)} is not of the form dimension:value.` };
    const dimension = token.slice(0, sep), value = token.slice(sep + 1);
    if (dimension in terms) return { ok: false, detail: `Scope names dimension ${JSON.stringify(dimension)} more than once.` };
    if (SET_DIMENSIONS.includes(dimension)) {
      const members = value.split(",");
      if (members.includes("") || new Set(members).size !== members.length) return { ok: false, detail: `Scope term ${JSON.stringify(token)} has an empty or repeated member.` };
      if (dimension === "suite") {
        if (!members.every(isSuite)) return { ok: false, detail: `Scope term ${JSON.stringify(token)} names a suite outside the NOMOS-SPEC-010 registry.` };
        if (members.includes("WebAuthn-ES256") && members.length > 1) return { ok: false, detail: "WebAuthn-ES256 must stand alone in a suite set (rev. 1.9 §3.6)." };
      }
    }
    if (dimension === "approver" && value.includes(",")) return { ok: false, detail: "An approver term names exactly one person (rev. 1.9 §3.7)." };
    terms[dimension] = value;
  }
  return { ok: true, scope: { terms } };
}

const setOf = (v: string) => new Set(v.split(","));
const subset = (inner: string, outer: string) => { const o = setOf(outer); return [...setOf(inner)].every((m) => o.has(m)); };
const ISO_3166 = /^[A-Z]{2}(-[A-Z0-9]{1,3})?$/;

/** Does the grant `broader` cover `narrower` on this dimension? Narrowing and matching alike. */
export function dimensionContains(dimension: string, broader: string, narrower: string): boolean {
  switch (dimension) {
    case "artifact": return broader === narrower;
    case "industry": return narrower === broader || narrower.startsWith(broader + "/");
    case "jurisdiction": return narrower === broader || (broader.length === 2 && narrower.startsWith(broader + "-"));
    case "claim": case "consent": case "suite": return subset(narrower, broader);
    case "approver": return broader === narrower;
    default: return false;
  }
}

export function isNarrowerOrEqual(child: ScopeTerms, parent: ScopeTerms): { ok: true } | { ok: false; dimension: string; detail: string } {
  for (const [dimension, childValue] of Object.entries(child.terms)) {
    const parentValue = parent.terms[dimension];
    if (parentValue === undefined) continue;
    if (!dimensionContains(dimension, parentValue, childValue)) {
      return { ok: false, dimension, detail: `Certificate widens ${dimension} from ${JSON.stringify(parentValue)} to ${JSON.stringify(childValue)} — a delegation never grants more than the delegator holds.` };
    }
  }
  return { ok: true };
}

/** Parent's terms keep their positions; the child's new terms are appended in its own order. */
export function mergeScopes(parent: ScopeTerms, child: ScopeTerms): ScopeTerms {
  return { terms: { ...parent.terms, ...child.terms } };
}

/** §3.6: without a `suite` term a key may use any suite its key type supports, but WebAuthn-ES256. */
export function suitePermitted(scope: ScopeTerms, suite: string): boolean {
  const s = scope.terms.suite;
  return s !== undefined ? setOf(s).has(suite) : suite !== "WebAuthn-ES256";
}

function metaMatches(dimension: string, value: string, meta: any): boolean {
  if (dimension === "artifact") return meta?.artifact_id === value;
  if (dimension === "industry") {
    const ind = meta?.industry;
    return typeof ind === "string" && ind !== "" && dimensionContains("industry", value, ind);
  }
  const codes = meta?.jurisdiction_codes;
  if (!Array.isArray(codes) || codes.length === 0 || !codes.every((c) => typeof c === "string" && ISO_3166.test(c))) return false;
  return codes.every((c) => dimensionContains("jurisdiction", value, c));
}

export type Admission = { ok: true } | { ok: false; dimension: string };

/** §3.8: terms are examined in effective-scope order; the first that refuses the purpose is reported. */
function termRefuses(dimension: string, value: string, meta: any, suite: Suite, allowed: string[]): boolean {
  if ((ARTIFACT_DIMENSIONS as readonly string[]).includes(dimension)) return !metaMatches(dimension, value, meta);
  if (dimension === "suite") return !setOf(value).has(suite);
  return !allowed.includes(dimension);
}

function defaultSuiteRefuses(scope: ScopeTerms, suite: Suite): boolean {
  return scope.terms.suite === undefined && !suitePermitted(scope, suite);
}

/** §3.4, §3.5, §3.6: may a key with this effective scope seal this artifact under this suite? */
export function admitArtifact(meta: any, suite: Suite, scope: ScopeTerms): Admission {
  for (const [d, v] of Object.entries(scope.terms)) if (termRefuses(d, v, meta, suite, [])) return { ok: false, dimension: d };
  return defaultSuiteRefuses(scope, suite) ? { ok: false, dimension: "suite" } : { ok: true };
}

/** rev. 1.8 §3.4.1, rev. 1.9 §3.6–§3.7: may it sign a `kind` statement about `name`, under this
 *  suite, for an act whose authority artifact carries `meta`? The statement's own kind first. */
export function admitStatement(kind: "claim" | "consent", name: string, meta: any, suite: Suite, scope: ScopeTerms): Admission {
  const own = scope.terms[kind];
  if (own === undefined || !setOf(own).has(name)) return { ok: false, dimension: kind };
  const allowed = kind === "consent" ? ["consent", "approver"] : ["claim"];
  for (const [d, v] of Object.entries(scope.terms)) if (termRefuses(d, v, meta, suite, allowed)) return { ok: false, dimension: d };
  return defaultSuiteRefuses(scope, suite) ? { ok: false, dimension: "suite" } : { ok: true };
}

/** "" for an unrestricted scope: a verdict then carries no effective_scope at all. */
export function formatScope(scope: ScopeTerms): string {
  return Object.entries(scope.terms).map(([d, v]) => `${d}:${v}`).join(" ");
}
