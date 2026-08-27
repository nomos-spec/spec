/**
 * Delegation scope (NOMOS-SPEC-007 §3.4) — the algebra behind "under what conditions".
 *
 * A key certificate can say a child key is authorized to sign only for some subset of artifacts.
 * Before this module that string was signed, carried, and then never read: a certificate reading
 * `scope: "authority:lending"` placed no actual limit on what the certified key could sign. The
 * badge said third floor and nobody checked the floor.
 *
 * Pure and dependency-free, like key-cert.ts itself. Nothing here touches rule evaluation:
 * scope constrains WHO MAY SIGN WHAT, never what an artifact's rules decide once the signer is
 * accepted.
 *
 * ── Grammar ──────────────────────────────────────────────────────────────────────────────────
 * A scope is a space-separated set of `dimension:value` terms, ALL of which must hold (AND).
 * At most one term per dimension. An absent or empty scope is UNRESTRICTED — every certificate
 * issued before this existed has no scope, and must keep meaning exactly what it meant.
 *
 *   (absent)                              → unrestricted
 *   artifact:khda_teacher_licensing       → may sign that one artifact and nothing else
 *   industry:financial/lending            → may sign artifacts declaring that industry or a
 *                                            descendant of it (financial/lending/mortgages)
 *   industry:financial artifact:loan_v1   → both constraints must hold
 *
 * ── Which dimensions exist, and why so few ───────────────────────────────────────────────────
 * Only dimensions whose match can actually be TRUSTED are supported. `meta.industry` in real
 * artifacts holds loose tokens ("library", "healthcare") and `meta.jurisdictions` holds free
 * prose ("State of California", "NHS England"). A matcher over free prose is string comparison
 * dressed up as authorization — it would pass silently when an issuer writes "CA" instead of
 * "State of California", which is strictly worse than today's honest no-op. So `jurisdiction:`
 * is deliberately NOT supported until a normalized identifier exists; see SPEC-007 §8.2.
 *
 * ── Fail closed, twice ───────────────────────────────────────────────────────────────────────
 * 1. If a scope constrains a dimension the artifact does not declare, the artifact is OUT of
 *    scope. "You were authorized only for financial services; this artifact doesn't say what it
 *    covers" is not a pass.
 * 2. An UNRECOGNIZED dimension puts the artifact out of scope rather than being skipped. This is
 *    X.509's critical-extension rule: a verifier that silently ignores a constraint it doesn't
 *    understand lets a future dimension be unenforceable against every older verifier.
 */

export interface ScopeTerms {
  /** dimension → value. An empty map means unrestricted. */
  terms: Record<string, string>;
}

/** Dimensions this version knows how to evaluate. Anything else fails closed (see header). */
export const KNOWN_SCOPE_DIMENSIONS = ['artifact', 'industry'] as const;
export type ScopeDimension = (typeof KNOWN_SCOPE_DIMENSIONS)[number];

export const UNRESTRICTED: ScopeTerms = { terms: {} };

export type ScopeParseResult =
  | { ok: true; scope: ScopeTerms }
  | { ok: false; detail: string };

/**
 * Parses a scope string. Rejects malformed input rather than ignoring the bad parts — a scope
 * that partially parsed would silently grant more than its author wrote.
 */
export function parseScope(raw: string | null | undefined): ScopeParseResult {
  if (raw === undefined || raw === null || raw.trim() === '') return { ok: true, scope: UNRESTRICTED };
  const terms: Record<string, string> = {};
  for (const token of raw.trim().split(/\s+/)) {
    const sep = token.indexOf(':');
    if (sep <= 0 || sep === token.length - 1) {
      return { ok: false, detail: `Scope term ${JSON.stringify(token)} is not of the form dimension:value.` };
    }
    const dimension = token.slice(0, sep);
    const value = token.slice(sep + 1);
    if (dimension in terms) {
      return { ok: false, detail: `Scope names dimension ${JSON.stringify(dimension)} more than once; a dimension may appear at most once.` };
    }
    terms[dimension] = value;
  }
  return { ok: true, scope: { terms } };
}

/**
 * Hierarchical containment for a single value, '/'-delimited. `financial` contains
 * `financial/lending`; it does NOT contain `financial-services` — the separator must fall on a
 * segment boundary, or a prefix match would let `financial` swallow any string starting with it.
 *
 * `artifact` is exact-match only (see valueContains' caller): globbing an artifact id would
 * reintroduce exactly the fuzzy matching this design avoids elsewhere.
 */
function valueContains(broader: string, narrower: string): boolean {
  if (broader === narrower) return true;
  return narrower.startsWith(broader + '/');
}

function dimensionContains(dimension: string, broader: string, narrower: string): boolean {
  if (dimension === 'artifact') return broader === narrower; // exact only, never a prefix
  return valueContains(broader, narrower);
}

/**
 * May `child` be issued under `parent`? A child may add dimensions the parent doesn't constrain
 * (that narrows), and may narrow a dimension the parent does constrain. It may NEVER widen one.
 *
 * Dimensions the parent constrains and the child omits are not a violation — they are inherited,
 * because the effective scope accumulates (see mergeScopes). Omitting is not an escape route.
 */
export function isNarrowerOrEqual(child: ScopeTerms, parent: ScopeTerms): { ok: true } | { ok: false; dimension: string; detail: string } {
  for (const [dimension, childValue] of Object.entries(child.terms)) {
    const parentValue = parent.terms[dimension];
    if (parentValue === undefined) continue; // parent places no limit on this dimension
    if (!dimensionContains(dimension, parentValue, childValue)) {
      return {
        ok: false,
        dimension,
        detail: `Certificate widens ${dimension} from ${JSON.stringify(parentValue)} to ${JSON.stringify(childValue)} — a delegation can never grant more than the delegator holds.`,
      };
    }
  }
  return { ok: true };
}

/**
 * The effective scope after applying `child` beneath `parent`: the UNION of their terms, which is
 * the INTERSECTION of the artifact sets they denote. Union (not replacement) is what stops a
 * later certificate shedding an earlier constraint simply by not mentioning it.
 * Assumes isNarrowerOrEqual already passed, so a shared dimension's child value is the narrower.
 */
export function mergeScopes(parent: ScopeTerms, child: ScopeTerms): ScopeTerms {
  return { terms: { ...parent.terms, ...child.terms } };
}

export type ScopeCheck =
  | { ok: true }
  | { ok: false; dimension: string; detail: string };

/**
 * Does this artifact fall inside `scope`? Reads only DECLARED fields on the artifact — never
 * infers an industry or an id that the issuer didn't state, since inferring one would let an
 * artifact drift into scope without anyone having declared it there.
 */
export function artifactInScope(artifact: any, scope: ScopeTerms): ScopeCheck {
  for (const [dimension, required] of Object.entries(scope.terms)) {
    if (!(KNOWN_SCOPE_DIMENSIONS as readonly string[]).includes(dimension)) {
      return {
        ok: false,
        dimension,
        detail: `Scope constrains unrecognized dimension ${JSON.stringify(dimension)}; this verifier cannot evaluate it and will not ignore it.`,
      };
    }

    if (dimension === 'artifact') {
      const declared = artifact?.meta?.artifact_id;
      if (typeof declared !== 'string' || !declared) {
        return { ok: false, dimension, detail: 'Scope constrains artifact id, but the artifact declares no meta.artifact_id.' };
      }
      if (declared !== required) {
        return { ok: false, dimension, detail: `Scope permits artifact ${JSON.stringify(required)}; this artifact is ${JSON.stringify(declared)}.` };
      }
      continue;
    }

    if (dimension === 'industry') {
      const declared = artifact?.meta?.industry;
      if (typeof declared !== 'string' || !declared) {
        return { ok: false, dimension, detail: 'Scope constrains industry, but the artifact declares no meta.industry.' };
      }
      if (!valueContains(required, declared)) {
        return { ok: false, dimension, detail: `Scope permits industry ${JSON.stringify(required)}; this artifact declares ${JSON.stringify(declared)}.` };
      }
      continue;
    }
  }
  return { ok: true };
}

/** Human-readable rendering, for verdict details and audit records. */
export function formatScope(scope: ScopeTerms): string {
  const entries = Object.entries(scope.terms);
  if (entries.length === 0) return '(unrestricted)';
  return entries.map(([d, v]) => `${d}:${v}`).join(' ');
}
