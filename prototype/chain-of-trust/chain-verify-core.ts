/**
 * PROTOTYPE — pure chain-verification core, NOMOS-SPEC-007 rev. 1.9
 *
 * The TypeScript reference for §3–§5: target-first, scope-aware resolution (§4.2a) over an
 * unordered certificate set that may be a tree, Ed25519 and ES256 certificates and seals
 * (NOMOS-SPEC-010), the `suite` and `approver` dimensions (§3.6, §3.7). The Python reference is
 * python/nomosprotocol/chain.py; both must reproduce chain-of-trust-vectors/vectors.json and
 * vectors-1.9.json field for field, in every listed presentation order.
 *
 * Two entry points share one resolver, so artifact and statement verification cannot drift:
 *   verifyChainPresentation()  an artifact and its seal (§4)
 *   resolveKey()               any key, for any purpose, incl. testimony and consent (§4.6)
 *
 * This module never calls process.exit() or console.log(), and never throws.
 */
import * as crypto from "crypto";
import { jcs, keyCertFingerprint, verifyKeyCertificate, verifyFreshnessStaple, type KeyCertificate, type FreshnessStaple } from "./key-cert.js";
import { kidOf, loadKey, verifySuite, isSuite, type Suite } from "./suites.js";
import {
  parseScope, isNarrowerOrEqual, mergeScopes, suitePermitted, admitArtifact, admitStatement, formatScope,
  UNRESTRICTED, type ScopeTerms, type Admission,
} from "./scope.js";

/** How confidently KEY revocation was checked across the resolved path (§5.5): the weakest link. */
export type RevocationConfidence = "live" | "staple" | "unchecked";

export type IssuerReason =
  | "no_certificate_for_root" | "chain_broken" | "invalid_key" | "kid_mismatch" | "bad_time" | "expired" | "not_yet_valid"
  | "bad_signature" | "bad_encoding" | "high_s" | "suite_key_mismatch" | "unknown_suite";

/** Every refusal a resolution can end in. Distinct classes call for distinct remedies, so none is
 *  collapsed into another: see the spec's §4.4 table. */
export type ResolveFailure =
  | { decision: "ISSUER_NOT_RECOGNIZED"; reason_code: IssuerReason; detail: string }
  | { decision: "KEY_REVOKED"; revoked_kid: string; detail: string }
  | { decision: "CERTIFICATE_REVOKED"; revoked_fingerprint: string; detail: string }
  /** The key is genuine, but no path delegates it this purpose. `reason_code` is present only when
   *  a certificate on the path itself is at fault (`widening`, `malformed_scope`,
   *  `suite_not_permitted`); absent, the path was sound and the purpose was refused (`dimension`). */
  | { decision: "OUT_OF_SCOPE"; dimension?: string; reason_code?: "widening" | "malformed_scope" | "suite_not_permitted"; detail: string }
  | { decision: "MALFORMED"; reason_code: string; detail: string };

export type ChainVerdict =
  | { decision: "ALLOWED"; leaf_kid: string; path: string[]; effective_scope?: string; revocation_checked: RevocationConfidence }
  | ResolveFailure
  | { decision: "SEAL_INVALID"; reason_code: string; detail: string };

export type Resolved = { decision: "RESOLVED"; pem: string; path: string[]; effective: ScopeTerms; hops: Hop[] };
type Hop = { cert: KeyCertificate; parentPem: string; parentScope: ScopeTerms };
export type Purpose = (scope: ScopeTerms) => Admission;

const MAX_CHAIN_LENGTH = 20; // §4.5
const CERT_FIELDS = ["parent_kid", "child_kid", "child_public_key_pem", "issued_at", "expires_at", "algorithm", "signature"] as const;
const STAPLE_FIELDS = ["child_kid", "parent_kid", "as_of", "valid_until", "algorithm", "signature"] as const;
const CERT_SUITES = ["Ed25519", "ES256"];
const SEAL_SUITES = ["Ed25519", "ES256"];

const malformed = (reason_code: string, detail: string): ResolveFailure => ({ decision: "MALFORMED", reason_code, detail });
const nonEmptyStrings = (o: any, fields: readonly string[]) => fields.every((f) => typeof o?.[f] === "string" && o[f] !== "");

/** §4.4–§4.5 shape gates, before any cryptographic work. */
export function checkPool(chain: unknown): ResolveFailure | null {
  if (!Array.isArray(chain)) return malformed("bad_chain", "key_certs must be an array of key certificates.");
  if (chain.length > MAX_CHAIN_LENGTH) return malformed("chain_over_length_cap", `chain has ${chain.length} certificates — exceeds the ${MAX_CHAIN_LENGTH}-certificate limit.`);
  for (let i = 0; i < chain.length; i++) {
    const c = chain[i];
    if (typeof c !== "object" || c === null || !nonEmptyStrings(c, CERT_FIELDS)) return malformed("bad_certificate", `chain[${i}] is missing a required string field.`);
    if (!CERT_SUITES.includes(c.algorithm)) return malformed("bad_certificate", `chain[${i}].algorithm must be Ed25519 or ES256 (rev. 1.9 §3.1).`);
    if (c.scope !== undefined && c.scope !== null && typeof c.scope !== "string") return malformed("bad_certificate", `chain[${i}].scope must be a string if present.`);
  }
  return null;
}

function checkStaples(staples: unknown): ResolveFailure | null {
  if (staples === undefined || staples === null) return null;
  if (!Array.isArray(staples) || staples.length > MAX_CHAIN_LENGTH) return malformed("bad_staples", `freshness_staples must be an array of at most ${MAX_CHAIN_LENGTH}.`);
  for (let i = 0; i < staples.length; i++) {
    if (!nonEmptyStrings(staples[i], STAPLE_FIELDS) || !CERT_SUITES.includes(staples[i].algorithm)) return malformed("bad_staple", `freshness_staples[${i}] is not a well-formed staple.`);
  }
  return null;
}

/** §4.2a step 2–3: root-to-target certificate lists, enumerated from the target, fingerprint order. */
function* candidates(target: string, root: string, pool: KeyCertificate[], onPath: Set<string>, depth = 0): Generator<KeyCertificate[]> {
  if (target === root) { yield []; return; }
  if (depth >= MAX_CHAIN_LENGTH || onPath.has(target)) return;
  const parents = pool.filter((c) => c.child_kid === target)
    .map((c) => ({ c, fp: keyCertFingerprint(c) }))
    .sort((a, b) => (a.fp < b.fp ? -1 : a.fp > b.fp ? 1 : 0));
  const next = new Set(onPath).add(target);
  for (const { c } of parents) for (const head of candidates(c.parent_kid, root, pool, next, depth + 1)) yield [...head, c];
}

/** §4.2a step 4: one candidate, root first. Every check that can fail a candidate is here. */
function validate(path: KeyCertificate[], rootPem: string, now: Date, purpose: Purpose, revokedKids: Set<string>, revokedCerts: Set<string>): Resolved | ResolveFailure {
  let pem = rootPem, scope: ScopeTerms = UNRESTRICTED;
  const hops: Hop[] = [];
  for (const cert of path) {
    const link = `${cert.parent_kid} → ${cert.child_kid}`;
    if ("reason" in loadKey(cert.child_public_key_pem)) return { decision: "ISSUER_NOT_RECOGNIZED", reason_code: "invalid_key", detail: `Certificate ${link} carries a key that is not a canonical Ed25519 or P-256 SPKI.` };
    if (kidOf(cert.child_public_key_pem) !== cert.child_kid) return { decision: "ISSUER_NOT_RECOGNIZED", reason_code: "kid_mismatch", detail: `Certificate ${link}: child_kid is not the key's id.` };
    if (!suitePermitted(scope, cert.algorithm)) return { decision: "OUT_OF_SCOPE", dimension: "suite", reason_code: "suite_not_permitted", detail: `Certificate ${link}: its parent may not sign under ${cert.algorithm} (§3.6).` };
    const v = verifyKeyCertificate(cert, pem, now);
    if (!v.valid) return { decision: "ISSUER_NOT_RECOGNIZED", reason_code: v.reason as IssuerReason, detail: `Certificate ${link}: ${v.reason}.` };
    const fp = keyCertFingerprint(cert);
    if (revokedCerts.has(fp)) return { decision: "CERTIFICATE_REVOKED", revoked_fingerprint: fp, detail: `Certificate ${link} has been revoked by its issuer.` };
    if (revokedKids.has(cert.child_kid)) return { decision: "KEY_REVOKED", revoked_kid: cert.child_kid, detail: `Key ${cert.child_kid} has been revoked.` };
    const parsed = parseScope(cert.scope);
    if (!parsed.ok) return { decision: "OUT_OF_SCOPE", reason_code: "malformed_scope", detail: `Certificate ${link}: ${parsed.detail}` };
    const narrowing = isNarrowerOrEqual(parsed.scope, scope);
    if (!narrowing.ok) return { decision: "OUT_OF_SCOPE", dimension: narrowing.dimension, reason_code: "widening", detail: `Certificate ${link}: ${narrowing.detail}` };
    hops.push({ cert, parentPem: pem, parentScope: scope });
    pem = cert.child_public_key_pem;
    scope = mergeScopes(scope, parsed.scope);
  }
  const admitted = purpose(scope);
  if (!admitted.ok) return { decision: "OUT_OF_SCOPE", dimension: admitted.dimension, detail: `The resolved scope ${JSON.stringify(formatScope(scope))} does not admit this use (${admitted.dimension}).` };
  return { decision: "RESOLVED", pem, path: [], effective: scope, hops };
}

/**
 * §4.2a: resolve `targetKid` to the pinned root for `purpose`. `chain` must have passed
 * checkPool(). A candidate path the purpose does not admit is a failed candidate (rev. 1.9);
 * if none validates, the first candidate's failure is returned.
 */
export function resolveKey(args: {
  targetKid: string; chain: KeyCertificate[]; rootPublicKeyPem: string; purpose: Purpose;
  revokedKids?: Set<string>; revokedCerts?: Set<string>; now?: Date;
}): Resolved | ResolveFailure {
  const now = args.now ?? new Date();
  const revokedKids = args.revokedKids ?? new Set<string>(), revokedCerts = args.revokedCerts ?? new Set<string>();
  const rootKid = kidOf(args.rootPublicKeyPem);
  if (rootKid === null) return malformed("bad_root", "The pinned root is not a canonical Ed25519 or P-256 public key.");
  if (revokedKids.has(rootKid)) return { decision: "KEY_REVOKED", revoked_kid: rootKid, detail: `The pinned root key (kid ${rootKid}) has been revoked.` };
  let first: ResolveFailure | null = null;
  for (const path of candidates(args.targetKid, rootKid, args.chain, new Set())) {
    const r = validate(path, args.rootPublicKeyPem, now, args.purpose, revokedKids, revokedCerts);
    if (r.decision === "RESOLVED") return { ...r, path: [rootKid, ...path.map((c) => c.child_kid)] };
    first ??= r;
  }
  if (first) return first;
  return args.chain.some((c) => c.parent_kid === rootKid)
    ? { decision: "ISSUER_NOT_RECOGNIZED", reason_code: "chain_broken", detail: `No path of valid certificates leads from the pinned root to kid ${args.targetKid}.` }
    : { decision: "ISSUER_NOT_RECOGNIZED", reason_code: "no_certificate_for_root", detail: `No certificate in the presented set is signed by the pinned root (kid ${rootKid}).` };
}

export const forArtifact = (meta: any, suite: Suite): Purpose => (scope) => admitArtifact(meta, suite, scope);
export const forStatement = (kind: "claim" | "consent", name: string, meta: any, suite: Suite): Purpose => (scope) => admitStatement(kind, name, meta, suite, scope);

/** §5.5, for a verifier with no revocation source of its own. The root is never staple-coverable
 *  and is not counted; every other hop must be covered by a staple from its own parent. */
function stapleConfidence(resolved: Resolved, staples: FreshnessStaple[], now: Date): RevocationConfidence {
  if (resolved.hops.length === 0) return "unchecked";
  const covered = (h: Hop) => staples.some((s) =>
    s.child_kid === h.cert.child_kid && s.parent_kid === h.cert.parent_kid &&
    suitePermitted(h.parentScope, s.algorithm) && verifyFreshnessStaple(s, h.parentPem, now));
  return resolved.hops.every(covered) ? "staple" : "unchecked";
}

/** An artifact and its key certificates (§4). Never throws: every input may be attacker-controlled. */
export function verifyChainPresentation(args: {
  artifact: any; chain: unknown; rootPublicKeyPem: string;
  revokedKids?: Set<string>; revokedCerts?: Set<string>; freshnessStaples?: unknown; now?: Date;
}): ChainVerdict {
  try {
    return verifyUnsafe(args);
  } catch (e: any) {
    return malformed("internal", `Unexpected error while evaluating the presentation: ${e?.message ?? String(e)}`);
  }
}

function verifyUnsafe(args: {
  artifact: any; chain: unknown; rootPublicKeyPem: string;
  revokedKids?: Set<string>; revokedCerts?: Set<string>; freshnessStaples?: unknown; now?: Date;
}): ChainVerdict {
  const now = args.now ?? new Date();
  const poolFailure = checkPool(args.chain);
  if (poolFailure) return poolFailure;
  const artifact = args.artifact, seal = artifact?.seal;
  if (typeof artifact !== "object" || artifact === null) return malformed("bad_artifact", "artifact must be an object.");
  if (typeof seal !== "object" || seal === null || seal.status !== "sealed" || !["hash", "signature", "kid"].every((k) => typeof seal[k] === "string")) {
    return malformed("unsealed_artifact", "Artifact is not sealed, or its seal lacks hash, signature or kid.");
  }
  if (!SEAL_SUITES.includes(seal.signature_algorithm) || !isSuite(seal.signature_algorithm)) {
    return malformed("seal_algorithm", "A chain can vouch only for an Ed25519 or ES256 seal (signature_algorithm).");
  }
  const stapleFailure = checkStaples(args.freshnessStaples);
  if (stapleFailure) return stapleFailure;
  // §5.5: undefined means "no revocation source of my own", which is what makes staples relevant.
  const hasOwnSource = args.revokedKids !== undefined || args.revokedCerts !== undefined;

  // §4.2a, scope-aware: OUT_OF_SCOPE is decided before the seal is checked.
  const r = resolveKey({
    targetKid: seal.kid, chain: args.chain as KeyCertificate[], rootPublicKeyPem: args.rootPublicKeyPem,
    purpose: forArtifact(artifact.meta ?? {}, seal.signature_algorithm), revokedKids: args.revokedKids, revokedCerts: args.revokedCerts, now,
  });
  if (r.decision !== "RESOLVED") return r;

  // The resolved key is the same on every candidate path (its kid is its hash), so the seal is
  // checked once, after the path is chosen.
  const body = Object.fromEntries(Object.entries(artifact).filter(([k]) => k !== "seal" && k !== "attestations"));
  if (crypto.createHash("sha256").update(jcs(body)).digest("hex") !== seal.hash) {
    return { decision: "SEAL_INVALID", reason_code: "hash_mismatch", detail: "Hash mismatch — payload modified after sealing." };
  }
  const sig = verifySuite(seal.signature_algorithm, r.pem, jcs({ hash: seal.hash, signed_by: seal.signed_by }), { signature: seal.signature });
  if (!sig.ok) return { decision: "SEAL_INVALID", reason_code: sig.reason, detail: `Seal signature does not verify against the resolved key (${sig.reason}).` };

  const confidence: RevocationConfidence = hasOwnSource ? "live" : stapleConfidence(r, (args.freshnessStaples ?? []) as FreshnessStaple[], now);
  const scope = formatScope(r.effective);
  return { decision: "ALLOWED", leaf_kid: seal.kid, path: r.path, ...(scope ? { effective_scope: scope } : {}), revocation_checked: confidence };
}
