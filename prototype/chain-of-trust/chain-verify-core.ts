/**
 * PROTOTYPE — pure chain-verification core
 *
 * Reference implementation for NOMOS-SPEC-007 (Draft) §4-5. Extracted from verify-chain.ts so the same verdict logic can back two different
 * presentations: a CLI (exit codes + printed lines) and an HTTP receiver (status + JSON body).
 * This module never calls process.exit() or console.log() — it returns a value. Copying the walk
 * into a second place instead of sharing this would let the CLI and the receiver drift apart,
 * which is exactly the failure mode a chain-verification primitive can't afford.
 *
 * Distinguishable outcomes, deliberately not collapsed into one another — a caller (wire or CLI)
 * needs to react differently to each. See each ChainVerdict variant's own comment for what
 * distinguishes it and why collapsing it into a neighbor would be wrong, rather than a count here
 * that has already gone stale twice as outcomes were added.
 */

import * as crypto from "crypto";
import {
  jcs, computeKid, verifyKeyCertificate, keyCertFingerprint, verifyFreshnessStaple,
  type KeyCertificate, type FreshnessStaple,
} from "./key-cert.js";
import {
  parseScope, isNarrowerOrEqual, mergeScopes, artifactInScope, formatScope,
  UNRESTRICTED, type ScopeTerms,
} from "./scope.js";

/** How confidently KEY revocation (not certificate revocation — §5.4 is a separate object with
 *  no staple coverage in this version) was checked across the whole resolved path. `live` —
 *  every kid checked against a real revocation source the verifier holds. `staple` — at least one
 *  kid relied on a presented freshness staple (§5.5) rather than the verifier's own source; still
 *  a bounded, disclosed guarantee, never silently equated with `live`. `unchecked` — at least one
 *  kid (routinely the root, which no staple can ever cover) had neither — fail-open, matching
 *  every other revocation check in this document, but never fail-SILENT: this is exactly what a
 *  caller inspects to know how much to trust an ALLOWED verdict. Always the WEAKEST result among
 *  every kid on the path, never the best. */
export type RevocationConfidence = "live" | "staple" | "unchecked";

export type ChainVerdict =
  | { decision: "ALLOWED"; leaf_kid: string; path: string[]; effective_scope: string; revocation_checked: RevocationConfidence }
  | { decision: "ISSUER_NOT_RECOGNIZED"; reason_code: "no_certificate_for_root" | "chain_broken" | "cycle" | "bad_signature" | "expired" | "not_yet_valid"; detail: string }
  /** A KEY's standing to sign was withdrawn entirely by its own parent (§5.1-5.2), checked at
   *  EVERY hop the walk visits — not only the terminal target — so a revoked intermediate is dead
   *  on every path a presenter might construct through it. Distinct from CERTIFICATE_REVOKED: a
   *  revoked key is dead everywhere; a revoked certificate withdraws only ONE delegation. */
  | { decision: "KEY_REVOKED"; revoked_kid: string; detail: string }
  /** ONE delegation was withdrawn by its issuer (§5.4), while the key itself remains validly
   *  certified elsewhere. Distinct from KEY_REVOKED: a different, unrevoked certificate for the
   *  same key can still resolve this, whereas a revoked KEY is dead on every path. */
  | { decision: "CERTIFICATE_REVOKED"; revoked_fingerprint: string; detail: string }
  /** The chain resolves and no key on it is revoked — the issuer IS recognized — but it was not
   *  delegated authority over this particular artifact. Distinct from ISSUER_NOT_RECOGNIZED: a
   *  broader, validly-issued delegation would fix this; nothing about re-presenting fixes "I do
   *  not know you". */
  | { decision: "OUT_OF_SCOPE"; dimension: string; effective_scope: string; detail: string }
  | { decision: "SEAL_INVALID"; detail: string }
  | { decision: "MALFORMED"; detail: string };

// No real chain is ever this deep — this bounds the O(chain.length) work per hop (worst case
// O(n^2) across the whole walk) against a pathologically large `chain` array, independent of and
// in addition to whatever body-size limit the transport (e.g. receiver.ts) already enforces.
const MAX_CHAIN_LENGTH = 20;

/** Every field an attacker-controlled certificate needs to have the right shape before any crypto
 *  touches it. Returns an error string, or null if the shape is acceptable — deliberately checked
 *  before any `crypto.*` call so a malformed certificate produces a clear MALFORMED message
 *  instead of an incidental crypto exception or a silently-failing type coercion. */
function validateCertShape(cert: unknown, index: number): string | null {
  if (typeof cert !== "object" || cert === null) return `chain[${index}] is not an object.`;
  const c = cert as Record<string, unknown>;
  for (const field of ["parent_kid", "child_kid", "child_public_key_pem", "issued_at", "expires_at", "signature"] as const) {
    if (typeof c[field] !== "string" || !c[field]) return `chain[${index}].${field} must be a non-empty string.`;
  }
  if (c.algorithm !== "Ed25519") return `chain[${index}].algorithm must be "Ed25519".`;
  if (c.scope !== undefined && typeof c.scope !== "string") return `chain[${index}].scope must be a string if present.`;
  return null;
}

function validateStapleShape(staple: unknown, index: number): string | null {
  if (typeof staple !== "object" || staple === null) return `freshness_staples[${index}] is not an object.`;
  const s = staple as Record<string, unknown>;
  for (const field of ["child_kid", "parent_kid", "as_of", "valid_until", "signature"] as const) {
    if (typeof s[field] !== "string" || !s[field]) return `freshness_staples[${index}].${field} must be a non-empty string.`;
  }
  if (s.algorithm !== "Ed25519") return `freshness_staples[${index}].algorithm must be "Ed25519".`;
  return null;
}

/**
 * The check every kid on the path runs (§5.2, §5.5). Never asserts revocation without a real
 * source — a staple can only raise confidence in "not revoked", never lower it, so a presenter's
 * own staple can never forge a false "not revoked" past a source that says otherwise: if the
 * verifier has its own source at all, the staple is not even consulted.
 */
function checkKeyNotRevoked(
  kid: string, parentKid: string | null, parentPem: string | null,
  hasOwnSource: boolean, revokedKids: Set<string>, staples: FreshnessStaple[], now: Date,
): { revoked: boolean; confidence: RevocationConfidence } {
  if (hasOwnSource) return { revoked: revokedKids.has(kid), confidence: "live" };
  // No source of our own. The root can never be staple-covered — nothing certifies a root, so
  // nothing but the relying party's own decision to un-pin it ever answers "is my root still
  // good" (§9). Every OTHER kid was certified by a real parent, who can vouch for it.
  if (parentKid === null || parentPem === null) return { revoked: false, confidence: "unchecked" };
  const staple = staples.find((s) => s.child_kid === kid && s.parent_kid === parentKid);
  if (staple && verifyFreshnessStaple(staple, parentPem, now)) return { revoked: false, confidence: "staple" };
  return { revoked: false, confidence: "unchecked" };
}

/** Combines confidence across every kid on the path — always the WEAKEST link, never the best,
 *  so one unchecked hop can't be hidden behind nine confidently-staple-checked ones. */
function worseConfidence(a: RevocationConfidence, b: RevocationConfidence): RevocationConfidence {
  const rank: Record<RevocationConfidence, number> = { live: 0, staple: 1, unchecked: 2 };
  return rank[a] >= rank[b] ? a : b;
}

function verifyEd25519(payload: Buffer, signatureB64: string, pem: string): boolean {
  try {
    return crypto.verify(null, payload, crypto.createPublicKey(pem), Buffer.from(signatureB64, "base64"));
  } catch {
    return false; // malformed key material or signature bytes — treated as "does not verify"
  }
}

type WalkResult =
  | { ok: true; pem: string; path: string[]; effectiveScope: ScopeTerms; revocationConfidence: RevocationConfidence }
  | { ok: false; kind: "ISSUER_NOT_RECOGNIZED"; reason_code: Extract<ChainVerdict, { decision: "ISSUER_NOT_RECOGNIZED" }>["reason_code"]; detail: string }
  | { ok: false; kind: "KEY_REVOKED"; revoked_kid: string; detail: string }
  | { ok: false; kind: "OUT_OF_SCOPE"; dimension: string; effectiveScope: ScopeTerms; detail: string }
  | { ok: false; kind: "CERTIFICATE_REVOKED"; revoked_fingerprint: string; detail: string }
  | { ok: false; kind: "MALFORMED"; detail: string };

/**
 * INVARIANT: `chain` is an unordered SET, not a sequence. At every step this searches the whole
 * remaining set for the certificate whose `parent_kid` matches the key just validated — never
 * assumes position i+1 continues position i. A relying party that receives {cert A, cert B,
 * cert C} in any order must reach the identical verdict. The moment verification depended on
 * order, the wire format carrying these certs would start carrying trust semantics it shouldn't
 * (an implicit "as-transmitted sequence = as-intended chain" assumption).
 *
 * Every kid visited — root, every intermediate, the leaf — is checked against `revokedKids`
 * (§5.2), not just the target. A revoked intermediate is dead on EVERY path a presenter might
 * construct to it, because the walk can never step through its kid without hitting this check,
 * regardless of which specific certificate carried it there.
 */
function walkChain(
  chain: KeyCertificate[], rootPublicKeyPem: string, targetKid: string,
  hasOwnKeySource: boolean, revokedKids: Set<string>, revokedCerts: Set<string>,
  freshnessStaples: FreshnessStaple[], now: Date,
): WalkResult {
  const rootKid = computeKid(rootPublicKeyPem);
  const rootCheck = checkKeyNotRevoked(rootKid, null, null, hasOwnKeySource, revokedKids, freshnessStaples, now);
  if (rootCheck.revoked) return { ok: false, kind: "KEY_REVOKED", revoked_kid: rootKid, detail: `The pinned root key (kid ${rootKid}) has been revoked.` };

  let currentKid = rootKid;
  let currentPem = rootPublicKeyPem;
  const remaining = [...chain];
  const visited = new Set<string>();
  const path: string[] = [rootKid];
  let effectiveScope: ScopeTerms = UNRESTRICTED;
  // The root can NEVER be staple-covered (§5.5 — nothing certifies a root), so its confidence is
  // 'unchecked' whenever there is no own source, regardless of how well-covered every delegated
  // hop turns out to be. Letting that inherent unchecked-ness seed the aggregate would drag every
  // chain down to 'unchecked' even when every hop that COULD be staple-covered was — defeating
  // the entire feature. It seeds the aggregate only in the degenerate case where the root itself
  // directly signed the artifact and there is nothing else to check at all; otherwise the
  // aggregate starts optimistic and is degraded only by hops that were genuinely checkable.
  let revocationConfidence: RevocationConfidence = targetKid === rootKid ? rootCheck.confidence : "live";

  while (currentKid !== targetKid) {
    if (visited.has(currentKid)) return { ok: false, kind: "ISSUER_NOT_RECOGNIZED", reason_code: "cycle", detail: `Chain contains a cycle at kid ${currentKid}.` };
    visited.add(currentKid);

    const idx = remaining.findIndex((c) => c.parent_kid === currentKid);
    if (idx === -1) {
      return currentKid === rootKid
        ? { ok: false, kind: "ISSUER_NOT_RECOGNIZED", reason_code: "no_certificate_for_root", detail: `No certificate in the presented chain is signed by the pinned root (kid ${rootKid}).` }
        : { ok: false, kind: "ISSUER_NOT_RECOGNIZED", reason_code: "chain_broken", detail: `Chain breaks after kid ${currentKid} — no certificate continues it toward the artifact's signing key.` };
    }
    const cert = remaining.splice(idx, 1)[0];

    const result = verifyKeyCertificate(cert, currentPem, now);
    if (!result.valid) {
      const detail =
        result.reason === "expired"
          ? `Certificate ${cert.parent_kid} → ${cert.child_kid} expired at ${cert.expires_at}.`
          : result.reason === "not_yet_valid"
          ? `Certificate ${cert.parent_kid} → ${cert.child_kid} is not yet valid (issued_at ${cert.issued_at}).`
          : `Certificate ${cert.parent_kid} → ${cert.child_kid} has an invalid signature — forged or corrupted link.`;
      return { ok: false, kind: "ISSUER_NOT_RECOGNIZED", reason_code: result.reason, detail };
    }

    // §5.4 — a withdrawn delegation stops the walk. After the signature check so an unverified
    // certificate is never probed, before scope so a revoked cert never narrows anything.
    const fingerprint = keyCertFingerprint(cert);
    if (revokedCerts.has(fingerprint)) {
      return { ok: false, kind: "CERTIFICATE_REVOKED", revoked_fingerprint: fingerprint,
        detail: `Certificate ${cert.parent_kid} \u2192 ${cert.child_kid} has been revoked by its issuer. The key may still be certified by another path.` };
    }

    // §3.4 — narrow the effective scope by this link. A certificate may add or tighten a
    // constraint; it may never loosen one. Rejected loudly rather than silently intersected, so a
    // misissued certificate surfaces instead of being quietly repaired.
    const parsed = parseScope(cert.scope);
    if (!parsed.ok) {
      return { ok: false, kind: "MALFORMED", detail: `Certificate ${cert.parent_kid} \u2192 ${cert.child_kid}: ${parsed.detail}` };
    }
    const narrowing = isNarrowerOrEqual(parsed.scope, effectiveScope);
    if (!narrowing.ok) {
      return {
        ok: false, kind: "OUT_OF_SCOPE", dimension: narrowing.dimension, effectiveScope,
        detail: `Certificate ${cert.parent_kid} \u2192 ${cert.child_kid}: ${narrowing.detail}`,
      };
    }
    effectiveScope = mergeScopes(effectiveScope, parsed.scope);

    // Captured before reassignment: verifying a staple for the new currentKid means verifying its
    // signature against the key that actually certified it — the parent this hop just resolved
    // through, never any other key on the path.
    const parentPemForThisHop = currentPem;
    const parentKidForThisHop = currentKid;
    currentKid = cert.child_kid;
    currentPem = cert.child_public_key_pem;
    const hopCheck = checkKeyNotRevoked(currentKid, parentKidForThisHop, parentPemForThisHop, hasOwnKeySource, revokedKids, freshnessStaples, now);
    if (hopCheck.revoked) return { ok: false, kind: "KEY_REVOKED", revoked_kid: currentKid, detail: `Key ${currentKid} in this chain has been revoked by its own parent.` };
    revocationConfidence = worseConfidence(revocationConfidence, hopCheck.confidence);
    path.push(currentKid);
  }
  return { ok: true, pem: currentPem, path, effectiveScope, revocationConfidence };
}

/**
 * Never throws. `artifact`, `chain`, and every field within them may be attacker-controlled (this
 * is exactly the function a wire receiver calls on an unauthenticated request body) — any
 * malformed shape, bad PEM, non-base64 signature, or unexpected type must resolve to a verdict,
 * never propagate an exception to a caller (CLI or HTTP) that isn't prepared to catch one.
 *
 * `revokedKids` is the caller's own DB-backed (or otherwise authoritative) revocation set for
 * KEYS (§5.1-5.2); `revokedCerts` is the equivalent for individual certificate fingerprints
 * (§5.4) — distinct sets, checked at distinct points in the walk, on purpose (§5.4's own text).
 * `freshnessStaples` is §5.5: presenter-supplied, and only ever consulted when `revokedKids` was
 * not supplied at all — see `hasOwnKeySource` below.
 */
export function verifyChainPresentation(args: {
  artifact: any; chain: unknown; rootPublicKeyPem: string;
  revokedKids?: Set<string>; revokedCerts?: Set<string>; freshnessStaples?: unknown; now?: Date;
}): ChainVerdict {
  try {
    return verifyChainPresentationUnsafe(args);
  } catch (e: any) {
    return { decision: "MALFORMED", detail: `Unexpected error while evaluating the presentation: ${e?.message ?? String(e)}` };
  }
}

function verifyChainPresentationUnsafe(args: {
  artifact: any; chain: unknown; rootPublicKeyPem: string;
  revokedKids?: Set<string>; revokedCerts?: Set<string>; freshnessStaples?: unknown; now?: Date;
}): ChainVerdict {
  const { artifact, rootPublicKeyPem } = args;
  const now = args.now ?? new Date();
  // Distinguishing undefined from an explicitly-empty Set is the entire mechanism (§5.5):
  // undefined means "I have no revocation source of my own", which is what makes staples
  // relevant at all. A caller that always supplies both, explicitly, even when empty, never even
  // consults a staple — they exist for the caller who has neither.
  const hasOwnKeySource = args.revokedKids !== undefined;
  const revokedKids = args.revokedKids ?? new Set<string>();
  const revokedCerts = args.revokedCerts ?? new Set<string>();

  const seal = artifact?.seal;
  if (!seal || seal.status === "draft") return { decision: "MALFORMED", detail: "Artifact is not sealed." };
  if (typeof seal.kid !== "string" || !seal.kid) return { decision: "MALFORMED", detail: "Artifact seal has no kid to resolve a chain for." };
  if (typeof seal.hash !== "string" || typeof seal.signature !== "string") {
    return { decision: "MALFORMED", detail: "Artifact seal is missing hash or signature." };
  }
  if (seal.signature_algorithm !== "Ed25519" && seal.algorithm !== "Ed25519") {
    return { decision: "MALFORMED", detail: "Chain verification requires an Ed25519-sealed artifact." };
  }

  if (!Array.isArray(args.chain)) return { decision: "MALFORMED", detail: "chain must be an array of key certificates." };
  if (args.chain.length > MAX_CHAIN_LENGTH) {
    return { decision: "MALFORMED", detail: `chain has ${args.chain.length} certificates — exceeds the ${MAX_CHAIN_LENGTH}-certificate limit.` };
  }
  for (let i = 0; i < args.chain.length; i++) {
    const err = validateCertShape(args.chain[i], i);
    if (err) return { decision: "MALFORMED", detail: err };
  }
  const chain = args.chain as KeyCertificate[];

  const rawStaples = args.freshnessStaples ?? [];
  if (!Array.isArray(rawStaples)) return { decision: "MALFORMED", detail: "freshness_staples must be an array, when present." };
  if (rawStaples.length > MAX_CHAIN_LENGTH) {
    return { decision: "MALFORMED", detail: `freshness_staples has ${rawStaples.length} entries — exceeds the ${MAX_CHAIN_LENGTH} limit.` };
  }
  for (let i = 0; i < rawStaples.length; i++) {
    const err = validateStapleShape(rawStaples[i], i);
    if (err) return { decision: "MALFORMED", detail: err };
  }
  const freshnessStaples = rawStaples as FreshnessStaple[];

  const walk = walkChain(chain, rootPublicKeyPem, seal.kid, hasOwnKeySource, revokedKids, revokedCerts, freshnessStaples, now);
  if (!walk.ok) {
    if (walk.kind === "MALFORMED") return { decision: "MALFORMED", detail: walk.detail };
    if (walk.kind === "KEY_REVOKED") return { decision: "KEY_REVOKED", revoked_kid: walk.revoked_kid, detail: walk.detail };
    if (walk.kind === "CERTIFICATE_REVOKED") return { decision: "CERTIFICATE_REVOKED", revoked_fingerprint: walk.revoked_fingerprint, detail: walk.detail };
    if (walk.kind === "OUT_OF_SCOPE") {
      return { decision: "OUT_OF_SCOPE", dimension: walk.dimension, effective_scope: formatScope(walk.effectiveScope), detail: walk.detail };
    }
    return { decision: "ISSUER_NOT_RECOGNIZED", reason_code: walk.reason_code, detail: walk.detail };
  }

  // §3.4 — the issuer is recognized; was it delegated authority over THIS artifact? Checked
  // before the seal so an out-of-scope artifact is never reported as merely seal-valid.
  const scopeCheck = artifactInScope(artifact, walk.effectiveScope);
  if (!scopeCheck.ok) {
    return {
      decision: "OUT_OF_SCOPE", dimension: scopeCheck.dimension,
      effective_scope: formatScope(walk.effectiveScope), detail: scopeCheck.detail,
    };
  }

  const payload = Object.fromEntries(Object.entries(artifact).filter(([k]) => k !== "seal" && k !== "attestations"));
  const computedHash = crypto.createHash("sha256").update(jcs(payload)).digest("hex");
  if (computedHash !== seal.hash) return { decision: "SEAL_INVALID", detail: "Hash mismatch — payload modified after sealing." };

  const signed = jcs({ hash: seal.hash, signed_by: seal.signed_by });
  if (!verifyEd25519(signed, seal.signature, walk.pem)) {
    return { decision: "SEAL_INVALID", detail: "Seal signature does not verify against the resolved chain key." };
  }

  return { decision: "ALLOWED", leaf_kid: seal.kid, path: walk.path, effective_scope: formatScope(walk.effectiveScope), revocation_checked: walk.revocationConfidence };
}
