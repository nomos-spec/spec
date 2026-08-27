/**
 * PROTOTYPE — pure chain-verification core
 *
 * NOT a spec. Extracted from verify-chain.ts so the same verdict logic can back two different
 * presentations: a CLI (exit codes + printed lines) and an HTTP receiver (status + JSON body).
 * This module never calls process.exit() or console.log() — it returns a value. Copying the walk
 * into a second place instead of sharing this would let the CLI and the receiver drift apart,
 * which is exactly the failure mode a chain-verification primitive can't afford.
 *
 * Four distinguishable outcomes, deliberately not collapsed into one another — a caller (wire or
 * CLI) needs to react differently to each:
 *   - ALLOWED               chain resolves to the pinned root; artifact seal verifies
 *   - ISSUER_NOT_RECOGNIZED chain doesn't connect the artifact's signer back to the root
 *                           (re-presenting with a different/complete chain might fix this)
 *   - SEAL_INVALID          the chain resolves fine, but the artifact itself was tampered with
 *                           after sealing (re-presenting won't help — the artifact is bad)
 *   - MALFORMED             the input wasn't well-formed enough to evaluate at all
 *                           (a client-side bug, not a trust finding)
 */

import * as crypto from "crypto";
import { jcs, computeKid, verifyKeyCertificate, type KeyCertificate } from "./key-cert.js";

export type ChainVerdict =
  | { decision: "ALLOWED"; leaf_kid: string; path: string[] }
  | { decision: "ISSUER_NOT_RECOGNIZED"; reason: "no_certificate_for_root" | "chain_broken" | "cycle" | "bad_signature" | "expired" | "not_yet_valid"; detail: string }
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

function verifyEd25519(payload: Buffer, signatureB64: string, pem: string): boolean {
  try {
    return crypto.verify(null, payload, crypto.createPublicKey(pem), Buffer.from(signatureB64, "base64"));
  } catch {
    return false; // malformed key material or signature bytes — treated as "does not verify"
  }
}

type WalkResult =
  | { ok: true; pem: string; path: string[] }
  | { ok: false; reason: Extract<ChainVerdict, { decision: "ISSUER_NOT_RECOGNIZED" }>["reason"]; detail: string };

/**
 * INVARIANT: `chain` is an unordered SET, not a sequence. At every step this searches the whole
 * remaining set for the certificate whose `parent_kid` matches the key just validated — never
 * assumes position i+1 continues position i. A relying party that receives {cert A, cert B,
 * cert C} in any order must reach the identical verdict. The moment verification depended on
 * order, the wire format carrying these certs would start carrying trust semantics it shouldn't
 * (an implicit "as-transmitted sequence = as-intended chain" assumption).
 */
function walkChain(chain: KeyCertificate[], rootPublicKeyPem: string, targetKid: string, now: Date): WalkResult {
  const rootKid = computeKid(rootPublicKeyPem);
  let currentKid = rootKid;
  let currentPem = rootPublicKeyPem;
  const remaining = [...chain];
  const visited = new Set<string>();
  const path: string[] = [rootKid];

  while (currentKid !== targetKid) {
    if (visited.has(currentKid)) return { ok: false, reason: "cycle", detail: `Chain contains a cycle at kid ${currentKid}.` };
    visited.add(currentKid);

    const idx = remaining.findIndex((c) => c.parent_kid === currentKid);
    if (idx === -1) {
      return currentKid === rootKid
        ? { ok: false, reason: "no_certificate_for_root", detail: `No certificate in the presented chain is signed by the pinned root (kid ${rootKid}).` }
        : { ok: false, reason: "chain_broken", detail: `Chain breaks after kid ${currentKid} — no certificate continues it toward the artifact's signing key.` };
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
      return { ok: false, reason: result.reason, detail };
    }

    currentKid = cert.child_kid;
    currentPem = cert.child_public_key_pem;
    path.push(currentKid);
  }
  return { ok: true, pem: currentPem, path };
}

/**
 * Never throws. `artifact`, `chain`, and every field within them may be attacker-controlled (this
 * is exactly the function a wire receiver calls on an unauthenticated request body) — any
 * malformed shape, bad PEM, non-base64 signature, or unexpected type must resolve to a verdict,
 * never propagate an exception to a caller (CLI or HTTP) that isn't prepared to catch one.
 */
export function verifyChainPresentation(args: { artifact: any; chain: unknown; rootPublicKeyPem: string; now?: Date }): ChainVerdict {
  try {
    return verifyChainPresentationUnsafe(args);
  } catch (e: any) {
    return { decision: "MALFORMED", detail: `Unexpected error while evaluating the presentation: ${e?.message ?? String(e)}` };
  }
}

function verifyChainPresentationUnsafe(args: { artifact: any; chain: unknown; rootPublicKeyPem: string; now?: Date }): ChainVerdict {
  const { artifact, rootPublicKeyPem } = args;
  const now = args.now ?? new Date();

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

  const walk = walkChain(chain, rootPublicKeyPem, seal.kid, now);
  if (!walk.ok) return { decision: "ISSUER_NOT_RECOGNIZED", reason: walk.reason, detail: walk.detail };

  const payload = Object.fromEntries(Object.entries(artifact).filter(([k]) => k !== "seal" && k !== "attestations"));
  const computedHash = crypto.createHash("sha256").update(jcs(payload)).digest("hex");
  if (computedHash !== seal.hash) return { decision: "SEAL_INVALID", detail: "Hash mismatch — payload modified after sealing." };

  const signed = jcs({ hash: seal.hash, signed_by: seal.signed_by });
  if (!verifyEd25519(signed, seal.signature, walk.pem)) {
    return { decision: "SEAL_INVALID", detail: "Seal signature does not verify against the resolved chain key." };
  }

  return { decision: "ALLOWED", leaf_kid: seal.kid, path: walk.path };
}
