/**
 * PROTOTYPE — Key Certificates (chain-of-trust)
 *
 * Reference implementation for NOMOS-SPEC-007 (Draft) §3 — see ./README.md for status and
 * scope. This module implements the key-certificate primitive the spec defines.
 *
 * A key certificate is one key (the "parent" — a root or intermediate) certifying that another
 * key (the "child") is authorized to sign, within an optional scope, until an expiry. It answers
 * a different question than a NOMOS-SPEC-004 attestation: an attestation is an advisory, additive
 * endorsement of one specific artifact ("I reviewed this and it holds up") that never gates
 * evaluation. A key certificate is the opposite — it is the mechanism that determines whether an
 * issuer is recognized *at all*. That's why this is a deliberate sibling module rather than a
 * `subject` field bolted onto attestations: same cryptographic shape (detached, Ed25519,
 * JCS-signed, bound to a specific target), different trust semantic (gating vs. advisory).
 * Cross-reference: the attestation analog this mirrors is `server/lib/nomos-attest.ts` in the
 * main platform repo (createAttestation / verifyAttestation).
 *
 * `issued_at` here means the same thing it means in NOMOS-SPEC-006 (revocation) — a timestamp
 * that is itself part of the signed payload — not the unsigned annotation meaning `revoked_at`
 * carries in NOMOS-SPEC-004. That distinction mattered once already in this codebase; checked
 * before reusing the name here.
 */

import * as crypto from "crypto";

// ── RFC 8785 JSON Canonicalization Scheme (JCS) — same minimal implementation as verify.ts ──
type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function jcsValue(value: JsonValue): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") { if (!isFinite(value)) throw new Error("NaN / Infinity not valid in JCS"); return String(value); }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(jcsValue).join(",") + "]";
  if (typeof value === "object") return "{" + Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${jcsValue(value[k])}`).join(",") + "}";
  throw new TypeError(`Unsupported type: ${typeof value}`);
}
export const jcs = (obj: unknown): Buffer => Buffer.from(jcsValue(obj as JsonValue), "utf8");

/** Same derivation as the platform's computeKid(): base64url(SHA-256(SPKI DER)), first 16 chars. */
export function computeKid(publicKeyPem: string): string {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("base64url").slice(0, 16);
}

export interface KeyCertificate {
  parent_kid: string;             // kid of the CERTIFYING key (root or intermediate)
  child_kid: string;              // kid of the key being certified
  child_public_key_pem: string;   // certified key's material, carried inline — there is no
                                   // central directory to resolve it from; that absence is the
                                   // entire point of a chain that verifies without calling home
  scope?: string;                 // delegation limits, ENFORCED per §3.4 — see scope.ts
  issued_at: string;              // ISO-8601, signed content
  expires_at: string;             // ISO-8601, signed content
  algorithm: "Ed25519";
  signature: string;              // base64 Ed25519 over keyCertPayload(this)
}

/** The exact signed content — everything in KeyCertificate except the signature itself. */
export function keyCertPayload(cert: Omit<KeyCertificate, "signature" | "algorithm">): Buffer {
  return jcs({
    parent_kid: cert.parent_kid,
    child_kid: cert.child_kid,
    child_public_key_pem: cert.child_public_key_pem,
    scope: cert.scope ?? null,
    issued_at: cert.issued_at,
    expires_at: cert.expires_at,
  });
}

/** Signs with the PARENT's private key. childPublicKeyPem is the key being certified, not the signer's. */
export function createKeyCertificate(args: {
  parentPrivateKeyPem: string;
  parentKid: string;
  childPublicKeyPem: string;
  scope?: string;
  issuedAt?: Date;
  expiresAt: Date;
}): KeyCertificate {
  const childKid = computeKid(args.childPublicKeyPem);
  const issuedAt = (args.issuedAt ?? new Date()).toISOString();
  const expiresAt = args.expiresAt.toISOString();
  const unsigned = {
    parent_kid: args.parentKid,
    child_kid: childKid,
    child_public_key_pem: args.childPublicKeyPem,
    scope: args.scope,
    issued_at: issuedAt,
    expires_at: expiresAt,
  };
  const signature = crypto
    .sign(null, keyCertPayload(unsigned), crypto.createPrivateKey(args.parentPrivateKeyPem))
    .toString("base64");
  return { ...unsigned, algorithm: "Ed25519", signature };
}

export type KeyCertVerifyResult =
  | { valid: true }
  | { valid: false; reason: "bad_signature" | "expired" | "not_yet_valid" };

/** Verifies ONE certificate's signature + expiry against a caller-supplied parent public key.
 *  Does not resolve trust on its own — see chain-verify-core.ts for the walk that turns a
 *  sequence of these into an actual "is this issuer recognized" decision.
 *
 *  Never throws. `cert` and `parentPublicKeyPem` may both be attacker-controlled — a malformed
 *  PEM, a non-base64 signature, or a missing field must fail closed as `bad_signature`, not
 *  propagate a raw crypto exception up to a caller that isn't expecting one. */
export function verifyKeyCertificate(cert: KeyCertificate, parentPublicKeyPem: string, now: Date = new Date()): KeyCertVerifyResult {
  let valid: boolean;
  try {
    valid = crypto.verify(
      null,
      keyCertPayload(cert),
      crypto.createPublicKey(parentPublicKeyPem),
      Buffer.from(cert.signature, "base64")
    );
  } catch {
    return { valid: false, reason: "bad_signature" };
  }
  if (!valid) return { valid: false, reason: "bad_signature" };
  if (now.getTime() > Date.parse(cert.expires_at)) return { valid: false, reason: "expired" };
  if (now.getTime() < Date.parse(cert.issued_at)) return { valid: false, reason: "not_yet_valid" };
  return { valid: true };
}
