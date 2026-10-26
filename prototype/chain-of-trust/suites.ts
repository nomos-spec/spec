/**
 * NOMOS-SPEC-010 signature suites, for the chain-of-trust prototype.
 *
 *   verifySuite(suite, publicKeyPem, payload, proof) -> { ok, reason }
 *
 * Written from the SPEC-010 text; it is the same algorithm as suite-vectors/check.mjs and must
 * pass the same 27 vectors (suite-vectors/check-prototype.ts runs them). Node built-in crypto only.
 */
import * as crypto from "crypto";

export const SUITES = ["Ed25519", "ES256", "WebAuthn-ES256"] as const;
export type Suite = (typeof SUITES)[number];
export type KeyType = "Ed25519" | "P-256";
export type SuiteReason =
  | "unknown_suite" | "invalid_key" | "suite_key_mismatch" | "bad_encoding" | "high_s"
  | "bad_signature" | "bad_client_data" | "challenge_mismatch" | "user_not_verified";

const N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
const ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const P256_PREFIX = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d03010703420004", "hex");
const SUITES_FOR: Record<KeyType, readonly Suite[]> = { "Ed25519": ["Ed25519"], "P-256": ["ES256", "WebAuthn-ES256"] };
const sha256 = (b: Buffer): Buffer => crypto.createHash("sha256").update(b).digest();

export const isSuite = (s: unknown): s is Suite => typeof s === "string" && (SUITES as readonly string[]).includes(s);

/** §2: canonical base64 — decode, re-encode, require identity. */
export function b64(s: unknown): Buffer | null {
  if (typeof s !== "string" || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const raw = Buffer.from(s, "base64");
  return raw.toString("base64") === s ? raw : null;
}
export function b64url(s: unknown): Buffer | null {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const raw = Buffer.from(s, "base64url");
  return raw.toString("base64url") === s ? raw : null;
}

function pemDer(pem: unknown): Buffer | null {
  if (typeof pem !== "string") return null;
  const m = pem.match(/^\s*-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END PUBLIC KEY-----\s*$/);
  return m ? b64(m[1].replace(/\s+/g, "")) : null;
}

/** §3.1: a key is accepted only as its exact canonical SPKI bytes. */
export function loadKey(pem: unknown): { type: KeyType; key: crypto.KeyObject; der: Buffer } | { reason: "invalid_key" } {
  const der = pemDer(pem);
  if (!der) return { reason: "invalid_key" };
  let type: KeyType;
  if (der.length === 44 && der.subarray(0, 12).equals(ED25519_PREFIX)) type = "Ed25519";
  else if (der.length === 91 && der.subarray(0, 27).equals(P256_PREFIX)) type = "P-256";
  else return { reason: "invalid_key" };
  try { return { type, key: crypto.createPublicKey({ key: der, format: "der", type: "spki" }), der }; }
  catch { return { reason: "invalid_key" }; }
}

/** SPEC-001 §8.4: base64url(SHA-256(SPKI DER)), first 16 characters, over the canonical DER. */
export function kidOf(pem: string): string | null {
  const k = loadKey(pem);
  return "reason" in k ? null : sha256(k.der).toString("base64url").slice(0, 16);
}

export function verifySuite(suite: unknown, pem: unknown, payload: Buffer, proof: any): { ok: true } | { ok: false; reason: SuiteReason } {
  const fail = (reason: SuiteReason) => ({ ok: false as const, reason });
  if (!isSuite(suite)) return fail("unknown_suite");
  const k = loadKey(pem);
  if ("reason" in k) return fail("invalid_key");
  if (!SUITES_FOR[k.type].includes(suite)) return fail("suite_key_mismatch");
  if (!proof || typeof proof !== "object") return fail("bad_encoding");

  if (suite === "Ed25519") {
    const sig = b64(proof.signature);
    if (!sig || sig.length !== 64) return fail("bad_encoding");
    return crypto.verify(null, payload, k.key, sig) ? { ok: true } : fail("bad_signature");
  }
  if (suite === "ES256") {
    const sig = b64(proof.signature);
    if (!sig || sig.length !== 64) return fail("bad_encoding");
    const r = BigInt("0x" + sig.subarray(0, 32).toString("hex")), s = BigInt("0x" + sig.subarray(32).toString("hex"));
    if (r < 1n || r >= N || s < 1n || s >= N) return fail("bad_encoding");
    if (s > N / 2n) return fail("high_s");
    return crypto.verify("sha256", payload, { key: k.key, dsaEncoding: "ieee-p1363" }, sig) ? { ok: true } : fail("bad_signature");
  }
  const auth = b64url(proof.authenticator_data), cdj = b64url(proof.client_data_json), sig = b64url(proof.signature);
  if (!auth || !cdj || !sig) return fail("bad_encoding");
  let client: any;
  try { client = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(cdj)); } catch { return fail("bad_client_data"); }
  if (!client || typeof client !== "object" || Array.isArray(client) || client.type !== "webauthn.get") return fail("bad_client_data");
  if (client.challenge !== sha256(payload).toString("base64url")) return fail("challenge_mismatch");
  if (auth.length < 37) return fail("bad_encoding");
  if (!(auth[32] & 0x01) || !(auth[32] & 0x04)) return fail("user_not_verified");
  let ok: boolean;
  try { ok = crypto.verify("sha256", Buffer.concat([auth, sha256(cdj)]), { key: k.key, dsaEncoding: "der" }, sig); }
  catch { return fail("bad_encoding"); }
  return ok ? { ok: true } : fail("bad_signature");
}
