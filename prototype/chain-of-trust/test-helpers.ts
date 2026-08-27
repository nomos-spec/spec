/**
 * PROTOTYPE — shared fixture helpers for demo.ts and test.ts.
 *
 * Kept as one module so the exact key-generation and toy-sealing procedure used by the runnable
 * demo and the automated test suite can never drift apart into two subtly different fixtures.
 */

import * as crypto from "crypto";
import { jcs } from "./key-cert.js";

export function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

/** Mirrors verify/verify.ts's expected artifact shape exactly — the same JCS + SHA-256 + Ed25519 procedure. */
export function sealToyArtifact(signerKid: string, signerPrivateKeyPem: string, label: string) {
  const unsealed = {
    meta: { artifact_id: `prototype-toy-${label}`, version: "0.1.0", verification_tier: "PROTOTYPE" },
    provenance: { review_summary: { pending_at_seal: 0 } },
    logic: { decisions: [] },
  };
  const hash = crypto.createHash("sha256").update(jcs(unsealed)).digest("hex");
  const signedBy = `prototype-demo:${label}`;
  const signature = crypto
    .sign(null, jcs({ hash, signed_by: signedBy }), crypto.createPrivateKey(signerPrivateKeyPem))
    .toString("base64");
  return { ...unsealed, seal: { status: "sealed", hash, signature, algorithm: "Ed25519", kid: signerKid, signed_by: signedBy } };
}
