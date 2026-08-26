#!/usr/bin/env node
/**
 * PROTOTYPE — Offline chain-of-trust verifier
 *
 * NOT a spec, not wired into any production path. See ./README.md.
 *
 * Extends the existing fully-offline verification path (verify/verify.ts's --pubkey mode) with
 * one new question: not just "is this seal authentic," but "is the key that signed it one a
 * pinned root actually vouches for" — without looking anything up in a central directory.
 *
 * Usage:
 *   npx tsx verify-chain.ts <artifact.nomos> --chain <certs.json> --root-pubkey <root.pub.pem>
 *
 * There is deliberately NO default for --root-pubkey and no fallback to any NOMOS-hosted key.
 * The relying party must supply the one root key it has independently decided to trust. That
 * decision — who operates a root, and why it should be trusted — is exactly the open governance
 * question this prototype does not answer; the required, no-default flag is what keeps it
 * visibly open in the code instead of silently resolved by a shipped default.
 *
 * What a successful chain resolution proves, precisely: verification needed no live call to the
 * issuer AND no per-issuer lookup — only the artifact, the chain presented alongside it, and the
 * one root key already pinned. It does NOT eliminate the trust bootstrap; the relying party still
 * had to obtain and pin that root key through some prior decision. That's what PKI does for the
 * web (browsers ship a pinned root store) — a real reduction of the trust problem, not its removal.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { jcs, computeKid, verifyKeyCertificate, type KeyCertificate } from "./key-cert.js";

function fail(msg: string): never {
  console.error(`\n  [FAIL] ${msg}\n\nResult: ISSUER_NOT_RECOGNIZED\n`);
  process.exit(2);
}

function verifyEd25519(payload: Buffer, signatureB64: string, pem: string): boolean {
  return crypto.verify(null, payload, crypto.createPublicKey(pem), Buffer.from(signatureB64, "base64"));
}

/**
 * Walks the chain from the pinned root to the artifact's signing key. Each step's verifying key
 * comes entirely from the previous step's certified `child_public_key_pem` — never from a
 * directory lookup — so the only externally-supplied trust input is the root itself.
 */
function walkChain(chain: KeyCertificate[], rootPubkeyPem: string, targetKid: string, now: Date): string {
  const rootKid = computeKid(rootPubkeyPem);
  let currentKid = rootKid;
  let currentPem = rootPubkeyPem;
  const remaining = [...chain];
  const visited = new Set<string>();

  while (currentKid !== targetKid) {
    if (visited.has(currentKid)) fail(`Chain contains a cycle at kid ${currentKid}.`);
    visited.add(currentKid);

    const idx = remaining.findIndex((c) => c.parent_kid === currentKid);
    if (idx === -1) {
      fail(
        currentKid === rootKid
          ? `No certificate in the presented chain is signed by the pinned root (kid ${rootKid}). Issuer not recognized.`
          : `Chain breaks after kid ${currentKid} — no certificate continues it toward the artifact's signing key.`
      );
    }
    const cert = remaining.splice(idx, 1)[0];

    const result = verifyKeyCertificate(cert, currentPem, now);
    if (!result.valid) {
      fail(
        result.reason === "expired"
          ? `Certificate ${cert.parent_kid} → ${cert.child_kid} expired at ${cert.expires_at}.`
          : result.reason === "not_yet_valid"
          ? `Certificate ${cert.parent_kid} → ${cert.child_kid} is not yet valid (issued_at ${cert.issued_at}).`
          : `Certificate ${cert.parent_kid} → ${cert.child_kid} has an invalid signature — forged or corrupted link.`
      );
    }
    console.log(`  [OK] ${currentKid} certifies ${cert.child_kid} (expires ${cert.expires_at})`);

    currentKid = cert.child_kid;
    currentPem = cert.child_public_key_pem;
  }
  return currentPem;
}

function verifyArtifactSeal(artifact: any, signingKeyPem: string): void {
  const seal = artifact.seal;
  const payload = Object.fromEntries(Object.entries(artifact).filter(([k]) => k !== "seal" && k !== "attestations"));
  const computedHash = crypto.createHash("sha256").update(jcs(payload)).digest("hex");
  if (computedHash !== seal.hash) fail(`Hash mismatch — payload modified after sealing.`);
  const signed = jcs({ hash: seal.hash, signed_by: seal.signed_by });
  if (!verifyEd25519(signed, seal.signature, signingKeyPem)) fail(`Seal signature does not verify against the resolved chain key.`);
}

function main(): void {
  const args = process.argv.slice(2);
  if (!args.length) {
    console.error("Usage: verify-chain.ts <artifact.nomos> --chain <certs.json> --root-pubkey <root.pub.pem>");
    process.exit(1);
  }
  const artifactPath = path.resolve(args[0]);
  let chainPath: string | null = null;
  let rootPubkeyPath: string | null = null;
  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--chain" && args[i + 1]) chainPath = path.resolve(args[++i]);
    else if (args[i] === "--root-pubkey" && args[i + 1]) rootPubkeyPath = path.resolve(args[++i]);
  }
  if (!rootPubkeyPath) fail("--root-pubkey is required. There is no default root — you must supply the key you've decided to trust.");
  if (!chainPath) fail("--chain <certs.json> is required — the ordered array of key certificates presented alongside the artifact.");

  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const chain: KeyCertificate[] = JSON.parse(fs.readFileSync(chainPath, "utf8"));
  const rootPubkeyPem = fs.readFileSync(rootPubkeyPath, "utf8");

  const seal = artifact.seal;
  if (!seal || seal.status === "draft") fail("Artifact is not sealed.");
  if (seal.signature_algorithm !== "Ed25519" && seal.algorithm !== "Ed25519") fail("Chain verification requires an Ed25519-sealed artifact.");

  console.log(`\nVerifying chain for: ${artifactPath}`);
  console.log(`  target kid (artifact signer) : ${seal.kid}`);
  console.log(`  pinned root kid              : ${computeKid(rootPubkeyPem)}`);

  const leafPem = walkChain(chain, rootPubkeyPem, seal.kid, new Date());
  verifyArtifactSeal(artifact, leafPem);

  console.log(`\nResult: ALLOWED — chain resolves from the pinned root to the artifact's signing key, seal verifies.\n`);
}

main();
