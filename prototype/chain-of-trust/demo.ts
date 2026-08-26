#!/usr/bin/env node
/**
 * PROTOTYPE — chain-of-trust demo fixture generator
 *
 * NOT a spec. Generates three FRESH, disposable Ed25519 keypairs in memory (root, intermediate,
 * leaf) — never NOMOS_SIGNING_KEY, never anything durable — issues key certificates between them,
 * seals a toy .nomos artifact with the leaf key, and writes fixtures to ./fixtures/ so
 * verify-chain.ts can be run against them as a real CLI, three separate times, to exercise:
 *   1. the success case       — full chain resolves, artifact honored
 *   2. the unrecognized case  — an uncertified key sealed the artifact, chain doesn't connect
 *   3. the expired case       — the chain connects but a link expired
 *
 * The root generated here is labeled exactly for what it is: a throwaway test key, not a
 * production trust anchor. This module does not decide who should operate a real root — that
 * question is out of scope by design (see README.md).
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { jcs, computeKid, createKeyCertificate } from "./key-cert.js";

const FIXTURES_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");

function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

/** Mirrors verify.ts's expected artifact shape exactly — the same JCS + SHA-256 + Ed25519 procedure. */
function sealToyArtifact(signerKid: string, signerPrivateKeyPem: string, label: string) {
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

function main(): void {
  fs.mkdirSync(FIXTURES_DIR, { recursive: true });

  const root = generateKeypair();
  const intermediate = generateKeypair();
  const leaf = generateKeypair();
  const impostor = generateKeypair(); // never certified by anything — the "not recognized" case

  const rootKid = computeKid(root.publicKeyPem);
  const intermediateKid = computeKid(intermediate.publicKeyPem);
  const leafKid = computeKid(leaf.publicKeyPem);

  const inOneYear = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
  const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const rootToIntermediate = createKeyCertificate({
    parentPrivateKeyPem: root.privateKeyPem,
    parentKid: rootKid,
    childPublicKeyPem: intermediate.publicKeyPem,
    scope: "prototype-demo",
    expiresAt: inOneYear,
  });
  const intermediateToLeaf = createKeyCertificate({
    parentPrivateKeyPem: intermediate.privateKeyPem,
    parentKid: intermediateKid,
    childPublicKeyPem: leaf.publicKeyPem,
    scope: "prototype-demo",
    expiresAt: inOneYear,
  });
  const intermediateToLeafExpired = createKeyCertificate({
    parentPrivateKeyPem: intermediate.privateKeyPem,
    parentKid: intermediateKid,
    childPublicKeyPem: leaf.publicKeyPem,
    scope: "prototype-demo",
    expiresAt: yesterday,
  });

  const artifactHonored = sealToyArtifact(leafKid, leaf.privateKeyPem, "honored");
  const artifactImpostor = sealToyArtifact(computeKid(impostor.publicKeyPem), impostor.privateKeyPem, "impostor");

  fs.writeFileSync(path.join(FIXTURES_DIR, "root.pub.pem"), root.publicKeyPem);
  fs.writeFileSync(path.join(FIXTURES_DIR, "artifact-honored.nomos"), JSON.stringify(artifactHonored, null, 2));
  fs.writeFileSync(path.join(FIXTURES_DIR, "artifact-impostor.nomos"), JSON.stringify(artifactImpostor, null, 2));
  fs.writeFileSync(path.join(FIXTURES_DIR, "chain-success.json"), JSON.stringify([rootToIntermediate, intermediateToLeaf], null, 2));
  fs.writeFileSync(path.join(FIXTURES_DIR, "chain-expired.json"), JSON.stringify([rootToIntermediate, intermediateToLeafExpired], null, 2));

  console.log("NOMOS PROTOTYPE TEST ROOT — not a production trust anchor. Generated fresh, this run only.\n");
  console.log(`  root kid         : ${rootKid}`);
  console.log(`  intermediate kid : ${intermediateKid}`);
  console.log(`  leaf kid         : ${leafKid}`);
  console.log(`  impostor kid     : ${computeKid(impostor.publicKeyPem)}  (never certified by anything)\n`);
  console.log(`Fixtures written to ${FIXTURES_DIR}\n`);
  console.log("Now run each of the three cases:\n");
  console.log("  # 1. success — full chain resolves");
  console.log("  npx tsx verify-chain.ts fixtures/artifact-honored.nomos --chain fixtures/chain-success.json --root-pubkey fixtures/root.pub.pem\n");
  console.log("  # 2. unrecognized — artifact signed by a key no certificate in the chain names");
  console.log("  npx tsx verify-chain.ts fixtures/artifact-impostor.nomos --chain fixtures/chain-success.json --root-pubkey fixtures/root.pub.pem\n");
  console.log("  # 3. expired — chain connects but the leaf certificate has lapsed");
  console.log("  npx tsx verify-chain.ts fixtures/artifact-honored.nomos --chain fixtures/chain-expired.json --root-pubkey fixtures/root.pub.pem\n");
}

main();
