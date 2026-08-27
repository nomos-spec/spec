#!/usr/bin/env node
/**
 * PROTOTYPE — chain-of-trust demo fixture generator
 *
 * Reference implementation for NOMOS-SPEC-007 (Draft). Generates FRESH, disposable Ed25519 keypairs in memory (root, intermediate, leaf,
 * plus an uncertified impostor) — never NOMOS_SIGNING_KEY, never anything durable — issues key
 * certificates between them, seals toy `.nomos` artifacts, and writes fixtures to ./fixtures/ so
 * verify-chain.ts (CLI) and receiver.ts/presenter.ts (real HTTP) can both be run against the
 * identical fixtures to exercise the same distinguishable outcomes:
 *   1. ALLOWED                — full chain resolves, artifact honored
 *   2. ISSUER_NOT_RECOGNIZED  — an uncertified key sealed the artifact, chain doesn't connect
 *   3. ISSUER_NOT_RECOGNIZED  — the chain connects but a link expired (distinct reason)
 *   4. order-independence     — same chain, reversed, must reach the identical verdict
 *   5. SEAL_INVALID           — chain resolves fine, artifact was edited after sealing
 *
 * The root generated here is labeled exactly for what it is: a throwaway test key, not a
 * production trust anchor. This module does not decide who should operate a real root — that
 * question is out of scope by design (see README.md).
 */

import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { computeKid, createKeyCertificate } from "./key-cert.js";
import { generateKeypair, sealToyArtifact } from "./test-helpers.js";

const FIXTURES_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");

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
  // Chain resolves fine (same leaf key as artifactHonored) but the content was edited after
  // sealing, so the hash no longer matches — a genuinely different failure from "not recognized":
  // re-presenting a better chain can never fix this, only re-sealing the artifact can.
  const artifactTampered = { ...artifactHonored, logic: { decisions: [{ injected: "post-seal edit" }] } };

  fs.writeFileSync(path.join(FIXTURES_DIR, "root.pub.pem"), root.publicKeyPem);
  fs.writeFileSync(path.join(FIXTURES_DIR, "artifact-honored.nomos"), JSON.stringify(artifactHonored, null, 2));
  fs.writeFileSync(path.join(FIXTURES_DIR, "artifact-impostor.nomos"), JSON.stringify(artifactImpostor, null, 2));
  fs.writeFileSync(path.join(FIXTURES_DIR, "artifact-tampered.nomos"), JSON.stringify(artifactTampered, null, 2));
  fs.writeFileSync(path.join(FIXTURES_DIR, "chain-success.json"), JSON.stringify([rootToIntermediate, intermediateToLeaf], null, 2));
  // Same two certificates as chain-success.json, reversed order. The chain walker matches by
  // parent_kid/child_kid content, never by array position — verification must reach the exact
  // same verdict from this file as from chain-success.json. See verify-chain.ts's walkChain().
  fs.writeFileSync(path.join(FIXTURES_DIR, "chain-success-reversed.json"), JSON.stringify([intermediateToLeaf, rootToIntermediate], null, 2));
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
  console.log("  # 4. order-independence — same two certificates as case 1, reversed. Must reach");
  console.log("  #    the identical ALLOWED verdict; presentation order carries no trust meaning.");
  console.log("  npx tsx verify-chain.ts fixtures/artifact-honored.nomos --chain fixtures/chain-success-reversed.json --root-pubkey fixtures/root.pub.pem\n");
  console.log("  # 5. seal-invalid — chain resolves fine, but the artifact was edited after sealing");
  console.log("  npx tsx verify-chain.ts fixtures/artifact-tampered.nomos --chain fixtures/chain-success.json --root-pubkey fixtures/root.pub.pem\n");
  console.log("Over the wire (see receiver.ts / presenter.ts):\n");
  console.log("  npx tsx receiver.ts --root-pubkey fixtures/root.pub.pem --port 8420 &");
  console.log("  npx tsx presenter.ts fixtures/artifact-honored.nomos  --chain fixtures/chain-success.json --url http://localhost:8420/verify");
  console.log("  npx tsx presenter.ts fixtures/artifact-impostor.nomos --chain fixtures/chain-success.json --url http://localhost:8420/verify");
  console.log("  npx tsx presenter.ts fixtures/artifact-tampered.nomos --chain fixtures/chain-success.json --url http://localhost:8420/verify");
}

main();
