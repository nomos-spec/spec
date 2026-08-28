/**
 * PROTOTYPE — automated end-to-end test suite (node:test, zero deps).
 *
 * Run: npx tsx --test test.ts
 *
 * Asserts on `decision` / `reason_code` / HTTP status fields, never on printed text, so these
 * tests stay stable if console formatting changes later. Covers the core chain-authenticity
 * outcomes, the hardening added in response to a security pass (shape validation, the
 * chain-length cap, cycle detection with a REAL signed cycle rather than one traced by reading
 * the code), §5.1-5.2 key revocation, §5.5 freshness-staple confidence, and the wire-layer edge
 * cases (oversized body, wrong content-type, confirming a request cannot smuggle in its own root
 * key). §3.4 scope and §5.4 certificate revocation are covered by chain-of-trust-vectors/ instead
 * of here — not duplicated in both places.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "crypto";
import { computeKid, createKeyCertificate, createFreshnessStaple, keyCertPayload, type KeyCertificate } from "./key-cert.js";
import { verifyChainPresentation } from "./chain-verify-core.js";
import { generateKeypair, sealToyArtifact } from "./test-helpers.js";
import { startReceiver } from "./receiver.js";

const ONE_YEAR = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
const YESTERDAY = new Date(Date.now() - 24 * 60 * 60 * 1000);

function buildBasicChain() {
  const root = generateKeypair();
  const intermediate = generateKeypair();
  const leaf = generateKeypair();
  const impostor = generateKeypair();

  const rootKid = computeKid(root.publicKeyPem);
  const intermediateKid = computeKid(intermediate.publicKeyPem);
  const leafKid = computeKid(leaf.publicKeyPem);

  const rootToIntermediate = createKeyCertificate({
    parentPrivateKeyPem: root.privateKeyPem, parentKid: rootKid,
    childPublicKeyPem: intermediate.publicKeyPem, expiresAt: ONE_YEAR,
  });
  const intermediateToLeaf = createKeyCertificate({
    parentPrivateKeyPem: intermediate.privateKeyPem, parentKid: intermediateKid,
    childPublicKeyPem: leaf.publicKeyPem, expiresAt: ONE_YEAR,
  });
  const intermediateToLeafExpired = createKeyCertificate({
    parentPrivateKeyPem: intermediate.privateKeyPem, parentKid: intermediateKid,
    childPublicKeyPem: leaf.publicKeyPem, expiresAt: YESTERDAY,
  });

  const artifactHonored = sealToyArtifact(leafKid, leaf.privateKeyPem, "honored");
  const artifactImpostor = sealToyArtifact(computeKid(impostor.publicKeyPem), impostor.privateKeyPem, "impostor");
  const artifactTampered = { ...artifactHonored, logic: { decisions: [{ injected: true }] } };

  return {
    root, intermediate, leaf, impostor, rootKid, intermediateKid, leafKid,
    chainSuccess: [rootToIntermediate, intermediateToLeaf],
    chainExpired: [rootToIntermediate, intermediateToLeafExpired],
    artifactHonored, artifactImpostor, artifactTampered,
  };
}

test("ALLOWED — full chain resolves, seal verifies", () => {
  const f = buildBasicChain();
  const v = verifyChainPresentation({ artifact: f.artifactHonored, chain: f.chainSuccess, rootPublicKeyPem: f.root.publicKeyPem });
  assert.equal(v.decision, "ALLOWED");
  if (v.decision === "ALLOWED") {
    assert.equal(v.leaf_kid, f.leafKid);
    assert.deepEqual(v.path, [f.rootKid, f.intermediateKid, f.leafKid]);
  }
});

test("ISSUER_NOT_RECOGNIZED — uncertified key sealed the artifact", () => {
  const f = buildBasicChain();
  const v = verifyChainPresentation({ artifact: f.artifactImpostor, chain: f.chainSuccess, rootPublicKeyPem: f.root.publicKeyPem });
  assert.equal(v.decision, "ISSUER_NOT_RECOGNIZED");
  if (v.decision === "ISSUER_NOT_RECOGNIZED") assert.equal(v.reason_code, "chain_broken");
});

test("ISSUER_NOT_RECOGNIZED — expired certificate, distinct reason", () => {
  const f = buildBasicChain();
  const v = verifyChainPresentation({ artifact: f.artifactHonored, chain: f.chainExpired, rootPublicKeyPem: f.root.publicKeyPem });
  assert.equal(v.decision, "ISSUER_NOT_RECOGNIZED");
  if (v.decision === "ISSUER_NOT_RECOGNIZED") assert.equal(v.reason_code, "expired");
});

test("order independence — reversed chain array reaches the identical verdict", () => {
  const f = buildBasicChain();
  const forward = verifyChainPresentation({ artifact: f.artifactHonored, chain: f.chainSuccess, rootPublicKeyPem: f.root.publicKeyPem });
  const reversed = verifyChainPresentation({ artifact: f.artifactHonored, chain: [...f.chainSuccess].reverse(), rootPublicKeyPem: f.root.publicKeyPem });
  assert.deepEqual(forward, reversed);
});

test("SEAL_INVALID — chain resolves fine but artifact was edited after sealing", () => {
  const f = buildBasicChain();
  const v = verifyChainPresentation({ artifact: f.artifactTampered, chain: f.chainSuccess, rootPublicKeyPem: f.root.publicKeyPem });
  assert.equal(v.decision, "SEAL_INVALID");
});

test("MALFORMED — artifact has no seal", () => {
  const v = verifyChainPresentation({ artifact: { meta: {} }, chain: [], rootPublicKeyPem: generateKeypair().publicKeyPem });
  assert.equal(v.decision, "MALFORMED");
});

test("MALFORMED — non-Ed25519 seal algorithm", () => {
  const f = buildBasicChain();
  const artifact = { ...f.artifactHonored, seal: { ...f.artifactHonored.seal, algorithm: "HMAC-SHA256" } };
  const v = verifyChainPresentation({ artifact, chain: f.chainSuccess, rootPublicKeyPem: f.root.publicKeyPem });
  assert.equal(v.decision, "MALFORMED");
});

test("MALFORMED — chain exceeds the length cap", () => {
  const f = buildBasicChain();
  const bloated = Array.from({ length: 21 }, () => ({}));
  const v = verifyChainPresentation({ artifact: f.artifactHonored, chain: bloated, rootPublicKeyPem: f.root.publicKeyPem });
  assert.equal(v.decision, "MALFORMED");
  if (v.decision === "MALFORMED") assert.match(v.detail, /exceeds the 20-certificate limit/);
});

test("MALFORMED — a certificate's signature field is not a string", () => {
  const f = buildBasicChain();
  const badChain = [{ ...f.chainSuccess[0], signature: 12345 } as unknown as KeyCertificate, f.chainSuccess[1]];
  const v = verifyChainPresentation({ artifact: f.artifactHonored, chain: badChain, rootPublicKeyPem: f.root.publicKeyPem });
  assert.equal(v.decision, "MALFORMED");
});

test("ISSUER_NOT_RECOGNIZED, not a crash — a validly-signed certificate names an unparseable child key", () => {
  // The root really did sign this (e.g. a buggy issuer, or corrupted key material) — the
  // certificate's own signature is genuine, but child_public_key_pem is not a real PEM. This is
  // exactly the case that, before the try/catch fix in key-cert.ts's verifyKeyCertificate, threw
  // an uncaught crypto exception on the *next* hop instead of failing closed.
  const f = buildBasicChain();
  const unsigned = {
    parent_kid: f.rootKid,
    child_kid: "not-derived-from-any-real-key",
    child_public_key_pem: "NOT A REAL PEM",
    issued_at: new Date().toISOString(),
    expires_at: ONE_YEAR.toISOString(),
  };
  const rootToGarbage: KeyCertificate = {
    ...unsigned,
    algorithm: "Ed25519",
    signature: crypto.sign(null, keyCertPayload(unsigned), crypto.createPrivateKey(f.root.privateKeyPem)).toString("base64"),
  };
  const garbageToLeaf: KeyCertificate = {
    parent_kid: "not-derived-from-any-real-key",
    child_kid: f.leafKid,
    child_public_key_pem: f.leaf.publicKeyPem,
    issued_at: new Date().toISOString(),
    expires_at: ONE_YEAR.toISOString(),
    algorithm: "Ed25519",
    signature: "deadbeef", // never reached — verifying it requires createPublicKey("NOT A REAL PEM") to succeed first
  };
  const v = verifyChainPresentation({ artifact: f.artifactHonored, chain: [rootToGarbage, garbageToLeaf], rootPublicKeyPem: f.root.publicKeyPem });
  assert.equal(v.decision, "ISSUER_NOT_RECOGNIZED");
  if (v.decision === "ISSUER_NOT_RECOGNIZED") assert.equal(v.reason_code, "bad_signature");
});

test("ISSUER_NOT_RECOGNIZED, not an infinite loop — a real signed cycle that never reaches the target", () => {
  const f = buildBasicChain();
  const a = generateKeypair();
  const aKid = computeKid(a.publicKeyPem);
  const rootToA = createKeyCertificate({ parentPrivateKeyPem: f.root.privateKeyPem, parentKid: f.rootKid, childPublicKeyPem: a.publicKeyPem, expiresAt: ONE_YEAR });
  const aToRoot = createKeyCertificate({ parentPrivateKeyPem: a.privateKeyPem, parentKid: aKid, childPublicKeyPem: f.root.publicKeyPem, expiresAt: ONE_YEAR });
  // Target (f.artifactHonored's leaf kid) never appears in this chain — root and A only certify
  // each other, so the walk must detect the cycle rather than loop forever.
  const v = verifyChainPresentation({ artifact: f.artifactHonored, chain: [rootToA, aToRoot], rootPublicKeyPem: f.root.publicKeyPem });
  assert.equal(v.decision, "ISSUER_NOT_RECOGNIZED");
  if (v.decision === "ISSUER_NOT_RECOGNIZED") assert.equal(v.reason_code, "cycle");
});

// ── §5.1-5.2 key revocation + §5.5 freshness staples ──────────────────────────────────────────

test("KEY_REVOKED — an own revocation source overrides everything, staples included", () => {
  const f = buildBasicChain();
  const revoked = verifyChainPresentation({ artifact: f.artifactHonored, chain: f.chainSuccess, rootPublicKeyPem: f.root.publicKeyPem, revokedKids: new Set([f.intermediateKid]) });
  assert.equal(revoked.decision, "KEY_REVOKED");
  if (revoked.decision === "KEY_REVOKED") assert.equal(revoked.revoked_kid, f.intermediateKid);

  const clean = verifyChainPresentation({ artifact: f.artifactHonored, chain: f.chainSuccess, rootPublicKeyPem: f.root.publicKeyPem, revokedKids: new Set(), revokedCerts: new Set() });
  assert.equal(clean.decision, "ALLOWED");
  if (clean.decision === "ALLOWED") assert.equal(clean.revocation_checked, "live");
});

test("no own source, no staple — fails open exactly as before, but now says so honestly", () => {
  const f = buildBasicChain();
  const v = verifyChainPresentation({ artifact: f.artifactHonored, chain: f.chainSuccess, rootPublicKeyPem: f.root.publicKeyPem });
  assert.equal(v.decision, "ALLOWED");
  if (v.decision === "ALLOWED") assert.equal(v.revocation_checked, "unchecked");
});

test("THE REGRESSION THIS TEST EXISTS FOR — a single staple-covered hop must not be dragged to 'unchecked' by the root's own inherent un-stapleable status", () => {
  const f = buildBasicChain();
  // Only the deepest hop needs a staple to exercise the bug: seeding revocationConfidence from
  // the ROOT's own (always-unchecked, since nothing certifies a root) confidence would drag this
  // down to 'unchecked' even though every hop that COULD be covered, was.
  const stapleRootToIntermediate = createFreshnessStaple({ parentPrivateKeyPem: f.root.privateKeyPem, parentKid: f.rootKid, childKid: f.intermediateKid, validUntil: ONE_YEAR });
  const stapleIntermediateToLeaf = createFreshnessStaple({ parentPrivateKeyPem: f.intermediate.privateKeyPem, parentKid: f.intermediateKid, childKid: f.leafKid, validUntil: ONE_YEAR });
  const v = verifyChainPresentation({ artifact: f.artifactHonored, chain: f.chainSuccess, rootPublicKeyPem: f.root.publicKeyPem, freshnessStaples: [stapleRootToIntermediate, stapleIntermediateToLeaf] });
  assert.equal(v.decision, "ALLOWED");
  if (v.decision === "ALLOWED") assert.equal(v.revocation_checked, "staple");
});

test("multi-hop weakest link — one uncovered hop pulls the whole aggregate down to 'unchecked'", () => {
  const f = buildBasicChain();
  const stapleRootToIntermediate = createFreshnessStaple({ parentPrivateKeyPem: f.root.privateKeyPem, parentKid: f.rootKid, childKid: f.intermediateKid, validUntil: ONE_YEAR });
  // Leaf hop's staple deliberately withheld.
  const v = verifyChainPresentation({ artifact: f.artifactHonored, chain: f.chainSuccess, rootPublicKeyPem: f.root.publicKeyPem, freshnessStaples: [stapleRootToIntermediate] });
  assert.equal(v.decision, "ALLOWED");
  if (v.decision === "ALLOWED") assert.equal(v.revocation_checked, "unchecked");
});

test("a forged staple (wrong signer, real label) is rejected, not trusted", () => {
  const f = buildBasicChain();
  const attacker = generateKeypair();
  const forged = createFreshnessStaple({ parentPrivateKeyPem: attacker.privateKeyPem, parentKid: f.intermediateKid, childKid: f.leafKid, validUntil: ONE_YEAR });
  const v = verifyChainPresentation({ artifact: f.artifactHonored, chain: f.chainSuccess, rootPublicKeyPem: f.root.publicKeyPem, freshnessStaples: [forged] });
  assert.equal(v.decision, "ALLOWED");
  if (v.decision === "ALLOWED") assert.equal(v.revocation_checked, "unchecked");
});

test("an expired staple counts as no staple at all", () => {
  const f = buildBasicChain();
  const expired = createFreshnessStaple({ parentPrivateKeyPem: f.intermediate.privateKeyPem, parentKid: f.intermediateKid, childKid: f.leafKid, issuedAt: new Date(Date.now() - 2 * 3600_000), validUntil: new Date(Date.now() - 3600_000) });
  const v = verifyChainPresentation({ artifact: f.artifactHonored, chain: f.chainSuccess, rootPublicKeyPem: f.root.publicKeyPem, freshnessStaples: [expired] });
  assert.equal(v.decision, "ALLOWED");
  if (v.decision === "ALLOWED") assert.equal(v.revocation_checked, "unchecked");
});

test("degenerate case — the root itself signed the artifact directly, nothing to staple-cover", () => {
  const f = buildBasicChain();
  const artifactSignedByRoot = sealToyArtifact(f.rootKid, f.root.privateKeyPem, "root-signed");
  const v = verifyChainPresentation({ artifact: artifactSignedByRoot, chain: [], rootPublicKeyPem: f.root.publicKeyPem });
  assert.equal(v.decision, "ALLOWED");
  if (v.decision === "ALLOWED") assert.equal(v.revocation_checked, "unchecked");
});

test("MALFORMED — a freshness staple's shape is invalid", () => {
  const f = buildBasicChain();
  const v = verifyChainPresentation({ artifact: f.artifactHonored, chain: f.chainSuccess, rootPublicKeyPem: f.root.publicKeyPem, freshnessStaples: [{ not: "a staple" }] });
  assert.equal(v.decision, "MALFORMED");
});

// ── Wire layer — real HTTP round trips against startReceiver(), not in-process function calls ──

async function withReceiver<T>(rootPublicKeyPem: string, fn: (url: string) => Promise<T>): Promise<T> {
  const server = startReceiver(rootPublicKeyPem, 0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  try {
    return await fn(`http://127.0.0.1:${port}/verify`);
  } finally {
    server.close();
  }
}

test("wire: ALLOWED over real HTTP", async () => {
  const f = buildBasicChain();
  await withReceiver(f.root.publicKeyPem, async (url) => {
    const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ artifact: f.artifactHonored, key_certs: f.chainSuccess }) });
    const body = await res.json();
    assert.equal(res.status, 200);
    assert.equal(body.decision, "ALLOWED");
  });
});

test("wire: ISSUER_NOT_RECOGNIZED → 403, SEAL_INVALID → 422", async () => {
  const f = buildBasicChain();
  await withReceiver(f.root.publicKeyPem, async (url) => {
    const notRecognized = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ artifact: f.artifactImpostor, key_certs: f.chainSuccess }) });
    assert.equal(notRecognized.status, 403);
    assert.equal((await notRecognized.json()).decision, "ISSUER_NOT_RECOGNIZED");

    const sealInvalid = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ artifact: f.artifactTampered, key_certs: f.chainSuccess }) });
    assert.equal(sealInvalid.status, 422);
    assert.equal((await sealInvalid.json()).decision, "SEAL_INVALID");
  });
});

test("wire: MALFORMED (400) for a missing key_certs field", async () => {
  const f = buildBasicChain();
  await withReceiver(f.root.publicKeyPem, async (url) => {
    const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ artifact: f.artifactHonored }) });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).decision, "MALFORMED");
  });
});

test("wire: wrong Content-Type is rejected (400), not parsed anyway", async () => {
  const f = buildBasicChain();
  await withReceiver(f.root.publicKeyPem, async (url) => {
    const res = await fetch(url, { method: "POST", headers: { "content-type": "text/plain" }, body: JSON.stringify({ artifact: f.artifactHonored, key_certs: f.chainSuccess }) });
    assert.equal(res.status, 400);
  });
});

test("wire: oversized body is rejected with 413, and the connection still yields a response", async () => {
  const f = buildBasicChain();
  await withReceiver(f.root.publicKeyPem, async (url) => {
    const huge = "x".repeat(2_000_000);
    const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ artifact: f.artifactHonored, key_certs: f.chainSuccess, padding: huge }) });
    assert.equal(res.status, 413);
    assert.equal((await res.json()).decision, "MALFORMED");
  });
});

test("wire: a presenter cannot smuggle in its own root key", async () => {
  const f = buildBasicChain();
  await withReceiver(f.root.publicKeyPem, async (url) => {
    const attackerRoot = generateKeypair();
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ artifact: f.artifactHonored, key_certs: f.chainSuccess, root_pubkey_pem: attackerRoot.publicKeyPem }),
    });
    const body = await res.json();
    // The receiver ignores the extra field entirely — the verdict is identical to the field
    // never having been sent, i.e. it still resolves against the receiver's OWN pinned root.
    assert.equal(res.status, 200);
    assert.equal(body.decision, "ALLOWED");
  });
});
