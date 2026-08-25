#!/usr/bin/env node
/**
 * NOMOS-SPEC-001 Reference Verifier (TypeScript / Node.js)
 *
 * Verifies a sealed .nomos artifact offline — no call to any NOMOS server. Two independent
 * checks, both must pass:
 *   1. integrity   — recompute the JCS/SHA-256 payload hash and compare to seal.hash
 *   2. authenticity —
 *        · Ed25519 (RECOMMENDED) — verify against the PUBLIC key (cannot forge). Fetch it once
 *          from /.well-known/nomos-signing-keys (--url) or pass it directly (--pubkey).
 *        · HMAC-SHA256 (legacy) — symmetric; needs the shared secret, not third-party verifiable.
 *
 * A third, optional check (NOMOS-SPEC-006 — Artifact Revocation):
 *   3. revocation  — with --revocations <file>, checks the artifact's seal.hash against a
 *                    downloaded, signed revocation list (§4). Without it, prints an explicit
 *                    warning that revocation was NOT checked — fail-open, but never silently
 *                    (§5.2). Seal validity and revocation status are reported as distinct facts.
 *
 * Usage:
 *   npx tsx verify.ts <artifact.nomos> --url https://nomosprotocol.com   # fetch the public key
 *   npx tsx verify.ts <artifact.nomos> --pubkey signing_key.pub.pem      # fully offline
 *   npx tsx verify.ts <artifact.nomos> --key <hex-or-raw>                # legacy HMAC seals
 *   npx tsx verify.ts <artifact.nomos> --pubkey key.pem --revocations revocations.json
 *
 * No external dependencies — Node.js built-in crypto (Ed25519 native).
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

// ── RFC 8785 JSON Canonicalization Scheme (JCS) — minimal implementation ──
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
const jcs = (obj: unknown): Buffer => Buffer.from(jcsValue(obj as JsonValue), "utf8");

function fail(msg: string): never {
  console.error(`\n  [FAIL] ${msg}\n\nResult: INVALID\n`);
  process.exit(1);
}

async function fetchPublicKey(baseUrl: string, kid?: string): Promise<string | null> {
  const r = await fetch(baseUrl.replace(/\/$/, "") + "/.well-known/nomos-signing-keys");
  const { keys } = (await r.json()) as { keys: Array<{ kid: string; public_key_pem: string }> };
  if (!keys?.length) return null;
  return (keys.find((k) => k.kid === kid) ?? keys[0]).public_key_pem;
}

// ── NOMOS-SPEC-006 — Artifact Revocation ──
type RevocationStatement = {
  artifact_id: string; artifact_version: string; artifact_hash: string;
  reason: string; algorithm: string; kid: string; signature: string; issued_at: string;
};
type RevocationList = {
  generated_at: string; algorithm: string; kid: string;
  statements: RevocationStatement[]; signature: string;
};

function verifyEd25519(payload: Buffer, signatureB64: string, pem: string): boolean {
  return crypto.verify(null, payload, crypto.createPublicKey(pem), Buffer.from(signatureB64, "base64"));
}

async function resolveKey(kid: string, opts: { pubkeyPem: string | null; url: string | null }): Promise<string | null> {
  if (opts.pubkeyPem) return opts.pubkeyPem;
  if (opts.url) return fetchPublicKey(opts.url, kid);
  return null;
}

/**
 * §5.1/§5.2 — checks a downloaded revocation list when supplied; otherwise prints an explicit,
 * unmissable notice that revocation was not checked. Never silently omits the check (fail-open,
 * but loud). A found, bound, and authentic revocation statement exits distinctly from a seal
 * failure — REVOKED is not the same finding as INVALID.
 */
async function checkRevocation(seal: { hash: string }, revocationsPath: string | null, opts: { pubkeyPem: string | null; url: string | null }): Promise<"unchecked" | "clean"> {
  if (!revocationsPath) {
    console.log("  [WARN] Revocation not checked — no --revocations file supplied and no network");
    console.log("         fetch was attempted. This artifact's current standing with its issuer is");
    console.log("         UNKNOWN. Seal integrity does not imply the issuer still stands behind this");
    console.log("         version. Supply --revocations <file> to check against a downloaded list.");
    return "unchecked";
  }

  const list: RevocationList = JSON.parse(fs.readFileSync(revocationsPath, "utf8"));

  const listPem = await resolveKey(list.kid, opts);
  const listPayload = jcs({ generated_at: list.generated_at, statements: list.statements });
  const listTrusted = !!listPem && verifyEd25519(listPayload, list.signature, listPem);
  if (listTrusted) {
    console.log(`  [OK] Revocation list signature verified (generated_at: ${list.generated_at})`);
  } else {
    console.log(`  [WARN] Revocation list signature could NOT be verified (no key, or signature`);
    console.log(`         mismatch) — treating the list transport as untrusted. Each contained`);
    console.log(`         statement is still checked independently below (§5.1.3).`);
  }

  // Check every statement independently, regardless of list-level trust — a corrupted or
  // untrusted list transport must not hide a genuine, individually-signed revocation.
  for (const stmt of list.statements ?? []) {
    if (stmt.artifact_hash !== seal.hash) continue; // not bound to this version (§3.4)
    const stmtPem = await resolveKey(stmt.kid, opts);
    if (!stmtPem) {
      console.log(`  [WARN] Found a statement naming this artifact_hash, but could not resolve kid`);
      console.log(`         "${stmt.kid}" to verify it. Treat as unconfirmed, not as cleared.`);
      continue;
    }
    const stmtPayload = jcs({
      artifact_id: stmt.artifact_id,
      artifact_version: stmt.artifact_version,
      artifact_hash: stmt.artifact_hash,
      reason: stmt.reason,
      issued_at: stmt.issued_at,
    });
    if (verifyEd25519(stmtPayload, stmt.signature, stmtPem)) {
      console.error(`\n  [REVOKED] This artifact version has been revoked by its issuer.`);
      console.error(`    reason    : ${stmt.reason}`);
      console.error(`    issued_at : ${stmt.issued_at}`);
      console.error(`    kid       : ${stmt.kid}`);
      console.error(`\nResult: REVOKED\n`);
      process.exit(2);
    }
  }
  console.log(`  [OK] No matching revocation found for this artifact_hash as of ${list.generated_at}.`);
  return "clean";
}

async function verifyArtifact(artifactPath: string, opts: { sealKey: Buffer | null; pubkeyPem: string | null; url: string | null; revocations: string | null }): Promise<void> {
  const artifact: any = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const seal = artifact.seal;
  const meta = artifact.meta ?? {};
  const alg: string = seal?.signature_algorithm ?? seal?.algorithm ?? "";
  console.log(`\nVerifying: ${artifactPath}`);
  console.log(`  artifact_id : ${meta.artifact_id}`);
  console.log(`  version     : ${meta.version}`);
  console.log(`  algorithm   : ${alg}    kid=${seal?.kid ?? "—"}`);

  if (!seal || seal.status === "draft") fail("Artifact is not sealed");

  // 1. Integrity — recompute the canonical hash (offline, no key)
  // Excludes both `seal` (can't cover itself) and `attestations` (NOMOS-SPEC-004 — added
  // after sealing by third parties; including them would break the seal the moment an
  // attestation is added or revoked). See spec §8.2.
  const payload = Object.fromEntries(Object.entries(artifact).filter(([k]) => k !== "seal" && k !== "attestations")) as Record<string, JsonValue>;
  const computedHash = crypto.createHash("sha256").update(jcs(payload)).digest("hex");
  if (computedHash !== seal.hash) {
    fail(`Hash mismatch — payload modified after sealing.\n  stored  : ${seal.hash}\n  computed: ${computedHash}`);
  }
  console.log(`  [OK] Payload hash matches: ${computedHash.slice(0, 16)}...`);

  // 2. Authenticity
  if (alg === "Ed25519" || alg === "RS256" || alg === "ES256") {
    let pem = opts.pubkeyPem;
    if (!pem && opts.url) pem = await fetchPublicKey(opts.url, seal.kid);
    if (!pem) fail("Provide the published key with --pubkey <pem> or --url <host> (fetches /.well-known/nomos-signing-keys).");
    const signed = jcs({ hash: seal.hash, signed_by: seal.signed_by });
    const hashAlgo = alg === "Ed25519" ? null : "sha256";     // Ed25519 signs raw bytes; RSA/EC pre-hash
    const valid = crypto.verify(hashAlgo, signed, crypto.createPublicKey(pem as string), Buffer.from(seal.signature, "base64"));
    if (!valid) fail("Signature does not verify — forged, wrong key, or the seal was altered.");
    console.log(`  [OK] ${alg} signature verified against the published PUBLIC key (no secret, no server call).`);
  } else if (alg === "HMAC-SHA256") {
    if (!opts.sealKey) {
      console.log("  [SKIP] HMAC (symmetric) seal — needs the shared secret; not third-party verifiable. Pass --key, or re-seal with Ed25519.");
    } else {
      const computedSig = crypto.createHmac("sha256", opts.sealKey).update(computedHash, "ascii").digest("hex");
      const stored = seal.sig ?? seal.signature ?? "";
      if (!crypto.timingSafeEqual(Buffer.from(computedSig, "hex"), Buffer.from(stored, "hex"))) fail("HMAC signature mismatch — wrong key or tampered hash.");
      console.log("  [OK] HMAC signature verified (symmetric — required the shared secret).");
    }
  } else {
    fail(`Unsupported seal algorithm: ${JSON.stringify(alg)}`);
  }

  // 3. Advisory — verification tier + conflicts at seal time
  console.log(`  [OK] Verification tier: ${meta.verification_tier ?? "N/A"}`);
  const pending = artifact.provenance?.review_summary?.pending_at_seal ?? 0;
  console.log(pending > 0 ? `  [WARN] ${pending} unresolved conflict(s) at seal time.` : "  [OK] No unresolved conflicts recorded at seal time.");

  // 4. Revocation (NOMOS-SPEC-006) — reported as a distinct fact, not folded into seal validity
  const revocationResult = await checkRevocation(seal, opts.revocations, opts);
  console.log(
    revocationResult === "clean"
      ? "\nResult: VALID (revocation checked — not revoked)\n"
      : "\nResult: VALID (seal only — revocation unchecked)\n"
  );
}

// ── CLI ──
const args = process.argv.slice(2);
if (!args.length) { console.error("Usage: verify.ts <artifact.nomos> [--url <host> | --pubkey <pem> | --key <hex>] [--revocations <file>]"); process.exit(1); }
const artifactPath = path.resolve(args[0]);
let pubkeyPem: string | null = null, url: string | null = null, rawKey: string | undefined, revocations: string | null = null;
for (let i = 1; i < args.length; i++) {
  if (args[i] === "--pubkey" && args[i + 1]) { pubkeyPem = fs.readFileSync(args[++i], "utf8"); }
  else if (args[i] === "--url" && args[i + 1]) { url = args[++i]; }
  else if (args[i] === "--key" && args[i + 1]) { rawKey = args[++i]; }
  else if (args[i] === "--key-env" && args[i + 1]) { rawKey = process.env[args[++i]]; }
  else if (args[i] === "--revocations" && args[i + 1]) { revocations = path.resolve(args[++i]); }
}
rawKey = rawKey ?? process.env["NOMOS_SEAL_KEY"];
let sealKey: Buffer | null = null;
if (rawKey) { try { sealKey = Buffer.from(rawKey.trim(), "hex"); if (!sealKey.length) throw new Error(); } catch { sealKey = Buffer.from(rawKey, "utf8"); } }

verifyArtifact(artifactPath, { sealKey, pubkeyPem, url, revocations }).catch((e) => fail(String(e?.message ?? e)));
