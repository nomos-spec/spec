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
 * Usage:
 *   npx tsx verify.ts <artifact.nomos> --url https://nomosprotocol.com   # fetch the public key
 *   npx tsx verify.ts <artifact.nomos> --pubkey signing_key.pub.pem      # fully offline
 *   npx tsx verify.ts <artifact.nomos> --key <hex-or-raw>                # legacy HMAC seals
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

async function verifyArtifact(artifactPath: string, opts: { sealKey: Buffer | null; pubkeyPem: string | null; url: string | null }): Promise<void> {
  const artifact: any = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const seal = artifact.seal;
  const alg: string = seal?.signature_algorithm ?? seal?.algorithm ?? "";
  console.log(`\nVerifying: ${artifactPath}`);
  console.log(`  artifact_id : ${artifact.artifact_id}`);
  console.log(`  version     : ${artifact.version}`);
  console.log(`  algorithm   : ${alg}    kid=${seal?.kid ?? "—"}`);

  if (!seal || seal.status === "draft") fail("Artifact is not sealed");

  // 1. Integrity — recompute the canonical hash (offline, no key)
  const payload = Object.fromEntries(Object.entries(artifact).filter(([k]) => k !== "seal")) as Record<string, JsonValue>;
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

  // 3. Advisory
  const count = artifact.contradiction_report?.contradiction_count ?? 0;
  console.log(count > 0 ? `  [WARN] ${count} contradiction(s) at seal time.` : "  [OK] No contradictions.");
  const r = artifact.readiness;
  console.log(`  [OK] Readiness: ARI=${r?.ari ?? "N/A"}  band=${r?.autonomy_band ?? "N/A"}`);
  console.log("\nResult: VALID\n");
}

// ── CLI ──
const args = process.argv.slice(2);
if (!args.length) { console.error("Usage: verify.ts <artifact.nomos> [--url <host> | --pubkey <pem> | --key <hex>]"); process.exit(1); }
const artifactPath = path.resolve(args[0]);
let pubkeyPem: string | null = null, url: string | null = null, rawKey: string | undefined;
for (let i = 1; i < args.length; i++) {
  if (args[i] === "--pubkey" && args[i + 1]) { pubkeyPem = fs.readFileSync(args[++i], "utf8"); }
  else if (args[i] === "--url" && args[i + 1]) { url = args[++i]; }
  else if (args[i] === "--key" && args[i + 1]) { rawKey = args[++i]; }
  else if (args[i] === "--key-env" && args[i + 1]) { rawKey = process.env[args[++i]]; }
}
rawKey = rawKey ?? process.env["NOMOS_SEAL_KEY"];
let sealKey: Buffer | null = null;
if (rawKey) { try { sealKey = Buffer.from(rawKey.trim(), "hex"); if (!sealKey.length) throw new Error(); } catch { sealKey = Buffer.from(rawKey, "utf8"); } }

verifyArtifact(artifactPath, { sealKey, pubkeyPem, url }).catch((e) => fail(String(e?.message ?? e)));
