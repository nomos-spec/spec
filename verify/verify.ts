#!/usr/bin/env node
/**
 * NOMOS-SPEC-001 Reference Verifier (TypeScript / Node.js)
 *
 * Verifies the cryptographic seal of a .nomos artifact.
 *
 * Usage:
 *   npx tsx verify.ts <artifact.nomos> --key <hex-or-raw-seal-key>
 *   npx tsx verify.ts <artifact.nomos> --key-env NOMOS_SEAL_KEY
 *   npx tsx verify.ts <artifact.nomos>   # structure check only
 *
 * No external dependencies — uses Node.js built-in crypto.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

// ---------------------------------------------------------------------------
// RFC 8785 JSON Canonicalization Scheme (JCS) — minimal implementation
// ---------------------------------------------------------------------------

type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

function jcsValue(value: JsonValue): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!isFinite(value)) throw new Error("NaN / Infinity not valid in JCS");
    return String(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(jcsValue).join(",") + "]";
  }
  if (typeof value === "object") {
    const pairs = Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${jcsValue(value[k])}`);
    return "{" + pairs.join(",") + "}";
  }
  throw new TypeError(`Unsupported type: ${typeof value}`);
}

function jcsCanonicalize(obj: Record<string, JsonValue>): Buffer {
  return Buffer.from(jcsValue(obj), "utf8");
}

// ---------------------------------------------------------------------------
// Seal verification
// ---------------------------------------------------------------------------

interface SealBlock {
  algorithm: string;
  ts: string;
  hash: string;
  sig: string;
}

interface NomosArtifact {
  artifact_id?: string;
  version?: string;
  spec_version?: string;
  confidence?: string;
  contradiction_report?: { contradiction_count?: number };
  readiness?: { ari?: number; autonomy_band?: string };
  seal?: SealBlock;
  [key: string]: JsonValue | undefined;
}

function fail(msg: string): never {
  console.error(`\n  [FAIL] ${msg}`);
  console.error("\nResult: INVALID\n");
  process.exit(1);
}

function verifyArtifact(artifactPath: string, sealKey: Buffer | null): void {
  const raw = fs.readFileSync(artifactPath, "utf8");
  const artifact: NomosArtifact = JSON.parse(raw);

  console.log(`\nVerifying: ${artifactPath}`);
  console.log(`  artifact_id : ${artifact.artifact_id}`);
  console.log(`  version     : ${artifact.version}`);
  console.log(`  spec_version: ${artifact.spec_version}`);
  console.log(`  confidence  : ${artifact.confidence}`);

  // 1. Check spec version
  if (artifact.spec_version !== "NOMOS-SPEC-001") {
    fail(`Unknown spec_version: ${JSON.stringify(artifact.spec_version)}`);
  }

  // 2. Extract seal
  const seal = artifact.seal;
  if (!seal) fail("Missing 'seal' block");

  const { hash: storedHash, sig: storedSig, algorithm } = seal;
  if (algorithm !== "HMAC-SHA256") {
    fail(`Unsupported seal algorithm: ${JSON.stringify(algorithm)}`);
  }

  // 3. Recompute payload hash
  const payload = Object.fromEntries(
    Object.entries(artifact).filter(([k]) => k !== "seal")
  ) as Record<string, JsonValue>;

  const canonical = jcsCanonicalize(payload);
  const computedHash = crypto.createHash("sha256").update(canonical).digest("hex");

  if (computedHash !== storedHash) {
    fail(
      `Hash mismatch!\n` +
      `  stored  : ${storedHash}\n` +
      `  computed: ${computedHash}\n` +
      `  The artifact payload has been modified after sealing.`
    );
  }
  console.log(`  [OK] Payload hash matches: ${computedHash.slice(0, 16)}...`);

  // 4. Verify HMAC signature
  if (!sealKey) {
    console.log("  [SKIP] No seal key provided — signature not verified.");
    console.log("         Pass --key or --key-env to verify the full seal.");
  } else {
    const computedSig = crypto
      .createHmac("sha256", sealKey)
      .update(computedHash, "ascii")
      .digest("hex");

    if (!crypto.timingSafeEqual(Buffer.from(computedSig, "hex"), Buffer.from(storedSig, "hex"))) {
      fail(
        "Signature mismatch!\n" +
        "  The seal key does not match, or the hash field was tampered with."
      );
    }
    console.log("  [OK] HMAC signature verified.");
  }

  // 5. Contradiction check
  const count = artifact.contradiction_report?.contradiction_count ?? 0;
  if (count > 0) {
    console.log(`  [WARN] ${count} contradiction(s) detected at seal time.`);
  } else {
    console.log("  [OK] No contradictions.");
  }

  // 6. Readiness summary
  const r = artifact.readiness;
  console.log(`  [OK] Readiness: ARI=${r?.ari ?? "N/A"}  band=${r?.autonomy_band ?? "N/A"}`);

  console.log("\nResult: VALID\n");
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(): { artifactPath: string; sealKey: Buffer | null } {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.error("Usage: verify.ts <artifact.nomos> [--key <hex>] [--key-env <VAR>]");
    process.exit(1);
  }

  const artifactPath = path.resolve(args[0]);
  let rawKey: string | undefined;

  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--key" && args[i + 1]) {
      rawKey = args[i + 1];
      i++;
    } else if (args[i] === "--key-env" && args[i + 1]) {
      rawKey = process.env[args[i + 1]];
      i++;
    }
  }

  if (!rawKey) {
    rawKey = process.env["NOMOS_SEAL_KEY"];
  }

  let sealKey: Buffer | null = null;
  if (rawKey) {
    try {
      sealKey = Buffer.from(rawKey.trim(), "hex");
      if (sealKey.length === 0) throw new Error("empty hex");
    } catch {
      sealKey = Buffer.from(rawKey, "utf8");
    }
  }

  return { artifactPath, sealKey };
}

const { artifactPath, sealKey } = parseArgs();
verifyArtifact(artifactPath, sealKey);
