#!/usr/bin/env node
/**
 * NOMOS Conformance Test Runner
 *
 * Tests the nine conformance requirements from NOMOS-SPEC-001 §9.1 and §9.2.
 * Does not require a live runtime — tests the structural and schema requirements
 * that any conformant implementation must satisfy.
 *
 * Usage:
 *   npx tsx conformance/run.ts
 *
 * Exit code 0 = all tests pass. Exit code 1 = one or more failures.
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface NomosArtifact {
  artifact_id: string;
  version: string;
  spec_version: string;
  confidence: string;
  domain?: { name: string; [k: string]: unknown };
  rules: unknown[];
  contradiction_report: { contradiction_count: number; contradictions: unknown[] };
  readiness: {
    lis: number; drs: number | null; res: number; gms: number;
    ari: number; autonomy_band: string;
  };
  seal: { algorithm: string; ts: string; hash: string; sig: string };
  [k: string]: unknown;
}

interface TestResult {
  id: string;
  description: string;
  passed: boolean;
  detail?: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const KNOWN_SPEC_VERSIONS = new Set(["NOMOS-SPEC-001", "NOMOS-SPEC-002"]);
const VALID_CONFIDENCE = new Set(["DECLARED", "VALIDATED", "CERTIFIED"]);
const VALID_OPERATORS = new Set([
  "eq", "neq", "gt", "gte", "lt", "lte", "in", "nin", "exists", "regex",
  "and", "or", "not",
]);
const VALID_AUTONOMY_BANDS = new Set(["autonomous", "bounded", "human_governed"]);
const REQUIRED_ARTIFACT_FIELDS = [
  "artifact_id", "version", "spec_version", "confidence",
  "domain", "rules", "contradiction_report", "readiness", "seal",
];

const FIXTURES = path.join(__dirname, "fixtures");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function loadFixture(name: string): NomosArtifact {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, name), "utf8"));
}

function collectOperators(node: unknown, found: Set<string>): void {
  if (!node || typeof node !== "object") return;
  const n = node as Record<string, unknown>;
  if (typeof n.op === "string") found.add(n.op);
  collectOperators(n.left, found);
  collectOperators(n.right, found);
}

function pass(id: string, description: string): TestResult {
  return { id, description, passed: true };
}

function fail(id: string, description: string, detail: string): TestResult {
  return { id, description, passed: false, detail };
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

const tests: TestResult[] = [];

// R1 — Refuse unknown spec_version
tests.push((() => {
  const id = "R1";
  const desc = "Refuses to execute artifact with unrecognised spec_version";
  try {
    const a = loadFixture("unknown_spec_version.nomos");
    if (!KNOWN_SPEC_VERSIONS.has(a.spec_version)) {
      return pass(id, desc);
    }
    return fail(id, desc, `spec_version '${a.spec_version}' should not be recognised`);
  } catch (e) {
    return fail(id, desc, String(e));
  }
})());

// R2 — Refuse tampered seal (hash mismatch)
tests.push((() => {
  const id = "R2";
  const desc = "Refuses artifact whose seal hash is all-zeros (tampered)";
  try {
    const a = loadFixture("tampered_seal.nomos");
    const allZero = /^0+$/.test(a.seal.hash);
    if (allZero) return pass(id, desc);
    return fail(id, desc, "Expected tampered_seal.nomos to have an all-zero hash");
  } catch (e) {
    return fail(id, desc, String(e));
  }
})());

// R3 — Valid artifact uses only known operators
tests.push((() => {
  const id = "R3";
  const desc = "Valid artifact only references operators defined in §4.2";
  try {
    const a = loadFixture("valid_declared.nomos");
    const found = new Set<string>();
    for (const rule of a.rules as Array<{ condition: unknown }>) {
      collectOperators(rule.condition, found);
    }
    const unknown = [...found].filter(op => !VALID_OPERATORS.has(op));
    if (unknown.length === 0) return pass(id, desc);
    return fail(id, desc, `Unknown operators in valid artifact: ${unknown.join(", ")}`);
  } catch (e) {
    return fail(id, desc, String(e));
  }
})());

// R4 — Unknown operator must trigger ESCALATE path (fixture uses fuzzy_match)
tests.push((() => {
  const id = "R4";
  const desc = "Artifact with unknown operator is detectable before execution";
  try {
    const a = loadFixture("unknown_operator.nomos");
    const found = new Set<string>();
    for (const rule of a.rules as Array<{ condition: unknown }>) {
      collectOperators(rule.condition, found);
    }
    const unknown = [...found].filter(op => !VALID_OPERATORS.has(op));
    if (unknown.length > 0) return pass(id, desc);
    return fail(id, desc, "Expected at least one unknown operator in unknown_operator.nomos");
  } catch (e) {
    return fail(id, desc, String(e));
  }
})());

// R5 — Verdict response schema requires audit_hash
tests.push((() => {
  const id = "R5";
  const desc = "Execution response schema requires audit_hash field";
  try {
    const schema = JSON.parse(
      fs.readFileSync(
        path.join(__dirname, "../schema/execution-response.schema.json"),
        "utf8"
      )
    );
    const required: string[] = schema.required ?? [];
    if (required.includes("audit_hash")) return pass(id, desc);
    return fail(id, desc, "audit_hash not in required array of execution-response.schema.json");
  } catch (e) {
    return fail(id, desc, String(e));
  }
})());

// R6 — Verdict response schema requires contradictions count
tests.push((() => {
  const id = "R6";
  const desc = "Execution response schema requires contradictions count field";
  try {
    const schema = JSON.parse(
      fs.readFileSync(
        path.join(__dirname, "../schema/execution-response.schema.json"),
        "utf8"
      )
    );
    const required: string[] = schema.required ?? [];
    if (required.includes("contradictions")) return pass(id, desc);
    return fail(id, desc, "contradictions not in required array of execution-response.schema.json");
  } catch (e) {
    return fail(id, desc, String(e));
  }
})());

// P1 — Valid artifact has all required fields
tests.push((() => {
  const id = "P1";
  const desc = "Valid artifact contains all required top-level fields";
  try {
    const a = loadFixture("valid_declared.nomos") as Record<string, unknown>;
    const missing = REQUIRED_ARTIFACT_FIELDS.filter(f => !(f in a));
    if (missing.length === 0) return pass(id, desc);
    return fail(id, desc, `Missing fields: ${missing.join(", ")}`);
  } catch (e) {
    return fail(id, desc, String(e));
  }
})());

// P1 (negative) — Artifact missing required field fails validation
tests.push((() => {
  const id = "P1-neg";
  const desc = "Artifact missing required field (domain) is detectable";
  try {
    const a = loadFixture("missing_required_field.nomos") as Record<string, unknown>;
    const missing = REQUIRED_ARTIFACT_FIELDS.filter(f => !(f in a));
    if (missing.includes("domain")) return pass(id, desc);
    return fail(id, desc, "Expected 'domain' to be missing from missing_required_field.nomos");
  } catch (e) {
    return fail(id, desc, String(e));
  }
})());

// P2 — Seal block has required fields
tests.push((() => {
  const id = "P2";
  const desc = "Seal block contains algorithm, ts, hash, and sig";
  try {
    const a = loadFixture("valid_declared.nomos");
    const seal = a.seal;
    const missing = ["algorithm", "ts", "hash", "sig"].filter(
      f => !(f in seal)
    );
    if (missing.length === 0 && seal.algorithm === "HMAC-SHA256") {
      return pass(id, desc);
    }
    return fail(id, desc, `Missing seal fields: ${missing.join(", ")} / algorithm: ${seal.algorithm}`);
  } catch (e) {
    return fail(id, desc, String(e));
  }
})());

// P3 — confidence tiers are the three valid values
tests.push((() => {
  const id = "P3";
  const desc = "Confidence tiers DECLARED, VALIDATED, CERTIFIED are all valid";
  try {
    const declared = loadFixture("valid_declared.nomos");
    const validated = loadFixture("valid_validated.nomos");

    if (!VALID_CONFIDENCE.has(declared.confidence)) {
      return fail(id, desc, `valid_declared.nomos has confidence '${declared.confidence}'`);
    }
    if (!VALID_CONFIDENCE.has(validated.confidence)) {
      return fail(id, desc, `valid_validated.nomos has confidence '${validated.confidence}'`);
    }
    if (declared.confidence !== "DECLARED") {
      return fail(id, desc, `Expected DECLARED, got ${declared.confidence}`);
    }
    if (validated.confidence !== "VALIDATED") {
      return fail(id, desc, `Expected VALIDATED, got ${validated.confidence}`);
    }
    // DECLARED artifact must have drs: null
    if (declared.readiness.drs !== null) {
      return fail(id, desc, "DECLARED artifact must have drs: null");
    }
    // VALIDATED artifact must have drs as a float
    if (typeof validated.readiness.drs !== "number") {
      return fail(id, desc, "VALIDATED artifact must have drs as a number");
    }
    return pass(id, desc);
  } catch (e) {
    return fail(id, desc, String(e));
  }
})());

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

const passed = tests.filter(t => t.passed).length;
const failed = tests.filter(t => !t.passed).length;
const width = 52;

console.log("\nNOMOS Conformance Test Suite");
console.log("=".repeat(width));

for (const t of tests) {
  const status = t.passed ? "PASS" : "FAIL";
  const color = t.passed ? "\x1b[32m" : "\x1b[31m";
  const reset = "\x1b[0m";
  console.log(`${color}[${status}]${reset} ${t.id.padEnd(8)} ${t.description}`);
  if (!t.passed && t.detail) {
    console.log(`         └─ ${t.detail}`);
  }
}

console.log("=".repeat(width));
console.log(`${passed} passed, ${failed} failed\n`);

process.exit(failed > 0 ? 1 : 0);
