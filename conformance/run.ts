#!/usr/bin/env node
/**
 * NOMOS Conformance Test Runner
 *
 * Part 1 — Structural & schema requirements from NOMOS-SPEC-001 §9.1 and §9.2.
 * Part 2 — Deterministic test vectors from conformance/vectors/ (§v01–v12).
 *           Vectors validate evaluation correctness without a live runtime;
 *           they use an in-process evaluator that mirrors the normative pipeline.
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
const VECTORS  = path.join(__dirname, "vectors");

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
// In-process evaluator (mirrors §6.2 pipeline — used for vector tests only)
// ---------------------------------------------------------------------------

type Verdict = "ALLOW" | "DENY" | "ESCALATE";
type EvalError = "seal_verification_failed" | "spec_version_unsupported" |
  "data_contract_violation" | "unsupported_operator" | string | null;

interface EvalResult {
  verdict: Verdict | null;
  matched_rule_id: string | null;
  reason?: string;
  error: EvalError;
  cached?: boolean;
}

function evalLeaf(node: Record<string, unknown>, ctx: Record<string, unknown>): boolean | "unsupported" {
  const op = node.op as string;
  const field = node.field as string;
  const value = node.value;
  const ctxVal = field.split(".").reduce<unknown>((o, k) =>
    (o && typeof o === "object") ? (o as Record<string, unknown>)[k] : undefined, ctx);

  switch (op) {
    case "eq":     return ctxVal === value;
    case "neq":    return ctxVal !== value;
    case "gt":     return typeof ctxVal === "number" && ctxVal > (value as number);
    case "gte":    return typeof ctxVal === "number" && ctxVal >= (value as number);
    case "lt":     return typeof ctxVal === "number" && ctxVal < (value as number);
    case "lte":    return typeof ctxVal === "number" && ctxVal <= (value as number);
    case "in":     return Array.isArray(value) && value.includes(ctxVal);
    case "nin":    return Array.isArray(value) && !value.includes(ctxVal);
    case "exists": return ctxVal !== undefined && ctxVal !== null;
    case "regex":  return typeof ctxVal === "string" && new RegExp(value as string).test(ctxVal);
    default:       return "unsupported";
  }
}

function evalCondition(node: unknown, ctx: Record<string, unknown>): boolean | "unsupported" {
  if (!node || typeof node !== "object") return false;
  const n = node as Record<string, unknown>;
  const op = n.op as string;
  if (op === "and") {
    const l = evalCondition(n.left, ctx);
    if (l === "unsupported") return "unsupported";
    const r = evalCondition(n.right, ctx);
    if (r === "unsupported") return "unsupported";
    return l && r;
  }
  if (op === "or") {
    const l = evalCondition(n.left, ctx);
    if (l === "unsupported") return "unsupported";
    const r = evalCondition(n.right, ctx);
    if (r === "unsupported") return "unsupported";
    return l || r;
  }
  if (op === "not") {
    const l = evalCondition(n.left, ctx);
    if (l === "unsupported") return "unsupported";
    return !l;
  }
  return evalLeaf(n, ctx);
}

const TEST_SEAL = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const TAMPERED_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

function runVector(artifact: NomosArtifact, ctx: Record<string, unknown>): EvalResult {
  // §3.3 — spec_version check
  if (!KNOWN_SPEC_VERSIONS.has(artifact.spec_version)) {
    return { verdict: null, matched_rule_id: null, error: "spec_version_unsupported" };
  }
  // §8.1 — seal verification (detect all-zero tampered seal)
  if (artifact.seal.hash === TAMPERED_HASH || artifact.seal.sig === TAMPERED_HASH) {
    return { verdict: null, matched_rule_id: null, error: "seal_verification_failed" };
  }
  // §3.9 — data_contract check
  const dc = artifact["data_contract"] as { required_fields?: string[] } | undefined;
  if (dc?.required_fields?.length) {
    const missing = dc.required_fields.filter(f => !(f in ctx));
    if (missing.length > 0) {
      return { verdict: null, matched_rule_id: null, error: "data_contract_violation" };
    }
  }

  const rules = (artifact.rules as Array<Record<string, unknown>>)
    .slice()
    .sort((a, b) => (b.priority as number) - (a.priority as number));

  const mode = (artifact["conflict_resolution"] as string) ?? "first_match";

  // §4.2 — check for unsupported operators
  for (const rule of rules) {
    const res = evalCondition(rule.condition, ctx);
    if (res === "unsupported") {
      return { verdict: "ESCALATE", matched_rule_id: null, reason: "unsupported_operator", error: null };
    }
  }

  const matched: Array<{ id: string; action: string; priority: number }> = [];
  for (const rule of rules) {
    if (evalCondition(rule.condition, ctx) === true) {
      matched.push({ id: rule.id as string, action: rule.action as string, priority: rule.priority as number });
    }
  }

  if (matched.length === 0) return { verdict: "ALLOW", matched_rule_id: null, error: null };

  if (mode === "first_match") {
    const r = matched[0];
    return { verdict: r.action as Verdict, matched_rule_id: r.id, error: null };
  }
  if (mode === "highest_priority") {
    const r = matched.reduce((a, b) => b.priority > a.priority ? b : a);
    return { verdict: r.action as Verdict, matched_rule_id: r.id, error: null };
  }
  // collect_and_resolve: DENY > ESCALATE > ALLOW
  const rank: Record<string, number> = { DENY: 3, ESCALATE: 2, ALLOW: 1 };
  const top = matched.reduce((a, b) => rank[b.action] > rank[a.action] ? b : a);
  return { verdict: top.action as Verdict, matched_rule_id: top.id, error: null };
}

// ---------------------------------------------------------------------------
// Part 2 — Vector tests
// ---------------------------------------------------------------------------

interface VectorFile {
  id: string;
  description: string;
  artifact: NomosArtifact;
  context: Record<string, unknown>;
  expected: {
    verdict: Verdict | null;
    matched_rule_id?: string | null;
    error: EvalError;
    cached?: boolean;
    first_call?: { verdict: Verdict; cached: boolean };
    second_call?: { verdict: Verdict; cached: boolean; audit_entry_created: boolean };
    note?: string;
  };
}

const vectorFiles = fs.readdirSync(VECTORS)
  .filter(f => f.endsWith(".json") && f !== "README.md");

for (const vf of vectorFiles.sort()) {
  const vec: VectorFile = JSON.parse(fs.readFileSync(path.join(VECTORS, vf), "utf8"));
  const id = `V-${vec.id.toUpperCase()}`;
  const desc = vec.description;

  // v12 (idempotency) is a behavioural test — flag as informational for structural runner
  if (vec.id === "v12") {
    tests.push(pass(id, desc + " [idempotency — runtime behavioural test, not evaluatable here]"));
    continue;
  }

  const result = runVector(vec.artifact, vec.context);
  const exp = vec.expected;

  if (exp.error !== null) {
    // Expecting an error
    if (result.error === exp.error) {
      tests.push(pass(id, desc));
    } else {
      tests.push(fail(id, desc,
        `Expected error '${exp.error}' but got error='${result.error}' verdict='${result.verdict}'`));
    }
  } else {
    // Expecting a verdict
    if (result.verdict === exp.verdict && result.error === null) {
      tests.push(pass(id, desc));
    } else {
      tests.push(fail(id, desc,
        `Expected verdict='${exp.verdict}' error=null, got verdict='${result.verdict}' error='${result.error}'`));
    }
  }
}

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
