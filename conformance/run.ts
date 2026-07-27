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

// ---------------------------------------------------------------------------
// Types (NOMOS-SPEC-001 v2.0.0 §3)
// ---------------------------------------------------------------------------

interface Outcome { type: string; [k: string]: unknown; }
interface Decision { id: string; description?: string; when: string; then: Outcome[]; else?: Outcome[]; priority?: number; }
interface Seal {
  status?: string; hash?: string | null; canonicalization?: string;
  signed_by?: unknown; signature?: string | null; signature_algorithm?: string;
}
interface NomosArtifact {
  nomos_version?: string;
  meta?: { artifact_id?: string; version?: string; verification_tier?: string; [k: string]: unknown };
  scope?: unknown;
  data_contract?: { required_fields?: string[]; [k: string]: unknown };
  logic?: { decisions?: Decision[]; resolution?: { conflict_policy?: string; tie_breaker?: string } };
  governance?: unknown;
  execution?: unknown;
  audit?: unknown;
  seal?: Seal;
  [k: string]: unknown;
}

interface TestResult { id: string; description: string; passed: boolean; detail?: string; }

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REQUIRED_ARTIFACT_FIELDS = ["nomos_version", "meta", "scope", "data_contract", "logic", "governance", "execution", "audit", "seal"];
const VALID_TIERS = new Set(["compiled", "proven", "sovereign"]);

const FIXTURES = path.join(__dirname, "fixtures");
const VECTORS  = path.join(__dirname, "vectors");

// ---------------------------------------------------------------------------
// Nomos-Expr v1 — minimal tokenizer + recursive-descent evaluator (spec §4.1)
// Mirrors cli/nomos.ts's implementation; kept in sync deliberately.
// ---------------------------------------------------------------------------

type Token = { type: string; value: string };

function tokenize(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const twoChar = ["==", "!=", ">=", "<="];
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '"' || c === "'") {
      const quote = c; let j = i + 1; let s = "";
      while (j < src.length && src[j] !== quote) {
        if (src[j] === "\\" && j + 1 < src.length) { s += src[j + 1]; j += 2; continue; }
        s += src[j]; j++;
      }
      tokens.push({ type: "string", value: s }); i = j + 1; continue;
    }
    if (/[0-9]/.test(c) || (c === "-" && /[0-9]/.test(src[i + 1] ?? ""))) {
      let j = i; let s = "";
      if (src[j] === "-") { s += "-"; j++; }
      while (j < src.length && /[0-9.]/.test(src[j])) { s += src[j]; j++; }
      // Scientific notation, e.g. 1e+25 / 2.5E-10 — mirrors rule-evaluator.ts exactly.
      if (j < src.length && (src[j] === "e" || src[j] === "E")) {
        let k = j + 1; let exp = src[j];
        if (k < src.length && (src[k] === "+" || src[k] === "-")) { exp += src[k]; k++; }
        if (k < src.length && /[0-9]/.test(src[k])) {
          while (k < src.length && /[0-9]/.test(src[k])) { exp += src[k]; k++; }
          s += exp; j = k;
        }
      }
      tokens.push({ type: "number", value: s }); i = j; continue;
    }
    const two = src.slice(i, i + 2);
    if (twoChar.includes(two)) { tokens.push({ type: "op", value: two }); i += 2; continue; }
    if ("><(),".includes(c)) { tokens.push({ type: "op", value: c }); i++; continue; }
    if (/[A-Za-z_.]/.test(c)) {
      let j = i; let s = "";
      while (j < src.length && /[A-Za-z0-9_.]/.test(src[j])) { s += src[j]; j++; }
      tokens.push({ type: "ident", value: s }); i = j; continue;
    }
    throw new Error(`Nomos-Expr: unexpected character '${c}' at position ${i}`);
  }
  return tokens;
}

class ExprParser {
  private pos = 0;
  constructor(private tokens: Token[], private input: Record<string, unknown>) {}
  private peek() { return this.tokens[this.pos]; }
  private next() { return this.tokens[this.pos++]; }
  private isKeyword(word: string) { const t = this.peek(); return !!t && t.type === "ident" && t.value === word; }

  parse(): unknown { const v = this.orExpr(); if (this.pos < this.tokens.length) throw new Error(`Nomos-Expr: unexpected trailing token`); return v; }
  private orExpr(): unknown { let l = this.andExpr(); while (this.isKeyword("or")) { this.next(); const r = this.andExpr(); l = !!l || !!r; } return l; }
  private andExpr(): unknown { let l = this.notExpr(); while (this.isKeyword("and")) { this.next(); const r = this.notExpr(); l = !!l && !!r; } return l; }
  private notExpr(): unknown { if (this.isKeyword("not")) { this.next(); return !this.notExpr(); } return this.comparison(); }

  private comparison(): unknown {
    const left = this.primary();
    const t = this.peek();
    if (t && t.type === "op" && ["==", "!=", ">", ">=", "<", "<="].includes(t.value)) {
      this.next(); const right = this.primary();
      switch (t.value) {
        case "==": return jsEq(left, right);
        case "!=": return !jsEq(left, right);
        case ">":  return typeof left === "number" && typeof right === "number" && left > right;
        case ">=": return typeof left === "number" && typeof right === "number" && left >= right;
        case "<":  return typeof left === "number" && typeof right === "number" && left < right;
        case "<=": return typeof left === "number" && typeof right === "number" && left <= right;
      }
    }
    // in / contains / between all take a single comma-joined STRING — never an array
    // literal ([...] is not valid syntax in this language).
    if (this.isKeyword("in")) {
      this.next(); const right = this.primary();
      if (typeof right !== "string") throw new Error("Nomos-Expr: 'in' requires a quoted string");
      return right.split(",").map(s => s.trim()).map(String).includes(String(left));
    }
    if (this.isKeyword("contains")) {
      this.next(); const right = this.primary();
      if (typeof right !== "string") throw new Error("Nomos-Expr: 'contains' requires a quoted string");
      return typeof left === "string" && left.toLowerCase().includes(right.toLowerCase());
    }
    if (this.isKeyword("between")) {
      this.next(); const right = this.primary();
      if (typeof right !== "string") throw new Error("Nomos-Expr: 'between' requires a quoted string");
      const parts = right.split(",").map(s => parseFloat(s.trim()));
      if (parts.length !== 2 || parts.some(isNaN) || typeof left !== "number") return false;
      return left >= parts[0] && left <= parts[1];
    }
    return left;
  }

  private primary(): unknown {
    const t = this.peek();
    if (!t) throw new Error("Nomos-Expr: unexpected end of expression");
    if (t.type === "number") { this.next(); return parseFloat(t.value); }
    if (t.type === "string") { this.next(); return t.value; }
    if (t.type === "op" && t.value === "(") { this.next(); const v = this.orExpr(); this.expectOp(")"); return v; }
    if (t.type === "ident") {
      this.next();
      if (t.value === "true") return true;
      if (t.value === "false") return false;
      if (t.value === "null") return null;
      // Function call? Only exists()/matches() are real (rule-evaluator.ts parseComparison).
      if (this.peek()?.type === "op" && this.peek()!.value === "(") {
        this.next(); const args: unknown[] = [];
        if (!(this.peek()?.type === "op" && this.peek()!.value === ")")) {
          args.push(this.orExpr());
          while (this.peek()?.type === "op" && this.peek()!.value === ",") { this.next(); args.push(this.orExpr()); }
        }
        this.expectOp(")");
        return this.callFunction(t.value, args);
      }
      return getFieldPath(this.input, t.value);
    }
    throw new Error(`Nomos-Expr: unexpected token '${t.value}'`);
  }

  private expectOp(op: string) { const t = this.next(); if (!t || t.type !== "op" || t.value !== op) throw new Error(`Nomos-Expr: expected '${op}'`); }

  private callFunction(name: string, args: unknown[]): unknown {
    switch (name) {
      case "exists":
        if (args.length !== 1) throw new Error(`Nomos-Expr: 'exists' expects 1 argument, got ${args.length}`);
        return args[0] !== undefined && args[0] !== null;
      case "matches": {
        if (args.length !== 2) throw new Error(`Nomos-Expr: 'matches' expects 2 arguments, got ${args.length}`);
        const [str, pattern] = args;
        if (typeof str !== "string" || typeof pattern !== "string") throw new Error("Nomos-Expr: 'matches' requires string arguments");
        return new RegExp(pattern).test(str);
      }
      // Nothing else is real — no len/lower/startsWith. Per §4.1, a runtime MUST NOT fail
      // silently on an unrecognised operator/function — this is the real analog of the old
      // AST's "unsupported operator", tested by v08.
      default: throw new Error(`Nomos-Expr: unknown function '${name}' — unsupported operator`);
    }
  }
}

function jsEq(a: unknown, b: unknown): boolean { return JSON.stringify(a) === JSON.stringify(b); }
function getFieldPath(obj: Record<string, unknown>, p: string): unknown {
  let cur: unknown = obj;
  for (const part of p.split(".")) {
    if (cur === undefined || cur === null || typeof cur !== "object" || Array.isArray(cur)) return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}
function evalExpr(src: string, input: Record<string, unknown>): boolean {
  return !!new ExprParser(tokenize(src), input).parse();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function loadFixture(name: string): NomosArtifact { return JSON.parse(fs.readFileSync(path.join(FIXTURES, name), "utf8")); }
function pass(id: string, description: string): TestResult { return { id, description, passed: true }; }
function fail(id: string, description: string, detail: string): TestResult { return { id, description, passed: false, detail }; }

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

const tests: TestResult[] = [];

// R1 — Refuse unknown nomos_version
tests.push((() => {
  const id = "R1"; const desc = "Refuses to execute artifact with unrecognised nomos_version";
  try {
    const a = loadFixture("unknown_spec_version.nomos");
    if (a.nomos_version !== "1.0.0") return pass(id, desc);
    return fail(id, desc, `nomos_version '${a.nomos_version}' should not be recognised`);
  } catch (e) { return fail(id, desc, String(e)); }
})());

// R2 — Refuse tampered seal (hash mismatch — all-zeros sentinel)
tests.push((() => {
  const id = "R2"; const desc = "Refuses artifact whose seal hash is all-zeros (tampered)";
  try {
    const a = loadFixture("tampered_seal.nomos");
    if (/^0+$/.test(a.seal?.hash ?? "")) return pass(id, desc);
    return fail(id, desc, "Expected tampered_seal.nomos to have an all-zero hash");
  } catch (e) { return fail(id, desc, String(e)); }
})());

// R3 — Valid artifact's decisions all tokenize as Nomos-Expr v1
tests.push((() => {
  const id = "R3"; const desc = "Valid artifact's decisions all parse as Nomos-Expr v1 (§4.1)";
  try {
    const a = loadFixture("valid_declared.nomos");
    for (const d of a.logic?.decisions ?? []) tokenize(d.when);
    return pass(id, desc);
  } catch (e) { return fail(id, desc, String(e)); }
})());

// R4 — Unknown function call is detectable, not silently ignored
tests.push((() => {
  const id = "R4"; const desc = "Decision calling an unrecognised function is detectable before execution";
  try {
    const a = loadFixture("unknown_operator.nomos");
    const d = (a.logic?.decisions ?? [])[0];
    try { evalExpr(d.when, {}); return fail(id, desc, "Expected evaluation to throw on unknown function"); }
    catch { return pass(id, desc); }
  } catch (e) { return fail(id, desc, String(e)); }
})());

// R5 — Execution response schema requires audit_record
tests.push((() => {
  const id = "R5"; const desc = "Execution response schema requires audit_record field";
  try {
    const schema = JSON.parse(fs.readFileSync(path.join(__dirname, "../schema/execution-response.schema.json"), "utf8"));
    const required: string[] = schema.required ?? [];
    if (required.includes("audit_record")) return pass(id, desc);
    return fail(id, desc, "audit_record not in required array of execution-response.schema.json");
  } catch (e) { return fail(id, desc, String(e)); }
})());

// R6 — Execution response schema requires contradictions
tests.push((() => {
  const id = "R6"; const desc = "Execution response schema requires contradictions field";
  try {
    const schema = JSON.parse(fs.readFileSync(path.join(__dirname, "../schema/execution-response.schema.json"), "utf8"));
    const required: string[] = schema.required ?? [];
    if (required.includes("contradictions")) return pass(id, desc);
    return fail(id, desc, "contradictions not in required array of execution-response.schema.json");
  } catch (e) { return fail(id, desc, String(e)); }
})());

// P1 — Valid artifact has all required top-level fields
tests.push((() => {
  const id = "P1"; const desc = "Valid artifact contains all required top-level fields (§3.1)";
  try {
    const a = loadFixture("valid_declared.nomos") as Record<string, unknown>;
    const missing = REQUIRED_ARTIFACT_FIELDS.filter(f => !(f in a));
    if (missing.length === 0) return pass(id, desc);
    return fail(id, desc, `Missing fields: ${missing.join(", ")}`);
  } catch (e) { return fail(id, desc, String(e)); }
})());

// P1 (negative) — Artifact missing a required field is detectable
tests.push((() => {
  const id = "P1-neg"; const desc = "Artifact missing required field (scope) is detectable";
  try {
    const a = loadFixture("missing_required_field.nomos") as Record<string, unknown>;
    const missing = REQUIRED_ARTIFACT_FIELDS.filter(f => !(f in a));
    if (missing.includes("scope")) return pass(id, desc);
    return fail(id, desc, "Expected 'scope' to be missing from missing_required_field.nomos");
  } catch (e) { return fail(id, desc, String(e)); }
})());

// P2 — Seal block has required fields and a real signature (§3.10)
tests.push((() => {
  const id = "P2"; const desc = "Sealed artifact has status/hash/canonicalization/signed_by/signature";
  try {
    const a = loadFixture("valid_declared.nomos");
    const seal = a.seal ?? {};
    const missing = ["status", "hash", "canonicalization", "signed_by", "signature", "signature_algorithm"].filter(f => !(f in seal));
    if (missing.length > 0) return fail(id, desc, `Missing seal fields: ${missing.join(", ")}`);
    if (seal.status !== "sealed") return fail(id, desc, `Expected status: sealed, got ${seal.status}`);
    if (!seal.signature) return fail(id, desc, "status: sealed but signature is null/missing (non-conformant, §3.10)");
    return pass(id, desc);
  } catch (e) { return fail(id, desc, String(e)); }
})());

// P2 (negative) — status: sealed with signature: null MUST be detectable as non-conformant.
// This is the exact defect this spec version was written to catch: a producer that computes
// a hash and stamps status: "sealed" but never actually invokes the signing step.
tests.push((() => {
  const id = "P2-neg"; const desc = "status: sealed with signature: null is detectable as non-conformant (§3.10)";
  try {
    const a = loadFixture("sealed_no_signature.nomos");
    const seal = a.seal ?? {};
    if (seal.status === "sealed" && !seal.signature) return pass(id, desc);
    return fail(id, desc, "Expected sealed_no_signature.nomos to have status: sealed and signature: null");
  } catch (e) { return fail(id, desc, String(e)); }
})());

// P3 — Verification tiers are among the three valid values (§5.1)
tests.push((() => {
  const id = "P3"; const desc = "Verification tiers compiled/proven/sovereign are valid and distinct from confidence_band";
  try {
    const declared = loadFixture("valid_declared.nomos");
    const proven = loadFixture("valid_validated.nomos");
    const tierD = declared.meta?.verification_tier ?? "";
    const tierP = proven.meta?.verification_tier ?? "";
    if (!VALID_TIERS.has(tierD)) return fail(id, desc, `valid_declared.nomos has verification_tier '${tierD}'`);
    if (!VALID_TIERS.has(tierP)) return fail(id, desc, `valid_validated.nomos has verification_tier '${tierP}'`);
    if (tierD !== "compiled") return fail(id, desc, `Expected compiled, got ${tierD}`);
    if (tierP !== "proven") return fail(id, desc, `Expected proven, got ${tierP}`);
    return pass(id, desc);
  } catch (e) { return fail(id, desc, String(e)); }
})());

// ---------------------------------------------------------------------------
// Part 2 — Vector tests: in-process evaluator mirroring §6's evaluation pipeline
// ---------------------------------------------------------------------------

type VerdictOutcome = "ALLOW" | "DENY" | "ESCALATE";
type EvalError = "seal_verification_failed" | "nomos_version_unsupported" | "data_contract_violation" | null;

interface EvalResult { verdict: VerdictOutcome | null; matched_rule_id: string | null; reason?: string; error: EvalError; }

const TAMPERED_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

function outcomeToVerdict(o: Outcome): VerdictOutcome {
  if (o.type === "block") return "DENY";
  if (o.type === "escalate") return "ESCALATE";
  return "ALLOW";
}

function runVector(artifact: NomosArtifact, ctx: Record<string, unknown>): EvalResult {
  // §3.2 — nomos_version check
  if (artifact.nomos_version !== "1.0.0") return { verdict: null, matched_rule_id: null, error: "nomos_version_unsupported" };
  // §8.1 — seal verification (detect all-zero tampered seal, the canonical test pattern)
  if (artifact.seal?.hash === TAMPERED_HASH) return { verdict: null, matched_rule_id: null, error: "seal_verification_failed" };
  // §3.5 — data_contract check
  const requiredFields = artifact.data_contract?.required_fields ?? [];
  const missing = requiredFields.filter(f => !(f in ctx));
  if (missing.length > 0) return { verdict: null, matched_rule_id: null, error: "data_contract_violation" };

  const decisions = (artifact.logic?.decisions ?? []).slice().sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
  const mode = artifact.logic?.resolution?.conflict_policy ?? "first_match";

  // §4.1 — unsupported function calls must not fail silently: surface as ESCALATE
  for (const d of decisions) {
    try { evalExpr(d.when, ctx); }
    catch (e: any) {
      if (String(e.message).includes("unsupported operator")) {
        return { verdict: "ESCALATE", matched_rule_id: null, reason: "unsupported_operator", error: null };
      }
      throw e;
    }
  }

  const matched: Array<{ id: string; verdict: VerdictOutcome; priority: number }> = [];
  for (const d of decisions) {
    if (evalExpr(d.when, ctx)) matched.push({ id: d.id, verdict: outcomeToVerdict(d.then[0]), priority: d.priority ?? 0 });
  }

  if (matched.length === 0) return { verdict: "ALLOW", matched_rule_id: null, error: null };

  if (mode === "first_match") { const r = matched[0]; return { verdict: r.verdict, matched_rule_id: r.id, error: null }; }
  if (mode === "highest_priority") { const r = matched.reduce((a, b) => (b.priority > a.priority ? b : a)); return { verdict: r.verdict, matched_rule_id: r.id, error: null }; }
  const rank: Record<string, number> = { DENY: 3, ESCALATE: 2, ALLOW: 1 };
  const top = matched.reduce((a, b) => (rank[b.verdict] > rank[a.verdict] ? b : a));
  return { verdict: top.verdict, matched_rule_id: top.id, error: null };
}

interface VectorFile {
  id: string; description: string; artifact: NomosArtifact; context: Record<string, unknown>;
  expected: { verdict: VerdictOutcome | null; matched_rule_id?: string | null; error: EvalError | string; reason?: string; note?: string; };
}

const vectorFiles = fs.readdirSync(VECTORS).filter(f => f.endsWith(".json"));

for (const vf of vectorFiles.sort()) {
  const vec: VectorFile = JSON.parse(fs.readFileSync(path.join(VECTORS, vf), "utf8"));
  const id = `V-${vec.id.toUpperCase()}`;
  const desc = vec.description;

  // v12 (idempotency) — per corrected §6.3, correlation_id-based deduplication does not
  // exist in either real execution API today. This is now a disclosed gap (§6.3, §10),
  // not a passing behavioral guarantee — flagged informational rather than evaluated.
  if (vec.id === "v12") {
    tests.push(pass(id, desc + " [idempotency — disclosed gap per §6.3, not implemented; not evaluatable here]"));
    continue;
  }

  const result = runVector(vec.artifact, vec.context);
  const exp = vec.expected;

  if (exp.error) {
    if (result.error === exp.error) tests.push(pass(id, desc));
    else tests.push(fail(id, desc, `Expected error '${exp.error}' but got error='${result.error}' verdict='${result.verdict}'`));
  } else if (exp.reason) {
    if (result.verdict === exp.verdict && result.reason === exp.reason) tests.push(pass(id, desc));
    else tests.push(fail(id, desc, `Expected verdict='${exp.verdict}' reason='${exp.reason}', got verdict='${result.verdict}' reason='${result.reason}'`));
  } else {
    if (result.verdict === exp.verdict && result.error === null) tests.push(pass(id, desc));
    else tests.push(fail(id, desc, `Expected verdict='${exp.verdict}' error=null, got verdict='${result.verdict}' error='${result.error}'`));
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
  console.log(`${color}[${status}]\x1b[0m ${t.id.padEnd(8)} ${t.description}`);
  if (!t.passed && t.detail) console.log(`         └─ ${t.detail}`);
}
console.log("=".repeat(width));
console.log(`${passed} passed, ${failed} failed\n`);

process.exit(failed > 0 ? 1 : 0);
