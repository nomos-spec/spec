#!/usr/bin/env node
/**
 * NOMOS CLI — validate, verify, exec, diff, lint
 *
 * Usage:
 *   npx tsx cli/nomos.ts <command> [options]
 *
 * Commands:
 *   validate <file>              Check artifact structure and required fields
 *   verify   <file>              Verify cryptographic seal
 *   exec     <file>              Execute artifact against an input payload
 *   diff     <file1> <file2>     Compare two artifact versions
 *   lint     <file>              Check for common authoring issues
 *
 * No external dependencies — Node.js built-ins only.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

// ─── Types ────────────────────────────────────────────────────────────────────

type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

interface Outcome {
  type: "allow" | "block" | "escalate" | "set" | "emit" | "action";
  [k: string]: JsonValue | undefined;
}

interface Decision {
  id: string;
  description?: string;
  when: string;
  then: Outcome[];
  else?: Outcome[];
  priority?: number;
  provenance?: Record<string, JsonValue>;
}

interface Seal {
  status?: "draft" | "sealed";
  hash?: string | null;
  canonicalization?: string;
  signed_by?: { name: string; org_id: string; role: string; timestamp: string } | null;
  signature?: string | null;
  signature_algorithm?: string;
  kid?: string;
  algorithm?: string; // legacy field name for HMAC
  sig?: string;       // legacy field name for HMAC signature
}

interface NomosArtifact {
  nomos_version?: string;
  meta?: {
    artifact_id?: string;
    name?: string;
    version?: string;
    verification_tier?: "compiled" | "proven" | "sovereign";
    [k: string]: JsonValue | undefined;
  };
  scope?: Record<string, JsonValue>;
  data_contract?: { required_fields?: string[]; [k: string]: JsonValue | undefined };
  logic?: {
    decisions?: Decision[];
    resolution?: { conflict_policy?: string; tie_breaker?: string };
    [k: string]: JsonValue | undefined;
  };
  governance?: Record<string, JsonValue>;
  execution?: Record<string, JsonValue>;
  audit?: Record<string, JsonValue>;
  agents?: Record<string, JsonValue>;
  provenance?: { review_summary?: { pending_at_seal?: number; [k: string]: JsonValue | undefined }; [k: string]: JsonValue | undefined };
  seal?: Seal;
  [key: string]: JsonValue | undefined;
}

// ─── Colours ─────────────────────────────────────────────────────────────────

const C = {
  green:  (s: string) => `\x1b[32m${s}\x1b[0m`,
  red:    (s: string) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  cyan:   (s: string) => `\x1b[36m${s}\x1b[0m`,
  bold:   (s: string) => `\x1b[1m${s}\x1b[0m`,
  dim:    (s: string) => `\x1b[2m${s}\x1b[0m`,
};

// ─── JCS Canonicalization (RFC 8785) ─────────────────────────────────────────

function jcsValue(v: JsonValue): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return String(v);
  if (typeof v === "number") {
    if (!isFinite(v)) throw new Error("NaN/Infinity not valid in JCS");
    return String(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcsValue).join(",") + "]";
  const pairs = Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${jcsValue(v[k])}`);
  return "{" + pairs.join(",") + "}";
}

function jcsCanonicalize(obj: Record<string, JsonValue>): Buffer {
  return Buffer.from(jcsValue(obj), "utf8");
}

// ─── Nomos-Expr v1 — tokenizer + recursive-descent evaluator (spec §4.1) ─────
// This mirrors server/lib/rule-evaluator.ts's real tokenizeWhenString/parseWhenTokens —
// not an idealized design. In particular: no arithmetic; in/contains/between take a single
// quoted string (not an array literal); only exists()/matches() are real functions; numbers
// may use scientific notation. Grammar (lowest to highest precedence):
//   expr        := orExpr
//   orExpr      := andExpr ( 'or' andExpr )*
//   andExpr     := notExpr ( 'and' notExpr )*
//   notExpr     := 'not' notExpr | comparison
//   comparison  := primary ( ('==' | '!=' | '>=' | '<=' | '>' | '<') primary
//                          | 'in' STRING | 'contains' STRING | 'between' STRING )?
//   primary     := NUMBER | STRING | 'true' | 'false' | 'null' | IDENT('(' args ')')? | '(' expr ')'

type Token = { type: string; value: string };

function tokenize(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const twoChar = ["==", "!=", ">=", "<="];
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '"' || c === "'") {
      const quote = c;
      let j = i + 1;
      let s = "";
      while (j < src.length && src[j] !== quote) {
        if (src[j] === "\\" && j + 1 < src.length) { s += src[j + 1]; j += 2; continue; }
        s += src[j]; j++;
      }
      tokens.push({ type: "string", value: s });
      i = j + 1;
      continue;
    }
    if (/[0-9]/.test(c) || (c === "-" && /[0-9]/.test(src[i + 1] ?? ""))) {
      let j = i; let s = "";
      if (src[j] === "-") { s += "-"; j++; }
      while (j < src.length && /[0-9.]/.test(src[j])) { s += src[j]; j++; }
      // Scientific notation, e.g. 1e+25 / 2.5E-10 — real production data uses this for
      // large numeric thresholds (FLOPs counts). Mirrors rule-evaluator.ts exactly.
      if (j < src.length && (src[j] === "e" || src[j] === "E")) {
        let k = j + 1; let exp = src[j];
        if (k < src.length && (src[k] === "+" || src[k] === "-")) { exp += src[k]; k++; }
        if (k < src.length && /[0-9]/.test(src[k])) {
          while (k < src.length && /[0-9]/.test(src[k])) { exp += src[k]; k++; }
          s += exp; j = k;
        }
      }
      tokens.push({ type: "number", value: s });
      i = j;
      continue;
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
  constructor(private tokens: Token[], private input: Record<string, JsonValue>) {}

  private peek(): Token | undefined { return this.tokens[this.pos]; }
  private next(): Token { return this.tokens[this.pos++]; }
  private isKeyword(word: string): boolean {
    const t = this.peek();
    return !!t && t.type === "ident" && t.value === word;
  }

  parse(): JsonValue { const v = this.orExpr(); if (this.pos < this.tokens.length) throw new Error(`Nomos-Expr: unexpected trailing token '${this.peek()!.value}'`); return v; }

  private orExpr(): JsonValue {
    let left = this.andExpr();
    while (this.isKeyword("or")) { this.next(); const right = this.andExpr(); left = !!left || !!right; }
    return left;
  }

  private andExpr(): JsonValue {
    let left = this.notExpr();
    while (this.isKeyword("and")) { this.next(); const right = this.notExpr(); left = !!left && !!right; }
    return left;
  }

  private notExpr(): JsonValue {
    if (this.isKeyword("not")) { this.next(); return !this.notExpr(); }
    return this.comparison();
  }

  private comparison(): JsonValue {
    const left = this.primary();
    const t = this.peek();
    if (t && t.type === "op" && ["==", "!=", ">", ">=", "<", "<="].includes(t.value)) {
      this.next();
      const right = this.primary();
      switch (t.value) {
        case "==": return jsEq(left, right);
        case "!=": return !jsEq(left, right);
        case ">":  return typeof left === "number" && typeof right === "number" && left > right;
        case ">=": return typeof left === "number" && typeof right === "number" && left >= right;
        case "<":  return typeof left === "number" && typeof right === "number" && left < right;
        case "<=": return typeof left === "number" && typeof right === "number" && left <= right;
      }
    }
    // in / contains / between all take a single comma-joined STRING on the right —
    // never an array literal ([...] is not valid syntax in this language).
    if (this.isKeyword("in")) {
      this.next();
      const right = this.primary();
      if (typeof right !== "string") throw new Error("Nomos-Expr: 'in' requires a quoted string, e.g. field in \"a,b,c\"");
      const list = right.split(",").map(s => s.trim());
      return list.map(String).includes(String(left));
    }
    if (this.isKeyword("contains")) {
      this.next();
      const right = this.primary();
      if (typeof right !== "string") throw new Error("Nomos-Expr: 'contains' requires a quoted string");
      return typeof left === "string" && left.toLowerCase().includes(right.toLowerCase());
    }
    if (this.isKeyword("between")) {
      this.next();
      const right = this.primary();
      if (typeof right !== "string") throw new Error("Nomos-Expr: 'between' requires a quoted string, e.g. field between \"2,8\"");
      const parts = right.split(",").map(s => parseFloat(s.trim()));
      if (parts.length !== 2 || parts.some(isNaN) || typeof left !== "number") return false;
      return left >= parts[0] && left <= parts[1];
    }
    return left;
  }

  private primary(): JsonValue {
    const t = this.peek();
    if (!t) throw new Error("Nomos-Expr: unexpected end of expression");

    if (t.type === "number") { this.next(); return parseFloat(t.value); }
    if (t.type === "string") { this.next(); return t.value; }
    if (t.type === "op" && t.value === "(") {
      this.next();
      const v = this.orExpr();
      this.expectOp(")");
      return v;
    }
    if (t.type === "ident") {
      this.next();
      if (t.value === "true") return true;
      if (t.value === "false") return false;
      if (t.value === "null") return null;
      // Function call? Only exists()/matches() are real (rule-evaluator.ts parseComparison).
      if (this.peek()?.type === "op" && this.peek()!.value === "(") {
        this.next();
        const args: JsonValue[] = [];
        if (!(this.peek()?.type === "op" && this.peek()!.value === ")")) {
          args.push(this.orExpr());
          while (this.peek()?.type === "op" && this.peek()!.value === ",") { this.next(); args.push(this.orExpr()); }
        }
        this.expectOp(")");
        return this.callFunction(t.value, args);
      }
      // Field reference — dot path into `input`
      return getFieldPath(this.input, t.value) as JsonValue;
    }
    throw new Error(`Nomos-Expr: unexpected token '${t.value}'`);
  }

  private expectOp(op: string): void {
    const t = this.next();
    if (!t || t.type !== "op" || t.value !== op) throw new Error(`Nomos-Expr: expected '${op}'`);
  }

  private callFunction(name: string, args: JsonValue[]): JsonValue {
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
      // Nothing else is real — no len/lower/startsWith. A rule calling one fails to parse,
      // exactly as it would against the real evaluator (fail closed, don't guess).
      default: throw new Error(`Nomos-Expr: unknown function '${name}' — unsupported operator`);
    }
  }
}

function jsEq(a: JsonValue, b: JsonValue): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function getFieldPath(obj: Record<string, JsonValue>, path: string): JsonValue | undefined {
  const parts = path.split(".");
  let cur: JsonValue | undefined = obj;
  for (const p of parts) {
    if (cur === undefined || cur === null || typeof cur !== "object" || Array.isArray(cur)) return undefined;
    cur = (cur as Record<string, JsonValue>)[p];
  }
  return cur;
}

function evalExpr(src: string, input: Record<string, JsonValue>): boolean {
  const tokens = tokenize(src);
  const parser = new ExprParser(tokens, input);
  return !!parser.parse();
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function loadArtifact(filePath: string): NomosArtifact {
  const abs = path.resolve(filePath);
  if (!fs.existsSync(abs)) {
    console.error(C.red(`File not found: ${abs}`));
    process.exit(1);
  }
  try {
    return JSON.parse(fs.readFileSync(abs, "utf8")) as NomosArtifact;
  } catch {
    console.error(C.red(`Failed to parse JSON: ${abs}`));
    process.exit(1);
  }
}

function ok(msg: string)   { console.log(`  ${C.green("✓")} ${msg}`); }
function warn(msg: string) { console.log(`  ${C.yellow("⚠")} ${msg}`); }
function fail(msg: string) { console.log(`  ${C.red("✗")} ${msg}`); }
function info(msg: string) { console.log(`  ${C.dim("·")} ${msg}`); }

// ─── VALIDATE ────────────────────────────────────────────────────────────────

function cmdValidate(filePath: string): void {
  const artifact = loadArtifact(filePath);
  console.log(`\n${C.bold("Validate")} ${C.cyan(filePath)}\n`);

  let errors = 0;

  const required = ["nomos_version", "meta", "scope", "data_contract", "logic", "governance", "execution", "audit", "seal"];
  for (const field of required) {
    if (artifact[field] === undefined || artifact[field] === null) {
      fail(`Missing required top-level field: ${field}`); errors++;
    } else {
      ok(`${field}: present`);
    }
  }

  if (artifact.meta && !artifact.meta.artifact_id) { fail("meta.artifact_id is missing"); errors++; }
  if (artifact.meta && !artifact.meta.version) { fail("meta.version is missing"); errors++; }

  const decisions = artifact.logic?.decisions;
  if (decisions !== undefined) {
    if (!Array.isArray(decisions)) {
      fail("`logic.decisions` must be an array"); errors++;
    } else {
      ok(`logic.decisions: ${decisions.length} decision(s)`);
      const ids = new Set<string>();
      for (const d of decisions) {
        if (!d.id) { fail(`Decision missing id: ${JSON.stringify(d).slice(0, 60)}`); errors++; }
        else if (ids.has(d.id)) { fail(`Duplicate decision id: ${d.id}`); errors++; }
        else ids.add(d.id);
        if (typeof d.when !== "string") { fail(`Decision ${d.id} 'when' must be a Nomos-Expr v1 string, not a condition-tree object (see §4.5 — that format is deprecated)`); errors++; }
        else {
          try { tokenize(d.when); } catch (e: any) { fail(`Decision ${d.id} 'when' failed to tokenize: ${e.message}`); errors++; }
        }
        if (!Array.isArray(d.then) || d.then.length === 0) { fail(`Decision ${d.id} has no 'then' outcomes`); errors++; }
      }
    }
  }

  if (artifact.nomos_version && artifact.nomos_version !== "1.0.0") {
    warn(`Unrecognised nomos_version: ${artifact.nomos_version}`);
  }

  console.log();
  if (errors === 0) {
    console.log(C.green(`Result: VALID`) + ` — ${artifact.meta?.artifact_id}@${artifact.meta?.version}\n`);
  } else {
    console.log(C.red(`Result: INVALID`) + ` — ${errors} error(s)\n`);
    process.exit(1);
  }
}

// ─── VERIFY ───────────────────────────────────────────────────────────────────
// Two independent checks: integrity (recompute the JCS/SHA-256 hash, excluding `seal` and
// `attestations` — §8.2) and authenticity (Ed25519 against a public key, or legacy HMAC
// against a shared secret — §8.3). Mirrors verify.ts/verify.py; kept in sync deliberately.

function getSealKey(args: string[]): Buffer | null {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--key" && args[i + 1]) return Buffer.from(args[i + 1].trim(), "hex");
    if (args[i] === "--key-env" && args[i + 1]) {
      const val = process.env[args[i + 1]];
      return val ? Buffer.from(val.trim(), "hex") : null;
    }
  }
  const env = process.env["NOMOS_SEAL_KEY"];
  return env ? Buffer.from(env.trim(), "hex") : null;
}

function getArg(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i !== -1 ? args[i + 1] : undefined;
}

function cmdVerify(filePath: string, args: string[]): void {
  const artifact = loadArtifact(filePath);
  console.log(`\n${C.bold("Verify")} ${C.cyan(filePath)}\n`);
  info(`artifact_id       : ${artifact.meta?.artifact_id}`);
  info(`version           : ${artifact.meta?.version}`);
  info(`verification_tier : ${artifact.meta?.verification_tier ?? "N/A"}`);
  console.log();

  const seal = artifact.seal;
  if (!seal || seal.status !== "sealed") { fail("Artifact is not sealed"); process.exit(1); }

  const alg = seal.signature_algorithm ?? seal.algorithm ?? "";

  // 1. Integrity — excludes `seal` and `attestations` (added post-seal by third parties, §8.2)
  const payload = Object.fromEntries(
    Object.entries(artifact).filter(([k]) => k !== "seal" && k !== "attestations")
  ) as Record<string, JsonValue>;
  const computedHash = crypto.createHash("sha256").update(jcsCanonicalize(payload)).digest("hex");
  const storedHash = seal.hash ?? "";
  if (computedHash !== storedHash) {
    fail(`Hash mismatch — artifact modified after sealing`);
    info(`  stored  : ${storedHash}`);
    info(`  computed: ${computedHash}`);
    process.exit(1);
  }
  ok(`Payload hash matches: ${computedHash.slice(0, 16)}…`);

  // 2. Authenticity
  if (alg === "Ed25519" || alg === "RS256" || alg === "ES256") {
    if (!seal.signature) { fail("status: sealed but signature is null — this artifact computed a hash but never invoked the signing step (non-conformant, §3.10)"); process.exit(1); }
    const pubkeyPath = getArg(args, "--pubkey");
    if (!pubkeyPath) { warn(`No --pubkey provided — cannot verify ${alg} signature offline. Fetch the key from /.well-known/nomos-signing-keys.`); }
    else {
      const pem = fs.readFileSync(path.resolve(pubkeyPath), "utf8");
      const signed = jcsCanonicalize({ hash: seal.hash ?? null, signed_by: (seal.signed_by as unknown as JsonValue) ?? null });
      const hashAlgo = alg === "Ed25519" ? null : "sha256";
      const valid = crypto.verify(hashAlgo, signed, crypto.createPublicKey(pem), Buffer.from(seal.signature, "base64"));
      if (!valid) { fail("Signature does not verify — forged, wrong key, or the seal was altered."); process.exit(1); }
      ok(`${alg} signature verified against the published PUBLIC key.`);
    }
  } else if (alg === "HMAC-SHA256") {
    const sealKey = getSealKey(args);
    const storedSig = seal.sig ?? seal.signature ?? "";
    if (!sealKey) {
      warn("No seal key — signature not verified (pass --key or --key-env NOMOS_SEAL_KEY)");
    } else if (!storedSig) {
      fail("status: sealed but signature is null — this artifact computed a hash but never invoked the signing step (non-conformant, §3.10)"); process.exit(1);
    } else {
      const computedSig = crypto.createHmac("sha256", sealKey).update(computedHash, "ascii").digest("hex");
      if (!crypto.timingSafeEqual(Buffer.from(computedSig, "hex"), Buffer.from(storedSig, "hex"))) {
        fail("HMAC signature mismatch"); process.exit(1);
      }
      ok("HMAC signature verified");
    }
  } else {
    fail(`Unsupported or missing seal algorithm: ${JSON.stringify(alg)}`); process.exit(1);
  }

  const pending = artifact.provenance?.review_summary?.pending_at_seal ?? 0;
  if (pending > 0) warn(`${pending} unresolved conflict(s) at seal time`);
  else ok("No unresolved conflicts recorded at seal time");

  console.log();
  console.log(C.green("Result: VALID\n"));
}

// ─── EXEC ─────────────────────────────────────────────────────────────────────

function cmdExec(filePath: string, args: string[]): void {
  const artifact = loadArtifact(filePath);

  const inputIdx = args.indexOf("--input");
  const inputFileIdx = args.indexOf("--input-file");

  let input: Record<string, JsonValue> = {};
  if (inputIdx !== -1 && args[inputIdx + 1]) {
    try { input = JSON.parse(args[inputIdx + 1]); } catch { console.error(C.red("Invalid JSON in --input")); process.exit(1); }
  } else if (inputFileIdx !== -1 && args[inputFileIdx + 1]) {
    try { input = JSON.parse(fs.readFileSync(path.resolve(args[inputFileIdx + 1]), "utf8")); }
    catch { console.error(C.red("Could not read --input-file")); process.exit(1); }
  } else {
    console.error(C.red("Usage: exec <file> --input '{...}' | --input-file <path>"));
    process.exit(1);
  }

  console.log(`\n${C.bold("Exec")} ${C.cyan(filePath)}\n`);
  info(`artifact: ${artifact.meta?.artifact_id}@${artifact.meta?.version}`);
  info(`input: ${JSON.stringify(input)}`);
  console.log();

  const decisions = (artifact.logic?.decisions ?? []).slice().sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
  const resolution = artifact.logic?.resolution?.conflict_policy ?? "collect_and_resolve";
  const matched: { decision: Decision; outcomes: Outcome[] }[] = [];

  for (const d of decisions) {
    let result: boolean;
    try { result = evalExpr(d.when, input); }
    catch (e: any) { fail(`decision ${d.id}: ${e.message}`); continue; }
    const outcomes = result ? d.then : (d.else ?? []);
    if (result || (d.else && d.else.length > 0)) matched.push({ decision: d, outcomes });
    info(`decision ${d.id} (priority ${d.priority ?? 0}): ${result ? C.green("when matched") : C.dim("when false")}`);
    if (resolution === "first_match" && result) break;
  }

  console.log();

  const firing = matched.filter(m => m.outcomes.length > 0);
  if (firing.length === 0) {
    console.log(C.yellow("Verdict: NO_OUTCOME") + " — no decision produced an outcome for this input\n");
    return;
  }

  console.log(C.bold("Outcomes:"));
  for (const { decision, outcomes } of firing) {
    for (const o of outcomes) {
      console.log(`  ${C.cyan(o.type.padEnd(10))} ${decision.id}  ${C.dim(decision.description ?? "")}`);
    }
  }
  console.log();
}

// ─── DIFF ─────────────────────────────────────────────────────────────────────

function cmdDiff(filePath1: string, filePath2: string): void {
  const a = loadArtifact(filePath1);
  const b = loadArtifact(filePath2);
  console.log(`\n${C.bold("Diff")}\n`);
  info(`${C.dim("from")} ${a.meta?.artifact_id}@${a.meta?.version}`);
  info(`${C.dim("to  ")} ${b.meta?.artifact_id}@${b.meta?.version}`);
  console.log();

  // Header fields
  let headerChanges = 0;
  if (JSON.stringify(a.meta?.verification_tier) !== JSON.stringify(b.meta?.verification_tier)) {
    console.log(`  ${C.yellow("~")} meta.verification_tier: ${C.red(String(a.meta?.verification_tier))} → ${C.green(String(b.meta?.verification_tier))}`);
    headerChanges++;
  }
  if (JSON.stringify(a.logic?.resolution) !== JSON.stringify(b.logic?.resolution)) {
    console.log(`  ${C.yellow("~")} logic.resolution: ${C.red(JSON.stringify(a.logic?.resolution))} → ${C.green(JSON.stringify(b.logic?.resolution))}`);
    headerChanges++;
  }
  if (headerChanges === 0) ok("Header fields unchanged");
  console.log();

  // Decisions
  const decisionsA = new Map((a.logic?.decisions ?? []).map(d => [d.id, d]));
  const decisionsB = new Map((b.logic?.decisions ?? []).map(d => [d.id, d]));
  let changes = 0;

  for (const [id, d] of decisionsB) {
    if (!decisionsA.has(id)) {
      console.log(`  ${C.green("+")} decision ${id}: ${C.dim(d.description?.slice(0, 60) ?? "")}`);
      changes++;
    }
  }
  for (const [id, d] of decisionsA) {
    if (!decisionsB.has(id)) {
      console.log(`  ${C.red("-")} decision ${id}: ${C.dim(d.description?.slice(0, 60) ?? "")}`);
      changes++;
    }
  }
  for (const [id, dA] of decisionsA) {
    const dB = decisionsB.get(id);
    if (!dB) continue;
    const whenChanged = dA.when !== dB.when;
    const thenChanged = JSON.stringify(dA.then) !== JSON.stringify(dB.then);
    const priorityChanged = dA.priority !== dB.priority;
    if (whenChanged || thenChanged || priorityChanged) {
      console.log(`  ${C.yellow("~")} decision ${id}:`);
      if (whenChanged)     console.log(`      when:     ${C.red(dA.when)} → ${C.green(dB.when)}`);
      if (thenChanged)     console.log(`      then changed`);
      if (priorityChanged) console.log(`      priority: ${C.red(String(dA.priority))} → ${C.green(String(dB.priority))}`);
      changes++;
    }
  }
  if (changes === 0) ok("Decisions unchanged");
  console.log();
}

// ─── LINT ─────────────────────────────────────────────────────────────────────

function cmdLint(filePath: string): void {
  const artifact = loadArtifact(filePath);
  console.log(`\n${C.bold("Lint")} ${C.cyan(filePath)}\n`);

  let issues = 0;

  const decisions = artifact.logic?.decisions ?? [];
  if (decisions.length === 0) { warn("No decisions defined"); issues++; }

  const ids = decisions.map(d => d.id);
  const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
  if (dupes.length > 0) { fail(`Duplicate decision IDs: ${dupes.join(", ")}`); issues++; }

  const noProvenance = decisions.filter(d => !d.provenance);
  if (noProvenance.length > 0) { warn(`${noProvenance.length} decision(s) missing provenance: ${noProvenance.map(d => d.id).join(", ")}`); issues++; }

  const noPriority = decisions.filter(d => d.priority === undefined);
  if (noPriority.length > 0) { warn(`${noPriority.length} decision(s) missing priority: ${noPriority.map(d => d.id).join(", ")}`); issues++; }

  for (const d of decisions) {
    try { tokenize(d.when); } catch (e: any) { fail(`decision ${d.id}: 'when' does not tokenize as Nomos-Expr v1 — ${e.message}`); issues++; }
  }

  // Seal
  if (!artifact.seal || artifact.seal.status !== "sealed") { warn("Artifact is not sealed"); issues++; }
  else if (!artifact.seal.signature) { fail("status: sealed but signature is null — non-conformant (§3.10)"); issues++; }
  else ok("Seal present and signed");

  // Verification tier
  const tier = artifact.meta?.verification_tier;
  if (!tier) { warn("meta.verification_tier not set"); issues++; }
  else ok(`Verification tier: ${tier}`);

  // Agents
  if (!artifact.agents || Object.keys(artifact.agents).length === 0) {
    info("No agents manifest — running in permissive mode");
  } else {
    ok(`Agents manifest: ${Object.keys(artifact.agents).length} agent(s) registered`);
  }

  console.log();
  if (issues === 0) {
    console.log(C.green("Result: CLEAN\n"));
  } else {
    console.log(C.yellow(`Result: ${issues} issue(s)\n`));
  }
}

// ─── HELP ─────────────────────────────────────────────────────────────────────

function printHelp(): void {
  console.log(`
${C.bold("nomos")} — NOMOS Protocol CLI

${C.bold("Usage:")}
  nomos validate <file>                    Check structure and required fields
  nomos verify   <file> [--pubkey <pem> | --key <hex> | --key-env <VAR>]
                                            Verify cryptographic seal
  nomos exec     <file> --input '{...}'    Execute artifact against input payload
  nomos exec     <file> --input-file <f>   Execute artifact from input file
  nomos diff     <file1> <file2>           Compare two artifact versions
  nomos lint     <file>                    Check for common authoring issues

${C.bold("Options for verify:")}
  --pubkey <pem>        Path to published Ed25519 public key (asymmetric seals)
  --key <hex>           Legacy HMAC seal key as hex string
  --key-env <VAR>       Read legacy HMAC seal key from environment variable
                        (defaults to NOMOS_SEAL_KEY env var)

${C.bold("Examples:")}
  nomos validate examples/lending_policy_v1.nomos
  nomos verify   examples/lending_policy_v1.nomos --pubkey signing_key.pub.pem
  nomos exec     examples/lending_policy_v1.nomos --input '{"patron_age":25,"account_standing":"good"}'
  nomos diff     examples/lending_policy_v1.nomos examples/lending_policy_v2.nomos
  nomos lint     examples/lending_policy_v1.nomos
`);
}

// ─── Entry ────────────────────────────────────────────────────────────────────

const [,, command, ...rest] = process.argv;

switch (command) {
  case "validate": cmdValidate(rest[0]); break;
  case "verify":   cmdVerify(rest[0], rest.slice(1)); break;
  case "exec":     cmdExec(rest[0], rest.slice(1)); break;
  case "diff":     cmdDiff(rest[0], rest[1]); break;
  case "lint":     cmdLint(rest[0]); break;
  default:         printHelp(); break;
}
