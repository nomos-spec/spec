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

interface ConditionNode {
  op: string;
  field?: string;
  value?: JsonValue;
  left?: ConditionNode;
  right?: ConditionNode;
  conditions?: ConditionNode[];
  pattern?: string;
}

interface Rule {
  id: string;
  text?: string;
  condition: ConditionNode;
  action: string;
  priority?: number;
  confidence?: number;
  metadata?: Record<string, JsonValue>;
}

interface NomosArtifact {
  artifact_id?: string;
  version?: string;
  spec_version?: string;
  confidence?: string;
  conflict_resolution?: string;
  domain?: Record<string, JsonValue>;
  rules?: Rule[];
  agents?: Record<string, JsonValue>;
  contradiction_report?: { contradiction_count?: number; contradictions?: JsonValue[] };
  readiness?: { lis?: number; drs?: number | null; res?: number; gms?: number; ari?: number; autonomy_band?: string };
  seal?: { algorithm: string; ts: string; hash: string; sig: string };
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

  const required = ["artifact_id", "version", "spec_version", "confidence", "rules", "seal"];
  for (const field of required) {
    if (artifact[field] === undefined || artifact[field] === null) {
      fail(`Missing required field: ${field}`); errors++;
    } else {
      ok(`${field}: ${JSON.stringify(artifact[field]).slice(0, 60)}`);
    }
  }

  if (artifact.rules !== undefined) {
    if (!Array.isArray(artifact.rules)) {
      fail("`rules` must be an array"); errors++;
    } else {
      ok(`rules: ${artifact.rules.length} rule(s)`);
      const ids = new Set<string>();
      for (const rule of artifact.rules) {
        if (!rule.id) { fail(`Rule missing id: ${JSON.stringify(rule).slice(0, 60)}`); errors++; }
        else if (ids.has(rule.id)) { fail(`Duplicate rule id: ${rule.id}`); errors++; }
        else ids.add(rule.id);
        if (!rule.condition) { fail(`Rule ${rule.id} has no condition`); errors++; }
        if (!rule.action) { fail(`Rule ${rule.id} has no action`); errors++; }
      }
    }
  }

  if (artifact.spec_version && !["NOMOS-SPEC-001", "NOMOS-SPEC-002"].includes(artifact.spec_version as string)) {
    warn(`Unrecognised spec_version: ${artifact.spec_version}`);
  }

  console.log();
  if (errors === 0) {
    console.log(C.green(`Result: VALID`) + ` — ${artifact.artifact_id}@${artifact.version}\n`);
  } else {
    console.log(C.red(`Result: INVALID`) + ` — ${errors} error(s)\n`);
    process.exit(1);
  }
}

// ─── VERIFY ───────────────────────────────────────────────────────────────────

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

function cmdVerify(filePath: string, args: string[]): void {
  const artifact = loadArtifact(filePath);
  const sealKey = getSealKey(args);
  console.log(`\n${C.bold("Verify")} ${C.cyan(filePath)}\n`);
  info(`artifact_id : ${artifact.artifact_id}`);
  info(`version     : ${artifact.version}`);
  info(`spec_version: ${artifact.spec_version}`);
  info(`confidence  : ${artifact.confidence}`);
  console.log();

  if (!artifact.seal) { fail("Missing seal block"); process.exit(1); }
  const { hash: storedHash, sig: storedSig, algorithm } = artifact.seal;

  if (algorithm !== "HMAC-SHA256") { fail(`Unsupported algorithm: ${algorithm}`); process.exit(1); }

  const payload = Object.fromEntries(
    Object.entries(artifact).filter(([k]) => k !== "seal")
  ) as Record<string, JsonValue>;

  const canonical = jcsCanonicalize(payload);
  const computedHash = crypto.createHash("sha256").update(canonical).digest("hex");

  if (computedHash !== storedHash) {
    fail(`Hash mismatch — artifact modified after sealing`);
    info(`  stored  : ${storedHash}`);
    info(`  computed: ${computedHash}`);
    process.exit(1);
  }
  ok(`Payload hash matches: ${computedHash.slice(0, 16)}…`);

  if (!sealKey) {
    warn("No seal key — signature not verified (pass --key or --key-env NOMOS_SEAL_KEY)");
  } else {
    const computedSig = crypto.createHmac("sha256", sealKey).update(computedHash, "ascii").digest("hex");
    if (!crypto.timingSafeEqual(Buffer.from(computedSig, "hex"), Buffer.from(storedSig, "hex"))) {
      fail("HMAC signature mismatch"); process.exit(1);
    }
    ok("HMAC signature verified");
  }

  const count = artifact.contradiction_report?.contradiction_count ?? 0;
  if (count > 0) warn(`${count} contradiction(s) detected at seal time`);
  else ok("No contradictions");

  const r = artifact.readiness;
  if (r) ok(`ARI=${r.ari ?? "N/A"}  band=${r.autonomy_band ?? "N/A"}`);

  console.log();
  console.log(C.green("Result: VALID\n"));
}

// ─── EXEC ─────────────────────────────────────────────────────────────────────

function evalCondition(node: ConditionNode, input: Record<string, JsonValue>): boolean {
  const { op } = node;

  if (op === "and") {
    if (node.conditions) return node.conditions.every(c => evalCondition(c, input));
    return !!(node.left && node.right && evalCondition(node.left, input) && evalCondition(node.right, input));
  }
  if (op === "or") {
    if (node.conditions) return node.conditions.some(c => evalCondition(c, input));
    return !!(node.left && node.right && (evalCondition(node.left, input) || evalCondition(node.right, input)));
  }
  if (op === "not") {
    const child = node.left ?? node.conditions?.[0];
    return child ? !evalCondition(child, input) : false;
  }

  const fieldVal = node.field ? input[node.field] : undefined;

  switch (op) {
    case "eq":     return fieldVal === node.value;
    case "neq":    return fieldVal !== node.value;
    case "gt":     return typeof fieldVal === "number" && typeof node.value === "number" && fieldVal > node.value;
    case "gte":    return typeof fieldVal === "number" && typeof node.value === "number" && fieldVal >= node.value;
    case "lt":     return typeof fieldVal === "number" && typeof node.value === "number" && fieldVal < node.value;
    case "lte":    return typeof fieldVal === "number" && typeof node.value === "number" && fieldVal <= node.value;
    case "in":     return Array.isArray(node.value) && node.value.includes(fieldVal as JsonValue);
    case "nin":    return Array.isArray(node.value) && !node.value.includes(fieldVal as JsonValue);
    case "exists": return fieldVal !== undefined && fieldVal !== null;
    case "regex":  return typeof fieldVal === "string" && typeof node.pattern === "string" && new RegExp(node.pattern).test(fieldVal);
    default:       return false;
  }
}

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
  info(`artifact_id: ${artifact.artifact_id}@${artifact.version}`);
  info(`input: ${JSON.stringify(input)}`);
  console.log();

  const rules = (artifact.rules ?? []).slice().sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
  const resolution = artifact.conflict_resolution ?? "first_match";
  const matched: { rule: Rule; result: boolean }[] = [];

  for (const rule of rules) {
    const result = evalCondition(rule.condition, input);
    if (result) matched.push({ rule, result });
    info(`rule ${rule.id} (priority ${rule.priority ?? 0}): ${result ? C.green("match") : C.dim("no match")}`);
  }

  console.log();

  if (matched.length === 0) {
    console.log(C.yellow("Verdict: NO_MATCH") + " — no rule matched the input\n");
    return;
  }

  if (resolution === "first_match") {
    const winner = matched[0].rule;
    console.log(C.bold("Verdict: ") + C.cyan(winner.action));
    info(`rule: ${winner.id}`);
    if (winner.text) info(`text: ${winner.text}`);
    console.log();
  } else {
    console.log(C.bold("Matched rules:"));
    for (const { rule } of matched) {
      console.log(`  ${C.cyan(rule.action.padEnd(12))} ${rule.id}  ${C.dim(rule.text ?? "")}`);
    }
    console.log();
  }
}

// ─── DIFF ─────────────────────────────────────────────────────────────────────

function cmdDiff(filePath1: string, filePath2: string): void {
  const a = loadArtifact(filePath1);
  const b = loadArtifact(filePath2);
  console.log(`\n${C.bold("Diff")}\n`);
  info(`${C.dim("from")} ${a.artifact_id}@${a.version}`);
  info(`${C.dim("to  ")} ${b.artifact_id}@${b.version}`);
  console.log();

  // Header fields
  const headerFields = ["artifact_id", "version", "spec_version", "confidence", "conflict_resolution"] as const;
  let headerChanges = 0;
  for (const f of headerFields) {
    if (JSON.stringify(a[f]) !== JSON.stringify(b[f])) {
      console.log(`  ${C.yellow("~")} ${f}: ${C.red(JSON.stringify(a[f]))} → ${C.green(JSON.stringify(b[f]))}`);
      headerChanges++;
    }
  }
  if (headerChanges === 0) ok("Header fields unchanged");
  console.log();

  // Rules
  const rulesA = new Map((a.rules ?? []).map(r => [r.id, r]));
  const rulesB = new Map((b.rules ?? []).map(r => [r.id, r]));
  let ruleChanges = 0;

  for (const [id, rule] of rulesB) {
    if (!rulesA.has(id)) {
      console.log(`  ${C.green("+")} rule ${id}: ${rule.action}  ${C.dim(rule.text?.slice(0, 60) ?? "")}`);
      ruleChanges++;
    }
  }
  for (const [id, rule] of rulesA) {
    if (!rulesB.has(id)) {
      console.log(`  ${C.red("-")} rule ${id}: ${rule.action}  ${C.dim(rule.text?.slice(0, 60) ?? "")}`);
      ruleChanges++;
    }
  }
  for (const [id, ruleA] of rulesA) {
    const ruleB = rulesB.get(id);
    if (!ruleB) continue;
    const condChanged = JSON.stringify(ruleA.condition) !== JSON.stringify(ruleB.condition);
    const actionChanged = ruleA.action !== ruleB.action;
    const priorityChanged = ruleA.priority !== ruleB.priority;
    if (condChanged || actionChanged || priorityChanged) {
      console.log(`  ${C.yellow("~")} rule ${id}:`);
      if (actionChanged)   console.log(`      action:   ${C.red(ruleA.action)} → ${C.green(ruleB.action)}`);
      if (priorityChanged) console.log(`      priority: ${C.red(String(ruleA.priority))} → ${C.green(String(ruleB.priority))}`);
      if (condChanged)     console.log(`      condition changed`);
      ruleChanges++;
    }
  }
  if (ruleChanges === 0) ok("Rules unchanged");
  console.log();

  // Readiness
  const ra = a.readiness; const rb = b.readiness;
  if (ra && rb) {
    const scoreFields = ["ari", "lis", "drs", "res", "gms"] as const;
    for (const f of scoreFields) {
      const va = ra[f]; const vb = rb[f];
      if (va !== vb) {
        const arrow = typeof va === "number" && typeof vb === "number"
          ? (vb > va ? C.green(`${vb}`) : C.red(`${vb}`))
          : C.yellow(String(vb));
        console.log(`  ${C.yellow("~")} ${f.toUpperCase()}: ${va} → ${arrow}`);
      }
    }
    if (ra.autonomy_band !== rb.autonomy_band) {
      console.log(`  ${C.yellow("~")} band: ${C.red(ra.autonomy_band ?? "N/A")} → ${C.green(rb.autonomy_band ?? "N/A")}`);
    }
  }
  console.log();
}

// ─── LINT ─────────────────────────────────────────────────────────────────────

function cmdLint(filePath: string): void {
  const artifact = loadArtifact(filePath);
  console.log(`\n${C.bold("Lint")} ${C.cyan(filePath)}\n`);

  let issues = 0;

  // Rules
  const rules = artifact.rules ?? [];
  if (rules.length === 0) { warn("No rules defined"); issues++; }

  const ids = rules.map(r => r.id);
  const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
  if (dupes.length > 0) { fail(`Duplicate rule IDs: ${dupes.join(", ")}`); issues++; }

  const lowConf = rules.filter(r => r.confidence !== undefined && r.confidence < 0.7);
  if (lowConf.length > 0) { warn(`${lowConf.length} rule(s) with confidence < 0.7: ${lowConf.map(r => r.id).join(", ")}`); issues++; }

  const noText = rules.filter(r => !r.text);
  if (noText.length > 0) { warn(`${noText.length} rule(s) missing text: ${noText.map(r => r.id).join(", ")}`); issues++; }

  const noPriority = rules.filter(r => r.priority === undefined);
  if (noPriority.length > 0) { warn(`${noPriority.length} rule(s) missing priority: ${noPriority.map(r => r.id).join(", ")}`); issues++; }

  // Contradictions
  const count = artifact.contradiction_report?.contradiction_count ?? 0;
  if (count > 0) { warn(`${count} contradiction(s) in contradiction_report`); issues++; }
  else ok("No contradictions");

  // Seal
  if (!artifact.seal) { fail("No seal — artifact is unsealed"); issues++; }
  else ok("Seal present");

  // Readiness
  const r = artifact.readiness;
  if (!r) { warn("No readiness block"); issues++; }
  else {
    if (r.ari !== undefined && r.ari !== null) {
      if (r.ari < 0.3) { warn(`ARI ${r.ari} — human_governed band. Not suitable for autonomous deployment`); issues++; }
      else ok(`ARI ${r.ari} — ${r.autonomy_band}`);
    }
    if (r.drs === null) info("DRS is null — no behavioral data ingested (Declared mode)");
  }

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
  nomos verify   <file>                    Verify cryptographic seal
  nomos exec     <file> --input '{...}'    Execute artifact against input payload
  nomos exec     <file> --input-file <f>   Execute artifact from input file
  nomos diff     <file1> <file2>           Compare two artifact versions
  nomos lint     <file>                    Check for common authoring issues

${C.bold("Options for verify:")}
  --key <hex>          HMAC seal key as hex string
  --key-env <VAR>      Read seal key from environment variable
                       (defaults to NOMOS_SEAL_KEY env var)

${C.bold("Examples:")}
  nomos validate examples/lending_policy_v1.nomos
  nomos verify   examples/lending_policy_v1.nomos --key-env NOMOS_SEAL_KEY
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
