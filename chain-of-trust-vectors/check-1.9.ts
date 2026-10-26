/**
 * Runs vectors-1.9.json through the TypeScript reference (../prototype/chain-of-trust), in every
 * presentation order each case lists, comparing every verdict field the vectors define.
 *
 * Run: npx tsx chain-of-trust-vectors/check-1.9.ts
 */
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { verifyChainPresentation, resolveKey, checkPool, forStatement } from "../prototype/chain-of-trust/chain-verify-core.js";
import { formatScope } from "../prototype/chain-of-trust/scope.js";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const v = JSON.parse(fs.readFileSync(path.join(DIR, process.argv[2] ?? "vectors-1.9.json"), "utf8"));
const FIELDS = ["decision", "reason_code", "dimension", "path", "effective_scope", "revoked_kid"];
const now = new Date(v.check_at);

function run(c: any, pool: any[]): any {
  if (c.purpose === "artifact") {
    return verifyChainPresentation({
      artifact: c.artifact, chain: pool, rootPublicKeyPem: v.root_public_key_pem, now,
      revokedKids: new Set(c.revoked_kids ?? []), revokedCerts: new Set(c.revoked_certs ?? []),
    });
  }
  const bad = checkPool(pool);
  if (bad) return bad;
  const s = c.statement;
  const r = resolveKey({ targetKid: s.kid, chain: pool, rootPublicKeyPem: v.root_public_key_pem, now,
    purpose: forStatement(s.kind, s.name, s.authority_meta, s.suite) });
  if (r.decision !== "RESOLVED") return r;
  const scope = formatScope(r.effective);
  return { decision: "RESOLVED", path: r.path, ...(scope ? { effective_scope: scope } : {}) };
}

let passed = 0, failed = 0;
for (const c of v.cases) {
  const bad: string[] = [];
  for (const order of c.orders) {
    const got = run(c, order.map((i: number) => c.key_certs[i]));
    const diffs = FIELDS.filter((k) => JSON.stringify(c.expected[k]) !== JSON.stringify(got[k]));
    if (diffs.length) bad.push(`order ${JSON.stringify(order)}: ` + diffs.map((k) => `${k} expected ${JSON.stringify(c.expected[k])} got ${JSON.stringify(got[k])}`).join(", "));
  }
  if (bad.length) { failed++; console.log(`  FAIL ${c.name} (${bad.length}/${c.orders.length} orders) ${bad[0]}`); }
  else { passed++; console.log(`  ok   ${c.name.padEnd(52)} ${c.expected.decision.padEnd(22)} x${c.orders.length}`); }
}
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
