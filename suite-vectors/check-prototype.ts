// The chain-of-trust prototype's own suite module (prototype/chain-of-trust/suites.ts) against the
// NOMOS-SPEC-010 vectors. Run: npx tsx suite-vectors/check-prototype.ts
import { readFileSync } from "node:fs";
import { verifySuite } from "../prototype/chain-of-trust/suites.js";

const v = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
let passed = 0, failed = 0;
for (const c of v.cases) {
  const r = verifySuite(c.suite, c.public_key_pem, Buffer.from(c.payload_b64, "base64"), c.proof);
  const reason = r.ok ? null : r.reason;
  if (r.ok === c.expected.ok && reason === c.expected.reason) passed++;
  else { failed++; console.log(`  FAIL ${c.name}: got ok=${r.ok} reason=${reason}, expected ${JSON.stringify(c.expected)}`); }
}
console.log(`${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
