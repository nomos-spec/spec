/**
 * Runs every case in vectors.json through THIS repo's own reference implementation
 * (../prototype/chain-of-trust/chain-verify-core.ts) and confirms the actual verdict matches
 * `expected`. This is what proves the vectors are self-consistent with the spec's own reference
 * code before anyone else is asked to check their implementation against them — a vectors file
 * nobody had verified against its own reference implementation would be worse than no vectors
 * file at all.
 *
 * This does NOT demonstrate interoperability — see README.md. It demonstrates that these
 * vectors are not simply wrong.
 *
 * Run: npx tsx chain-of-trust-vectors/check.ts
 */
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { verifyChainPresentation } from '../prototype/chain-of-trust/chain-verify-core.js';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(fs.readFileSync(path.join(DIR, 'vectors.json'), 'utf8'));

let passed = 0, failed = 0;

for (const testCase of vectors.cases) {
  const result = verifyChainPresentation({
    artifact: testCase.artifact,
    chain: testCase.key_certs,
    rootPublicKeyPem: vectors.root_public_key_pem,
    // Only present when the CASE itself declares them (§5.1-5.2, §5.5) — a case that omits
    // revoked_kids must keep hasOwnKeySource=false exactly as every pre-existing vector does,
    // not silently switch to an empty-but-present revocation source.
    revokedKids: testCase.revoked_kids ? new Set<string>(testCase.revoked_kids) : undefined,
    freshnessStaples: testCase.freshness_staples,
    now: new Date(vectors.check_at),
  });

  const decisionMatches = result.decision === testCase.expected.decision;
  const reasonMatches = testCase.expected.reason_code === undefined || (result as any).reason_code === testCase.expected.reason_code;
  const pathMatches = testCase.expected.path === undefined || JSON.stringify((result as any).path) === JSON.stringify(testCase.expected.path);
  const leafKidMatches = testCase.expected.leaf_kid === undefined || (result as any).leaf_kid === testCase.expected.leaf_kid;
  // §3.4 fields — without these the scope cases would be verified on `decision` alone, which
  // would pass even if an implementation blamed the wrong dimension or lost the effective scope.
  const dimensionMatches = testCase.expected.dimension === undefined || (result as any).dimension === testCase.expected.dimension;
  const scopeMatches = testCase.expected.effective_scope === undefined || (result as any).effective_scope === testCase.expected.effective_scope;
  const revokedKidMatches = testCase.expected.revoked_kid === undefined || (result as any).revoked_kid === testCase.expected.revoked_kid;
  // §5.5 — without this a staple-coverage case would pass on `decision: ALLOWED` alone even if an
  // implementation silently reported unchecked confidence as if it were staple-backed, or vice versa.
  const revocationCheckedMatches = testCase.expected.revocation_checked === undefined || (result as any).revocation_checked === testCase.expected.revocation_checked;

  if (decisionMatches && reasonMatches && pathMatches && leafKidMatches && dimensionMatches && scopeMatches && revokedKidMatches && revocationCheckedMatches) {
    console.log(`  ✓ ${testCase.name}`);
    passed++;
  } else {
    console.error(`  ✗ ${testCase.name}`);
    console.error(`    expected: ${JSON.stringify(testCase.expected)}`);
    console.error(`    actual:   ${JSON.stringify(result)}`);
    failed++;
  }
}

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
