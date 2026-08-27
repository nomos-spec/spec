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
    now: new Date(vectors.check_at),
  });

  const decisionMatches = result.decision === testCase.expected.decision;
  const reasonMatches = testCase.expected.reason === undefined || (result as any).reason === testCase.expected.reason;
  const pathMatches = testCase.expected.path === undefined || JSON.stringify((result as any).path) === JSON.stringify(testCase.expected.path);
  const leafKidMatches = testCase.expected.leaf_kid === undefined || (result as any).leaf_kid === testCase.expected.leaf_kid;

  if (decisionMatches && reasonMatches && pathMatches && leafKidMatches) {
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
