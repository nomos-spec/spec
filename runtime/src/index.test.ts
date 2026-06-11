/**
 * Smoke tests for @nomos/runtime
 * Run: npx tsx src/index.test.ts
 */

import { execute, loadArtifact } from './index';

const artifact = loadArtifact('../conformance/fixtures/valid_declared.nomos');

let passed = 0;
let failed = 0;

async function test(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    console.log(`\x1b[32m[PASS]\x1b[0m ${name}`);
    passed++;
  } catch (e) {
    console.log(`\x1b[31m[FAIL]\x1b[0m ${name} — ${e}`);
    failed++;
  }
}

function assert(condition: boolean, msg: string) {
  if (!condition) throw new Error(msg);
}

async function main() {
  await test('approved user gets proceed verdict', async () => {
    const result = await execute({ artifact, context: { user_status: 'approved' } });
    assert(result.verdict === 'proceed', `Expected proceed, got ${result.verdict}`);
    assert(result.allowed === true, 'allowed should be true');
    assert(result.audit_hash.length === 64, 'audit_hash should be 64 hex chars');
    assert(result.contradictions === 0, 'no contradictions expected');
  });

  await test('suspended user gets deny verdict', async () => {
    const result = await execute({ artifact, context: { user_status: 'suspended' } });
    assert(result.verdict === 'deny', `Expected deny, got ${result.verdict}`);
    assert(result.allowed === false, 'allowed should be false');
  });

  await test('no rule match on autonomous band proceeds', async () => {
    const result = await execute({ artifact, context: { user_status: 'unknown' } });
    assert(result.verdict === 'proceed', `Expected proceed for no match on autonomous band, got ${result.verdict}`);
  });

  await test('unknown spec version escalates (R1)', async () => {
    const bad = { ...artifact, spec_version: 'NOMOS-SPEC-999' } as typeof artifact;
    const result = await execute({ artifact: bad, context: {} });
    assert(result.verdict === 'escalate', `Expected escalate, got ${result.verdict}`);
    assert(result.reason === 'UNKNOWN_SPEC_VERSION', `Expected UNKNOWN_SPEC_VERSION reason`);
  });

  await test('artifact_id and version echoed in response', async () => {
    const result = await execute({ artifact, context: { user_status: 'approved' } });
    assert(result.artifact_id === artifact.artifact_id, 'artifact_id mismatch');
    assert(result.artifact_version === artifact.version, 'artifact_version mismatch');
    assert(result.confidence === 'DECLARED', 'confidence mismatch');
  });

  await test('request_id is generated when not provided', async () => {
    const result = await execute({ artifact, context: {} });
    assert(typeof result.request_id === 'string' && result.request_id.length > 0, 'request_id should be generated');
  });

  await test('custom request_id is echoed', async () => {
    const id = 'test-request-id-123';
    const result = await execute({ artifact, context: {}, request_id: id });
    assert(result.request_id === id, `Expected ${id}, got ${result.request_id}`);
  });

  console.log(`\n${'='.repeat(44)}`);
  console.log(`${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

main();
