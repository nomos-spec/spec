# @nomos/runtime

Portable NOMOS governance runtime. Load a `.nomos` artifact and evaluate decisions anywhere — no network required, no database, no external dependencies.

## Install

```bash
npm install @nomos/runtime
```

## Usage

```typescript
import { execute, loadArtifact } from '@nomos/runtime';

// Load a sealed .nomos artifact
const artifact = loadArtifact('./my_policy.nomos.json');

// Evaluate a decision
const result = await execute({
  artifact,
  context: {
    credit_score: 720,
    amount: 15000,
  },
});

console.log(result.verdict);          // 'proceed' | 'escalate' | 'deny'
console.log(result.rule);             // which rule matched
console.log(result.rule_description); // natural language description
console.log(result.audit_hash);       // sha256 hash-chain entry
console.log(result.allowed);          // boolean convenience field
```

## With seal verification

```typescript
const result = await execute({
  artifact,
  context: { ... },
  seal_key: process.env.NOMOS_SEAL_KEY, // hex-encoded HMAC secret
});
```

If the seal does not verify, the runtime returns `verdict: 'escalate'` with `reason: 'SEAL_VERIFICATION_FAILED'` rather than throwing.

## With agent identity (SPEC-002)

```typescript
const result = await execute({
  artifact,
  context: { action: 'approve_loan', amount: 15000 },
  agent_id: 'loan-agent-v1',
});
```

If the artifact contains an `agents` manifest, the runtime checks the agent's permissions and constraints before evaluating rules.

## Producing artifacts

The runtime evaluates artifacts. It does not produce them. To compile a policy document into a `.nomos` artifact, use [NOMOS Studio](https://nomosprotocol.com).

## Spec conformance

This package implements [NOMOS-SPEC-001](../spec/NOMOS-SPEC-001.md) and [NOMOS-SPEC-002](../spec/NOMOS-SPEC-002.md). Run the conformance suite to verify:

```bash
npx tsx ../conformance/run.ts
```

## License

Apache 2.0
