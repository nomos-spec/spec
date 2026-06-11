/**
 * @nomos/runtime
 *
 * Portable NOMOS governance runtime.
 * Load a .nomos artifact and evaluate decisions anywhere — no network required.
 *
 * @example
 * import { execute } from '@nomos/runtime';
 * import artifact from './my_policy.nomos.json';
 *
 * const result = await execute({
 *   artifact,
 *   context: { credit_score: 720, amount: 15000 },
 * });
 *
 * if (!result.allowed) {
 *   // handle escalate / deny
 * }
 */

import * as fs from 'fs';
import * as crypto from 'crypto';
import { evalCondition, findUnknownOperators } from './evaluator';
import { verifySeal, computeAuditHash, genesisHash } from './crypto';
import type {
  NomosArtifact,
  ExecutionRequest,
  ExecutionResponse,
  Verdict,
  NomosRule,
} from './types';

export type {
  NomosArtifact,
  ExecutionRequest,
  ExecutionResponse,
  Verdict,
  NomosRule,
  RuntimeError,
  ConfidenceTier,
  ContradictionReport,
  Readiness,
  AgentDefinition,
  AgentsManifest,
} from './types';

export { verifySeal, canonicalizeJCS } from './crypto';
export { evalCondition } from './evaluator';

// ─── Known spec versions ─────────────────────────────────────────────────────

const KNOWN_SPEC_VERSIONS = new Set(['NOMOS-SPEC-001', 'NOMOS-SPEC-002']);

// ─── loadArtifact ─────────────────────────────────────────────────────────────

/**
 * Load a .nomos artifact from a file path or parse from a JSON string.
 * Throws if the file cannot be read or the JSON is invalid.
 */
export function loadArtifact(pathOrJson: string): NomosArtifact {
  let raw: string;
  try {
    raw = pathOrJson.trimStart().startsWith('{')
      ? pathOrJson
      : fs.readFileSync(pathOrJson, 'utf8');
  } catch (e) {
    throw new Error(`Failed to load artifact: ${String(e)}`);
  }
  return JSON.parse(raw) as NomosArtifact;
}

// ─── execute ─────────────────────────────────────────────────────────────────

/**
 * Evaluate a decision context against a sealed .nomos artifact.
 *
 * Pipeline:
 *   1. Spec version check
 *   2. Seal verification (if seal_key provided)
 *   3. Agent guard (if artifact has agents manifest)
 *   4. Rule evaluation + conflict resolution
 *   5. Audit hash computation
 */
export async function execute(req: ExecutionRequest): Promise<ExecutionResponse> {
  const { artifact, context, agent_id, seal_key } = req;
  const request_id = req.request_id ?? crypto.randomUUID();
  const ts = new Date().toISOString();

  // 1. Spec version check (R1)
  if (!KNOWN_SPEC_VERSIONS.has(artifact.spec_version)) {
    return escalateResponse({
      artifact, request_id, ts,
      reason: 'UNKNOWN_SPEC_VERSION',
      message: `Unrecognised spec_version: ${artifact.spec_version}`,
    });
  }

  // 2. Seal verification (R2)
  if (seal_key) {
    if (!verifySeal(artifact, seal_key)) {
      return escalateResponse({
        artifact, request_id, ts,
        reason: 'SEAL_VERIFICATION_FAILED',
        message: 'Artifact seal verification failed — artifact may have been tampered with',
      });
    }
  }

  // 3. Agent guard (SPEC-002)
  if (artifact.agents) {
    const guardResult = checkAgentGuard(artifact, agent_id, context);
    if (guardResult) return { ...guardResult, request_id, ts, audit_hash: makeHash(artifact, request_id, guardResult.verdict, ts) };
  }

  // 4. Rule evaluation
  const rules = [...artifact.rules].sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
  const matchedRules: NomosRule[] = [];

  for (const rule of rules) {
    // Check for unknown operators (R4) — escalate rather than fail silently
    const unknownOps = findUnknownOperators(rule.condition);
    if (unknownOps.length > 0) {
      return escalateResponse({
        artifact, request_id, ts,
        reason: 'unknown_operator',
        message: `Rule ${rule.id} uses unknown operator(s): ${unknownOps.join(', ')}`,
      });
    }

    if (evalCondition(rule.condition, context)) {
      matchedRules.push(rule);
    }
  }

  // 5. Conflict resolution
  const resolution = artifact.conflict_resolution ?? 'first_match';
  let primaryRule: NomosRule | undefined;
  let verdict: Verdict;

  if (matchedRules.length === 0) {
    // No rule matched — default based on autonomy band
    const band = artifact.readiness.autonomy_band;
    verdict = band === 'autonomous' ? 'proceed' : 'escalate';
  } else if (resolution === 'first_match' || resolution === 'highest_priority') {
    primaryRule = matchedRules[0];
    verdict = actionToVerdict(primaryRule.action);
  } else {
    // collect_and_resolve: DENY > ESCALATE > ALLOW
    const hasDeny = matchedRules.some(r => r.action === 'DENY');
    const hasEscalate = matchedRules.some(r => r.action === 'ESCALATE');
    if (hasDeny) {
      primaryRule = matchedRules.find(r => r.action === 'DENY');
      verdict = 'deny';
    } else if (hasEscalate) {
      primaryRule = matchedRules.find(r => r.action === 'ESCALATE');
      verdict = 'escalate';
    } else {
      primaryRule = matchedRules[0];
      verdict = 'proceed';
    }
  }

  const audit_hash = makeHash(artifact, request_id, verdict, ts);

  return {
    verdict,
    allowed: verdict === 'proceed',
    outcome: verdict === 'proceed' ? 'auto_approved' : verdict === 'escalate' ? 'manual_review_required' : 'denied',
    rule: primaryRule?.id,
    rule_description: primaryRule?.text,
    matched_rules: matchedRules.map(r => r.id),
    artifact_id: artifact.artifact_id,
    artifact_version: artifact.version,
    confidence: artifact.confidence,
    request_id,
    ts,
    audit_hash,
    contradictions: artifact.contradiction_report.contradiction_count,
  };
}

// ─── Agent guard ─────────────────────────────────────────────────────────────

function checkAgentGuard(
  artifact: NomosArtifact,
  agent_id: string | undefined,
  context: Record<string, unknown>,
): Omit<ExecutionResponse, 'request_id' | 'ts' | 'audit_hash'> | null {
  const manifest = artifact.agents!;

  if (!agent_id) {
    if (manifest.default_policy === 'restrictive') {
      return baseEscalate(artifact, 'UNKNOWN_AGENT', 'No agent_id provided and artifact default_policy is restrictive');
    }
    return null;
  }

  const agentDef = manifest.agents.find(a => a.agent_id === agent_id);
  if (!agentDef) {
    if (manifest.default_policy === 'restrictive') {
      return baseEscalate(artifact, 'UNKNOWN_AGENT', `Agent '${agent_id}' is not registered in the artifact manifest`);
    }
    return null;
  }

  const requestedAction = (context['action'] as string) ?? '';

  if (agentDef.denied_actions.includes(requestedAction)) {
    return {
      verdict: 'deny',
      allowed: false,
      matched_rules: [],
      artifact_id: artifact.artifact_id,
      artifact_version: artifact.version,
      confidence: artifact.confidence,
      contradictions: artifact.contradiction_report.contradiction_count,
      reason: 'AGENT_ACTION_DENIED',
    };
  }

  if (agentDef.constraints) {
    for (const constraint of agentDef.constraints) {
      const val = (context[constraint.field] as number) ?? null;
      if (val === null) continue;
      const violated = checkConstraint(val, constraint.operator, constraint.value as number);
      if (violated) {
        return baseEscalate(artifact, 'CONSTRAINT_VIOLATED', `Constraint violated: ${constraint.field} ${constraint.operator} ${constraint.value}`);
      }
    }
  }

  return null;
}

function checkConstraint(
  actual: number,
  operator: string,
  expected: number | string | boolean,
): boolean {
  const e = Number(expected);
  switch (operator) {
    case 'lt':  return !(actual < e);
    case 'lte': return !(actual <= e);
    case 'gt':  return !(actual > e);
    case 'gte': return !(actual >= e);
    case 'eq':  return !(actual === e);
    case 'neq': return !(actual !== e);
    default:    return false;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function actionToVerdict(action: 'ALLOW' | 'DENY' | 'ESCALATE'): Verdict {
  if (action === 'ALLOW') return 'proceed';
  if (action === 'DENY') return 'deny';
  return 'escalate';
}

function makeHash(artifact: NomosArtifact, requestId: string, verdict: string, ts: string): string {
  const genesis = genesisHash(artifact.artifact_id, artifact.seal.ts);
  return computeAuditHash(genesis, requestId, verdict, ts);
}

function baseEscalate(
  artifact: NomosArtifact,
  reason: string,
  _message: string,
): Omit<ExecutionResponse, 'request_id' | 'ts' | 'audit_hash'> {
  return {
    verdict: 'escalate',
    allowed: false,
    matched_rules: [],
    artifact_id: artifact.artifact_id,
    artifact_version: artifact.version,
    confidence: artifact.confidence,
    contradictions: artifact.contradiction_report.contradiction_count,
    reason,
  };
}

function escalateResponse(opts: {
  artifact: NomosArtifact;
  request_id: string;
  ts: string;
  reason: string;
  message: string;
}): ExecutionResponse {
  const { artifact, request_id, ts, reason } = opts;
  const audit_hash = makeHash(artifact, request_id, 'escalate', ts);
  return {
    verdict: 'escalate',
    allowed: false,
    matched_rules: [],
    artifact_id: artifact.artifact_id,
    artifact_version: artifact.version,
    confidence: artifact.confidence,
    request_id,
    ts,
    audit_hash,
    contradictions: artifact.contradiction_report.contradiction_count,
    reason,
  };
}
