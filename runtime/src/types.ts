// ─── Artifact types ──────────────────────────────────────────────────────────

export type ConfidenceTier = 'DECLARED' | 'VALIDATED' | 'CERTIFIED';
export type Verdict = 'proceed' | 'escalate' | 'deny';
export type ConflictResolution = 'first_match' | 'collect_and_resolve' | 'highest_priority';
export type RuleSource = 'policy' | 'behavioral' | 'inferred';
export type AutonommyBand = 'autonomous' | 'bounded' | 'human_governed';

export type Json =
  | string | number | boolean | null
  | Json[]
  | { [key: string]: Json };

// Condition formats — simple leaf (SPEC-001) or AST node (SPEC-001 §4.5)
export type SimpleOperator =
  | 'eq' | 'neq' | 'gt' | 'gte' | 'lt' | 'lte'
  | 'in' | 'nin' | 'exists' | 'regex';

export interface SimpleCondition {
  op: SimpleOperator;
  field: string;
  value?: Json;
}

export type ASTExpr =
  | { lit: Json }
  | { ref: string }
  | { op: string; args: ASTExpr[] }
  | { fn: string; args: ASTExpr[] };

export type Condition = SimpleCondition | ASTExpr;

export interface NomosRule {
  id: string;
  text: string;
  condition: Condition;
  action: 'ALLOW' | 'DENY' | 'ESCALATE';
  priority: number;
  source: RuleSource;
  confidence?: number;
  metadata?: {
    section?: string;
    page?: number;
    tags?: string[];
    last_modified?: string;
  };
}

export interface ContradictionReport {
  contradiction_count: number;
  contradictions: Array<{
    type: 'threshold_conflict' | 'role_conflict' | 'ghost_term' | 'rule_collision' | 'layer_divergence';
    rule_ids: string[];
    description: string;
    severity: 'low' | 'medium' | 'high';
  }>;
}

export interface Readiness {
  lis: number;
  drs: number | null;
  res: number;
  gms: number;
  ari: number;
  autonomy_band: AutonommyBand;
}

export interface Seal {
  algorithm: 'HMAC-SHA256';
  ts: string;
  hash: string;
  sig: string;
}

export interface AgentConstraint {
  field: string;
  operator: 'lt' | 'lte' | 'gt' | 'gte' | 'eq' | 'neq';
  value: number | string | boolean;
}

export interface AgentDefinition {
  agent_id: string;
  display_name?: string;
  allowed_actions: string[];
  denied_actions: string[];
  constraints?: AgentConstraint[];
  audit_level: 'minimal' | 'standard' | 'full';
}

export interface AgentsManifest {
  version: string;
  default_policy: 'permissive' | 'restrictive';
  agents: AgentDefinition[];
}

export interface NomosArtifact {
  artifact_id: string;
  version: string;
  spec_version: 'NOMOS-SPEC-001' | 'NOMOS-SPEC-002';
  confidence: ConfidenceTier;
  conflict_resolution?: ConflictResolution;
  domain: {
    name: string;
    organization?: string;
    effective_date?: string;
    jurisdiction?: string;
    tags?: string[];
  };
  rules: NomosRule[];
  agents?: AgentsManifest;
  contradiction_report: ContradictionReport;
  readiness: Readiness;
  seal: Seal;
}

// ─── Execution types ─────────────────────────────────────────────────────────

export interface ExecutionRequest {
  /** Artifact to evaluate against. Pass the loaded object directly. */
  artifact: NomosArtifact;
  /** Decision context — key/value pairs matched against rule conditions */
  context: Record<string, unknown>;
  /** Agent identifier. Required if artifact contains an agents manifest. */
  agent_id?: string;
  /** UUIDv4 for idempotency. Generated automatically if omitted. */
  request_id?: string;
  /**
   * Seal verification key (hex-encoded HMAC secret).
   * If provided, the seal is verified before evaluation.
   * If omitted, the seal is not checked (useful for testing).
   */
  seal_key?: string;
}

export interface ExecutionResponse {
  verdict: Verdict;
  allowed: boolean;
  outcome?: string;
  rule?: string;
  rule_description?: string;
  matched_rules: string[];
  artifact_id: string;
  artifact_version: string;
  confidence: ConfidenceTier;
  request_id: string;
  ts: string;
  audit_hash: string;
  contradictions: number;
  /** Present when verdict is escalate due to a system condition, not a rule match */
  reason?: string;
}

export interface RuntimeError {
  code:
    | 'UNKNOWN_SPEC_VERSION'
    | 'SEAL_VERIFICATION_FAILED'
    | 'UNKNOWN_AGENT'
    | 'AGENT_ACTION_DENIED'
    | 'CONSTRAINT_VIOLATED'
    | 'MISSING_CONTEXT_FIELD'
    | 'INVALID_ARTIFACT';
  message: string;
}
