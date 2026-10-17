export const DECISIONS = ["ALLOW", "DENY", "REVIEW"] as const;
export type Decision = (typeof DECISIONS)[number];

export const INCIDENT_STATUSES = ["open", "acknowledged", "resolved"] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];
export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export interface ActionInput {
  /** Stable gateway envelope fields are optional for backwards-compatible lab calls. */
  eventId?: string;
  agentId?: string;
  sessionId?: string;
  taskId?: string;
  toolName?: string;
  operation?: string;
  dataClassification?: "public" | "internal" | "confidential" | "restricted";
  authorizationContext?: Record<string, unknown>;
  parentDelegationId?: string;
  actor: string;
  action: string;
  resource: string;
  source?: string;
  metadata?: Record<string, unknown>;
  timestamp?: string;
}

export interface PolicyMatch {
  actions?: string[];
  actionPrefixes?: string[];
  resourceIncludes?: string[];
  sources?: string[];
  actors?: string[];
}

export interface PolicyInput {
  name: string;
  description?: string;
  effect: Decision;
  priority?: number;
  match: PolicyMatch;
  enabled?: boolean;
}

export interface Policy extends PolicyInput {
  id: number;
  priority: number;
  enabled: boolean;
  createdAt: string;
}

export interface PolicyMatchResult {
  policy: Policy;
  reason: string;
}

export interface EvaluationResult {
  decision: Decision;
  reasons: string[];
  matchedPolicies: PolicyMatchResult[];
  riskScore: number;
}

export interface EventRecord {
  id: number;
  createdAt: string;
  actor: string;
  action: string;
  resource: string;
  source: string;
  metadata: Record<string, unknown>;
  decision: Decision;
  reasons: string[];
  policyIds: number[];
  riskScore: number;
}
