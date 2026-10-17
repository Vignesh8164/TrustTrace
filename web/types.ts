export type Decision = "ALLOW" | "DENY" | "REVIEW";
export type Severity = "low" | "medium" | "high" | "critical";
export type IncidentStatus = "open" | "acknowledged" | "resolved";

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

export interface Detection {
  id: number;
  rule: string;
  signal: string;
  severity: Severity;
  createdAt: string;
}

export interface Incident {
  id: number;
  eventId: number;
  severity: Severity;
  status: IncidentStatus;
  title: string;
  summary: string;
  resolution: string | null;
  createdAt: string;
  updatedAt: string;
  event: EventRecord | null;
  detections: Detection[];
}

export interface PolicyMatch {
  actions?: string[];
  actionPrefixes?: string[];
  resourceIncludes?: string[];
  sources?: string[];
  actors?: string[];
}

export interface Policy {
  id: number;
  name: string;
  description?: string;
  effect: Decision;
  priority: number;
  match: PolicyMatch;
  enabled: boolean;
  createdAt: string;
}

export interface Summary {
  events: number;
  incidents: number;
  openIncidents: number;
  detections: number;
  decisions: Partial<Record<Decision, number>>;
}

export interface Report {
  generatedAt: string;
  summary: Partial<Record<Decision, number>>;
  incidentBreakdown: {
    status: IncidentStatus;
    severity: Severity;
    count: number;
  }[];
  recentEvents: EventRecord[];
  policies: number;
}

export interface LabRun {
  scenario: string;
  events: EventRecord[];
  decisions: Decision[];
  incidentIds: (number | null)[];
}

export interface ApiEnvelope<T> {
  items: T[];
  total?: number;
}
