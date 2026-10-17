import Database from "better-sqlite3";
import { nowIso } from "./db";
import { evaluate } from "./policy";
import { ActionInput, EventRecord, EvaluationResult, Severity } from "./types";

function severityFor(
  decision: EvaluationResult["decision"],
  riskScore: number,
): Severity {
  if (decision === "DENY") return riskScore >= 90 ? "critical" : "high";
  if (decision === "REVIEW") return "medium";
  return "low";
}

function parseJson<T>(value: unknown, fallback: T): T {
  try {
    return JSON.parse(String(value)) as T;
  } catch {
    return fallback;
  }
}

export function eventFromRow(row: Record<string, unknown>): EventRecord {
  return {
    id: Number(row.id),
    createdAt: String(row.created_at),
    actor: String(row.actor),
    action: String(row.action),
    resource: String(row.resource),
    source: String(row.source),
    metadata: parseJson<Record<string, unknown>>(row.metadata_json, {}),
    decision: row.decision as EventRecord["decision"],
    reasons: parseJson<string[]>(row.reasons_json, []),
    policyIds: parseJson<number[]>(row.policy_ids_json, []),
    riskScore: Number(row.risk_score),
  };
}

export function recordEvaluation(
  db: Database.Database,
  action: ActionInput,
): { event: EventRecord; evaluation: EvaluationResult; incidentId?: number } {
  const evaluation = evaluate(db, action);
  const eventTime = action.timestamp ?? nowIso();
  const incidentTime = nowIso();
  const auditMetadata = {
    ...(action.metadata ?? {}),
    gateway: {
      eventId: action.eventId ?? null,
      agentId: action.agentId ?? action.actor,
      sessionId: action.sessionId ?? null,
      taskId: action.taskId ?? null,
      toolName: action.toolName ?? action.action,
      operation: action.operation ?? action.action,
      dataClassification: action.dataClassification ?? "internal",
      authorizationContext: action.authorizationContext ?? {},
      parentDelegationId: action.parentDelegationId ?? null,
    },
  };
  let incidentId: number | undefined;
  const transaction = db.transaction(() => {
    const inserted = db
      .prepare(
        `INSERT INTO events (created_at, actor, action, resource, source, metadata_json, decision, reasons_json, policy_ids_json, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        eventTime,
        action.actor,
        action.action,
        action.resource,
        action.source ?? "api",
        JSON.stringify(auditMetadata),
        evaluation.decision,
        JSON.stringify(evaluation.reasons),
        JSON.stringify(
          evaluation.matchedPolicies.map(({ policy }) => policy.id),
        ),
        evaluation.riskScore,
      );
    const eventId = Number(inserted.lastInsertRowid);
    if (evaluation.decision !== "ALLOW") {
      const severity = severityFor(evaluation.decision, evaluation.riskScore);
      const title =
        evaluation.decision === "DENY"
          ? "Blocked action requires attention"
          : "Action held for review";
      const summary = `${action.actor} attempted ${action.action} on ${action.resource}.`;
      const incident = db
        .prepare(
          `INSERT INTO incidents (event_id, severity, status, title, summary, created_at, updated_at) VALUES (?, ?, 'open', ?, ?, ?, ?)`,
        )
        .run(eventId, severity, title, summary, incidentTime, incidentTime);
      incidentId = Number(incident.lastInsertRowid);
      const rule =
        evaluation.decision === "DENY" ? "policy-deny" : "policy-review";
      db.prepare(
        `INSERT INTO detections (event_id, rule, signal, severity, created_at) VALUES (?, ?, ?, ?, ?)`,
      ).run(
        eventId,
        rule,
        evaluation.reasons.join("; "),
        severity,
        incidentTime,
      );
      if (
        action.metadata?.promptInjection === true ||
        /ignore (?:all )?polic/i.test(JSON.stringify(action.metadata))
      ) {
        db.prepare(
          `INSERT INTO detections (event_id, rule, signal, severity, created_at) VALUES (?, 'prompt-injection', 'Instruction override signal detected', 'high', ?)`,
        ).run(eventId, incidentTime);
      }
      const actionText = `${action.action} ${action.resource}`.toLowerCase();
      const signals: Array<[string, string, Severity]> = [];
      if (/secret|credential|token|canary/.test(actionText))
        signals.push([
          "restricted-data",
          "Restricted synthetic data indicator",
          "critical",
        ]);
      if (
        /delegate|role\.grant|permission\.add/.test(actionText) ||
        action.metadata?.delegatedFrom
      )
        signals.push([
          "delegation-escalation",
          "Cross-agent delegation or privilege escalation indicator",
          "high",
        ]);
      if (/policy\.|tamper|disable.*security/.test(actionText))
        signals.push([
          "policy-tampering",
          "Security policy modification indicator",
          "critical",
        ]);
      if (action.metadata?.repeatedDenial === true)
        signals.push([
          "repeated-denials",
          "Repeated denial sequence indicator",
          "high",
        ]);
      for (const [rule, signal, severity] of signals)
        db.prepare(
          `INSERT INTO detections (event_id, rule, signal, severity, created_at) VALUES (?, ?, ?, ?, ?)`,
        ).run(eventId, rule, signal, severity, incidentTime);
    }
    const row = db
      .prepare("SELECT * FROM events WHERE id = ?")
      .get(eventId) as Record<string, unknown>;
    return eventFromRow(row);
  });
  return { event: transaction(), evaluation, incidentId };
}

export function seedBaseline(db: Database.Database): void {
  const count = Number(
    (
      db.prepare("SELECT COUNT(*) AS count FROM events").get() as {
        count: number;
      }
    ).count,
  );
  if (count > 0) return;
  const baseline: ActionInput[] = [
    {
      actor: "analyst.synthetic",
      action: "data.read",
      resource: "workspace/audit-log",
      source: "internal",
      metadata: { synthetic: true },
      timestamp: "2025-01-15T10:00:00.000Z",
    },
    {
      actor: "automation.synthetic",
      action: "data.export",
      resource: "customer-records",
      source: "external-webhook",
      metadata: { synthetic: true },
      timestamp: "2025-01-15T10:01:00.000Z",
    },
    {
      actor: "agent.synthetic",
      action: "database.delete",
      resource: "production/orders",
      source: "internal",
      metadata: { synthetic: true },
      timestamp: "2025-01-15T10:02:00.000Z",
    },
  ];
  for (const action of baseline) recordEvaluation(db, action);
}
