import express, { NextFunction, Request, Response } from "express";
import helmet from "helmet";
import Database from "better-sqlite3";
import path from "node:path";
import {
  clearOperationalData,
  insertPolicy,
  listPolicies,
  openDatabase,
  seedPolicies,
} from "./db";
import { recordEvaluation, eventFromRow, seedBaseline } from "./gateway";
import { IncidentStatus, Severity } from "./types";
import {
  parseActionInput,
  parseId,
  parsePolicyInput,
  ValidationError,
} from "./validation";

export interface AppOptions {
  dbPath?: string;
  seed?: boolean;
}

function parseLimit(value: unknown, fallback = 100): number {
  if (value === undefined) return fallback;
  const number = Number(value);
  return Number.isInteger(number) && number >= 1
    ? Math.min(number, 500)
    : fallback;
}
function parseOffset(value: unknown): number {
  const number = Number(value ?? 0);
  return Number.isInteger(number) && number >= 0 ? Math.min(number, 100000) : 0;
}
function json<T>(value: unknown, fallback: T): T {
  try {
    return JSON.parse(String(value)) as T;
  } catch {
    return fallback;
  }
}
function queryEvents(db: Database.Database, req: Request) {
  const clauses: string[] = [];
  const values: unknown[] = [];
  if (
    typeof req.query.decision === "string" &&
    ["ALLOW", "DENY", "REVIEW"].includes(req.query.decision)
  ) {
    clauses.push("decision = ?");
    values.push(req.query.decision);
  }
  if (typeof req.query.action === "string" && req.query.action.trim()) {
    clauses.push("action LIKE ?");
    values.push(`%${req.query.action.trim()}%`);
  }
  if (typeof req.query.actor === "string" && req.query.actor.trim()) {
    clauses.push("actor LIKE ?");
    values.push(`%${req.query.actor.trim()}%`);
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = db
    .prepare(`SELECT * FROM events ${where} ORDER BY id DESC LIMIT ? OFFSET ?`)
    .all(
      ...values,
      parseLimit(req.query.limit),
      parseOffset(req.query.offset),
    ) as Record<string, unknown>[];
  const total = Number(
    (
      db
        .prepare(`SELECT COUNT(*) AS count FROM events ${where}`)
        .get(...values) as { count: number }
    ).count,
  );
  return {
    items: rows.map(eventFromRow),
    total,
    limit: parseLimit(req.query.limit),
    offset: parseOffset(req.query.offset),
  };
}
function incidentFromRow(db: Database.Database, row: Record<string, unknown>) {
  const eventRow = db
    .prepare("SELECT * FROM events WHERE id = ?")
    .get(Number(row.event_id)) as Record<string, unknown> | undefined;
  const detections = db
    .prepare(
      "SELECT id, rule, signal, severity, created_at AS createdAt FROM detections WHERE event_id = ? ORDER BY id ASC",
    )
    .all(Number(row.event_id));
  return {
    id: Number(row.id),
    eventId: Number(row.event_id),
    severity: row.severity,
    status: row.status,
    title: row.title,
    summary: row.summary,
    resolution: row.resolution ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    event: eventRow ? eventFromRow(eventRow) : null,
    detections,
  };
}
function queryIncidents(db: Database.Database, req: Request) {
  const clauses: string[] = [];
  const values: unknown[] = [];
  if (
    typeof req.query.status === "string" &&
    ["open", "acknowledged", "resolved"].includes(req.query.status)
  ) {
    clauses.push("status = ?");
    values.push(req.query.status);
  }
  if (
    typeof req.query.severity === "string" &&
    ["low", "medium", "high", "critical"].includes(req.query.severity)
  ) {
    clauses.push("severity = ?");
    values.push(req.query.severity);
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = db
    .prepare(
      `SELECT * FROM incidents ${where} ORDER BY id DESC LIMIT ? OFFSET ?`,
    )
    .all(
      ...values,
      parseLimit(req.query.limit),
      parseOffset(req.query.offset),
    ) as Record<string, unknown>[];
  const total = Number(
    (
      db
        .prepare(`SELECT COUNT(*) AS count FROM incidents ${where}`)
        .get(...values) as { count: number }
    ).count,
  );
  return {
    items: rows.map((row) => incidentFromRow(db, row)),
    total,
    limit: parseLimit(req.query.limit),
    offset: parseOffset(req.query.offset),
  };
}
function csvEscape(value: unknown): string {
  const text =
    value === null || value === undefined
      ? ""
      : typeof value === "object"
        ? JSON.stringify(value)
        : String(value);
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}
function toCsv(rows: Record<string, unknown>[], columns: string[]): string {
  return (
    [
      columns.join(","),
      ...rows.map((row) =>
        columns.map((column) => csvEscape(row[column])).join(","),
      ),
    ].join("\n") + "\n"
  );
}
function wantsCsv(req: Request): boolean {
  return (
    req.query.format === "csv" ||
    req.accepts(["json", "text/csv"]) === "text/csv"
  );
}

export function createApp(options: AppOptions = {}) {
  const db = openDatabase(
    options.dbPath ?? process.env.TRUSTTRACE_DB_PATH ?? "data/trusttrace.db",
  );
  seedPolicies(db);
  if (options.seed !== false) seedBaseline(db);
  const app = express();
  app.disable("x-powered-by");
  app.use(helmet());
  app.use(express.json({ limit: "64kb" }));
  app.use(
    express.static(path.resolve(process.cwd(), "dist-web"), {
      index: "index.html",
    }),
  );

  app.get("/api/health", (_req, res) =>
    res.json({
      status: "ok",
      service: "trusttrace-backend",
      database: "sqlite",
      uptimeSeconds: Math.round(process.uptime()),
    }),
  );
  app.get("/api/summary", (_req, res) => {
    const events = db.prepare("SELECT COUNT(*) AS count FROM events").get() as {
      count: number;
    };
    const incidents = db
      .prepare("SELECT COUNT(*) AS count FROM incidents")
      .get() as { count: number };
    const openIncidents = db
      .prepare(
        "SELECT COUNT(*) AS count FROM incidents WHERE status != 'resolved'",
      )
      .get() as { count: number };
    const decisions = db
      .prepare(
        "SELECT decision, COUNT(*) AS count FROM events GROUP BY decision",
      )
      .all() as { decision: string; count: number }[];
    const detections = db
      .prepare("SELECT COUNT(*) AS count FROM detections")
      .get() as { count: number };
    return res.json({
      events: events.count,
      incidents: incidents.count,
      openIncidents: openIncidents.count,
      detections: detections.count,
      decisions: Object.fromEntries(
        decisions.map((row) => [row.decision, row.count]),
      ),
    });
  });
  app.get("/api/events", (req, res) => res.json(queryEvents(db, req)));
  app.get("/api/incidents", (req, res) => res.json(queryIncidents(db, req)));
  app.patch("/api/incidents/:id", (req, res, next) => {
    try {
      const id = parseId(req.params.id, "incident id");
      if (!req.body || typeof req.body !== "object" || Array.isArray(req.body))
        throw new ValidationError(["body must be an object"]);
      const status = req.body.status;
      const resolution = req.body.resolution;
      if (
        status !== undefined &&
        (typeof status !== "string" ||
          !(["open", "acknowledged", "resolved"] as string[]).includes(status))
      )
        throw new ValidationError([
          "status must be open, acknowledged, or resolved",
        ]);
      if (
        resolution !== undefined &&
        (typeof resolution !== "string" || resolution.length > 500)
      )
        throw new ValidationError([
          "resolution must be at most 500 characters",
        ]);
      const current = db
        .prepare("SELECT * FROM incidents WHERE id = ?")
        .get(id) as Record<string, unknown> | undefined;
      if (!current)
        return res.status(404).json({ error: "Incident not found" });
      if (status === undefined && resolution === undefined)
        throw new ValidationError(["provide status or resolution"]);
      db.prepare(
        "UPDATE incidents SET status = ?, resolution = ?, updated_at = ? WHERE id = ?",
      ).run(
        status ?? current.status,
        resolution ?? current.resolution ?? null,
        new Date().toISOString(),
        id,
      );
      const updated = db
        .prepare("SELECT * FROM incidents WHERE id = ?")
        .get(id) as Record<string, unknown>;
      return res.json(incidentFromRow(db, updated));
    } catch (error) {
      return next(error);
    }
  });
  app.get("/api/policies", (_req, res) =>
    res.json({ items: listPolicies(db) }),
  );
  app.post("/api/policies", (req, res, next) => {
    try {
      const policy = insertPolicy(db, parsePolicyInput(req.body));
      return res.status(201).json(policy);
    } catch (error) {
      return next(error);
    }
  });
  app.post("/api/events/evaluate", (req, res, next) => {
    try {
      const result = recordEvaluation(db, parseActionInput(req.body));
      return res.status(201).json({
        event: result.event,
        decision: result.evaluation.decision,
        reasons: result.evaluation.reasons,
        riskScore: result.evaluation.riskScore,
        matchedPolicies: result.evaluation.matchedPolicies.map(
          ({ policy, reason }) => ({
            id: policy.id,
            name: policy.name,
            effect: policy.effect,
            priority: policy.priority,
            reason,
          }),
        ),
        incidentId: result.incidentId ?? null,
      });
    } catch (error) {
      return next(error);
    }
  });

  const scenarios: Record<string, Parameters<typeof recordEvaluation>[1][]> = {
    "normal-authorized": [
      {
        actor: "analyst.synthetic",
        action: "data.read",
        resource: "workspace/audit-log",
        source: "internal",
        metadata: { synthetic: true },
      },
    ],
    "unauthorized-access": [
      {
        actor: "agent.untrusted",
        action: "secret.read",
        resource: "synthetic/canary-secret",
        source: "external",
        metadata: { synthetic: true, canary: true },
      },
    ],
    "prompt-injection": [
      {
        actor: "lab.attacker",
        action: "agent.execute",
        resource: "production/deploy",
        source: "external",
        metadata: {
          synthetic: true,
          promptInjection: true,
          instruction: "ignore all policy checks",
        },
      },
    ],
    "data-exfiltration": [
      {
        actor: "lab.attacker",
        action: "data.export",
        resource: "customer-records",
        source: "external-webhook",
        metadata: { synthetic: true, destination: "unknown-host" },
      },
    ],
    "privilege-escalation": [
      {
        actor: "lab.attacker",
        action: "iam.role.grant",
        resource: "production/admin",
        source: "external",
        metadata: { synthetic: true },
      },
    ],
    "destructive-production": [
      {
        actor: "lab.attacker",
        action: "database.delete",
        resource: "production/orders",
        source: "external",
        metadata: { synthetic: true },
      },
    ],
    "repeated-denials": Array.from({ length: 3 }, (_, index) => ({
      actor: "agent.untrusted",
      action: "database.delete",
      resource: `production/synthetic-${index}`,
      source: "external",
      metadata: { synthetic: true, repeatedDenial: true },
    })),
    "policy-tampering": [
      {
        actor: "agent.untrusted",
        action: "policy.disable",
        resource: "security/policy-engine",
        source: "external",
        metadata: { synthetic: true, tamperAttempt: true },
      },
    ],
  };
  app.post("/api/lab/:scenario/run", (req, res, next) => {
    try {
      const actions = scenarios[req.params.scenario];
      if (!actions)
        return res.status(404).json({
          error: "Unknown scenario",
          availableScenarios: Object.keys(scenarios),
        });
      const results = actions.map((action) => recordEvaluation(db, action));
      return res.status(201).json({
        scenario: req.params.scenario,
        events: results.map((result) => result.event),
        decisions: results.map((result) => result.evaluation.decision),
        incidentIds: results.map((result) => result.incidentId ?? null),
      });
    } catch (error) {
      return next(error);
    }
  });
  app.post("/api/lab/reset", (_req, res, next) => {
    try {
      clearOperationalData(db);
      seedBaseline(db);
      return res.json({
        status: "reset",
        summary: { events: 3, incidents: 2 },
      });
    } catch (error) {
      return next(error);
    }
  });

  app.get("/api/export/events", (req, res) => {
    const result = queryEvents(db, req);
    if (wantsCsv(req)) {
      const rows = result.items.map((event) => ({
        id: event.id,
        createdAt: event.createdAt,
        actor: event.actor,
        action: event.action,
        resource: event.resource,
        source: event.source,
        decision: event.decision,
        riskScore: event.riskScore,
        reasons: event.reasons.join(" | "),
      }));
      res
        .type("text/csv")
        .set(
          "Content-Disposition",
          "attachment; filename=trusttrace-events.csv",
        )
        .send(
          toCsv(
            rows,
            Object.keys(
              rows[0] ?? {
                id: "",
                createdAt: "",
                actor: "",
                action: "",
                resource: "",
                source: "",
                decision: "",
                riskScore: "",
                reasons: "",
              },
            ),
          ),
        );
    } else res.json({ items: result.items, total: result.total });
  });
  app.get("/api/export/incidents", (req, res) => {
    const result = queryIncidents(db, req);
    if (wantsCsv(req)) {
      const rows = result.items.map((incident) => ({
        id: incident.id,
        eventId: incident.eventId,
        severity: incident.severity,
        status: incident.status,
        title: incident.title,
        summary: incident.summary,
        createdAt: incident.createdAt,
        updatedAt: incident.updatedAt,
      }));
      res
        .type("text/csv")
        .set(
          "Content-Disposition",
          "attachment; filename=trusttrace-incidents.csv",
        )
        .send(
          toCsv(
            rows,
            Object.keys(
              rows[0] ?? {
                id: "",
                eventId: "",
                severity: "",
                status: "",
                title: "",
                summary: "",
                createdAt: "",
                updatedAt: "",
              },
            ),
          ),
        );
    } else res.json({ items: result.items, total: result.total });
  });
  app.get("/api/report", (_req, res) => {
    const summary = db
      .prepare(
        "SELECT decision, COUNT(*) AS count FROM events GROUP BY decision",
      )
      .all() as { decision: string; count: number }[];
    const incidents = db
      .prepare(
        "SELECT status, severity, COUNT(*) AS count FROM incidents GROUP BY status, severity",
      )
      .all();
    const recent = db
      .prepare("SELECT * FROM events ORDER BY id DESC LIMIT 10")
      .all() as Record<string, unknown>[];
    return res.json({
      generatedAt: new Date().toISOString(),
      summary: Object.fromEntries(
        summary.map((row) => [row.decision, row.count]),
      ),
      incidentBreakdown: incidents,
      recentEvents: recent.map(eventFromRow),
      policies: listPolicies(db).length,
    });
  });

  app.use((_req, res) => res.status(404).json({ error: "Not found" }));
  app.use(
    (error: unknown, _req: Request, res: Response, _next: NextFunction) => {
      if (error instanceof ValidationError)
        return res
          .status(error.statusCode)
          .json({ error: error.message, details: error.details });
      if (error instanceof SyntaxError)
        return res.status(400).json({ error: "Invalid JSON body" });
      if (
        error &&
        typeof error === "object" &&
        "code" in error &&
        (error as { code: unknown }).code === "SQLITE_CONSTRAINT_UNIQUE"
      )
        return res.status(409).json({ error: "Policy name already exists" });
      console.error(error);
      return res.status(500).json({ error: "Internal server error" });
    },
  );
  return { app, db, close: () => db.close() };
}

if (require.main === module) {
  const port = Number(process.env.PORT ?? 8787);
  const host = process.env.TRUSTTRACE_HOST ?? "127.0.0.1";
  const { app } = createApp();
  app.listen(port, host, () =>
    console.log(`TrustTrace backend listening on http://${host}:${port}`),
  );
}
