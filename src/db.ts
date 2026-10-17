import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import { Policy, PolicyInput } from "./types";

export function nowIso(): string {
  return new Date().toISOString();
}

export function openDatabase(filename: string): Database.Database {
  if (filename !== ":memory:")
    fs.mkdirSync(path.dirname(path.resolve(filename)), { recursive: true });
  const db = new Database(filename);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(`
    CREATE TABLE IF NOT EXISTS policies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      description TEXT,
      effect TEXT NOT NULL CHECK (effect IN ('ALLOW', 'DENY', 'REVIEW')),
      priority INTEGER NOT NULL DEFAULT 50,
      match_json TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT NOT NULL,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      resource TEXT NOT NULL,
      source TEXT NOT NULL,
      metadata_json TEXT NOT NULL,
      decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'REVIEW')),
      reasons_json TEXT NOT NULL,
      policy_ids_json TEXT NOT NULL,
      risk_score INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
      severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
      status TEXT NOT NULL CHECK (status IN ('open', 'acknowledged', 'resolved')),
      title TEXT NOT NULL,
      summary TEXT NOT NULL,
      resolution TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS detections (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
      rule TEXT NOT NULL,
      signal TEXT NOT NULL,
      severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision);
    CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
    CREATE INDEX IF NOT EXISTS idx_detections_event ON detections(event_id);
  `);
  return db;
}

export function policyFromRow(row: Record<string, unknown>): Policy {
  return {
    id: Number(row.id),
    name: String(row.name),
    description: row.description ? String(row.description) : undefined,
    effect: row.effect as Policy["effect"],
    priority: Number(row.priority),
    match: JSON.parse(String(row.match_json)),
    enabled: Boolean(row.enabled),
    createdAt: String(row.created_at),
  };
}

export function listPolicies(db: Database.Database): Policy[] {
  const rows = db
    .prepare("SELECT * FROM policies ORDER BY priority DESC, id ASC")
    .all() as Record<string, unknown>[];
  return rows.map(policyFromRow);
}

export function insertPolicy(
  db: Database.Database,
  input: PolicyInput,
): Policy {
  const createdAt = nowIso();
  const result = db
    .prepare(
      `INSERT INTO policies (name, description, effect, priority, match_json, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      input.name,
      input.description ?? null,
      input.effect,
      input.priority ?? 50,
      JSON.stringify(input.match),
      input.enabled === false ? 0 : 1,
      createdAt,
    );
  const row = db
    .prepare("SELECT * FROM policies WHERE id = ?")
    .get(Number(result.lastInsertRowid)) as Record<string, unknown>;
  return policyFromRow(row);
}

export function clearOperationalData(db: Database.Database): void {
  db.exec("DELETE FROM detections; DELETE FROM incidents; DELETE FROM events;");
}

export function seedPolicies(db: Database.Database): void {
  const seeds: PolicyInput[] = [
    {
      name: "deny-production-destructive",
      description: "Block destructive actions against production resources.",
      effect: "DENY",
      priority: 100,
      match: {
        actions: [
          "database.delete",
          "filesystem.delete",
          "deployment.rollback",
        ],
        resourceIncludes: ["production"],
      },
    },
    {
      name: "deny-privilege-escalation",
      description: "Block role grants to administrative production identities.",
      effect: "DENY",
      priority: 95,
      match: {
        actions: ["iam.role.grant", "iam.permission.add"],
        resourceIncludes: ["admin", "production"],
      },
    },
    {
      name: "deny-secret-access",
      description: "Block direct access to secrets and credentials.",
      effect: "DENY",
      priority: 90,
      match: {
        actions: ["secret.read", "secret.export"],
        resourceIncludes: ["secret", "credential", "token"],
      },
    },
    {
      name: "deny-policy-tampering",
      description: "Block attempts to alter the security control plane.",
      effect: "DENY",
      priority: 110,
      match: { actionPrefixes: ["policy.", "security.policy."] },
    },
    {
      name: "review-external-export",
      description: "Route exports outside the trusted workspace for review.",
      effect: "REVIEW",
      priority: 60,
      match: {
        actions: ["data.export"],
        sources: ["external", "external-webhook", "unknown"],
      },
    },
    {
      name: "review-sensitive-data",
      description: "Review exports containing sensitive records.",
      effect: "REVIEW",
      priority: 55,
      match: {
        actions: ["data.export"],
        resourceIncludes: ["customer", "pii", "sensitive"],
      },
    },
    {
      name: "allow-read-only",
      description: "Allow low-risk read operations.",
      effect: "ALLOW",
      priority: 10,
      match: { actionPrefixes: ["data.read", "repo.read", "status.read"] },
    },
  ];
  const insert = db.prepare(
    `INSERT OR IGNORE INTO policies (name, description, effect, priority, match_json, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
  );
  const transaction = db.transaction(() => {
    for (const policy of seeds)
      insert.run(
        policy.name,
        policy.description ?? null,
        policy.effect,
        policy.priority,
        JSON.stringify(policy.match),
        1,
        nowIso(),
      );
  });
  transaction();
}
