import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import request from "supertest";
import { createApp } from "../src/server";

let tempDir: string;
let dbPath: string;
let service: ReturnType<typeof createApp>;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "trusttrace-test-"));
  dbPath = path.join(tempDir, "trusttrace.db");
  service = createApp({ dbPath });
});
afterEach(() => {
  service.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

describe("TrustTrace backend contract", () => {
  it("reports health and baseline synthetic data", async () => {
    const health = await request(service.app).get("/api/health").expect(200);
    assert.equal(health.body.status, "ok");
    assert.equal(health.headers["x-content-type-options"], "nosniff");
    const summary = await request(service.app).get("/api/summary").expect(200);
    assert.equal(summary.body.events, 3);
    assert.equal(summary.body.incidents, 2);
    assert.equal(summary.body.decisions.ALLOW, 1);
    assert.equal(summary.body.decisions.DENY, 1);
    assert.equal(summary.body.decisions.REVIEW, 1);
  });

  it("evaluates actions with deny precedence and creates an audit incident", async () => {
    await request(service.app)
      .post("/api/policies")
      .send({
        name: "test-allow-delete",
        effect: "ALLOW",
        priority: 999,
        match: { actions: ["database.delete"] },
      })
      .expect(201);
    const response = await request(service.app)
      .post("/api/events/evaluate")
      .send({
        actor: "test.user",
        action: "database.delete",
        resource: "production/payments",
        source: "internal",
        metadata: { synthetic: true },
      })
      .expect(201);
    assert.equal(response.body.decision, "DENY");
    assert.ok(response.body.reasons.includes("Deny precedence applied"));
    assert.ok(response.body.incidentId);
    const events = await request(service.app)
      .get("/api/events?decision=DENY")
      .expect(200);
    assert.equal(events.body.total, 2);
    const incidents = await request(service.app)
      .get("/api/incidents?status=open")
      .expect(200);
    assert.equal(incidents.body.total, 3);
  });

  it("persists historical decisions across a database restart", async () => {
    const evaluated = await request(service.app)
      .post("/api/events/evaluate")
      .send({
        actor: "persist.user",
        action: "status.read",
        resource: "service/health",
      })
      .expect(201);
    const eventId = evaluated.body.event.id;
    service.close();
    service = createApp({ dbPath });
    const event = await request(service.app)
      .get(`/api/events?actor=persist.user`)
      .expect(200);
    assert.equal(event.body.total, 1);
    assert.equal(event.body.items[0].id, eventId);
    assert.equal(event.body.items[0].decision, "ALLOW");
  });

  it("validates input, updates incidents, and exports JSON/CSV", async () => {
    const bad = await request(service.app)
      .post("/api/events/evaluate")
      .send({ actor: "", action: "data.read" })
      .expect(400);
    assert.match(bad.body.error, /validation/i);
    const incident = (
      await request(service.app).get("/api/incidents").expect(200)
    ).body.items[0];
    const updated = await request(service.app)
      .patch(`/api/incidents/${incident.id}`)
      .send({ status: "resolved", resolution: "Synthetic test complete" })
      .expect(200);
    assert.equal(updated.body.status, "resolved");
    const csv = await request(service.app)
      .get("/api/export/events?format=csv")
      .expect(200);
    assert.match(csv.headers["content-type"], /text\/csv/);
    assert.match(csv.text, /decision/);
    const json = await request(service.app)
      .get("/api/export/incidents?format=json")
      .expect(200);
    assert.equal(json.body.items.length, 2);
  });

  it("runs and resets Attack Lab scenarios", async () => {
    const authorized = await request(service.app)
      .post("/api/lab/normal-authorized/run")
      .expect(201);
    assert.deepEqual(authorized.body.decisions, ["ALLOW"]);
    const unauthorized = await request(service.app)
      .post("/api/lab/unauthorized-access/run")
      .expect(201);
    assert.deepEqual(unauthorized.body.decisions, ["DENY"]);
    const run = await request(service.app)
      .post("/api/lab/privilege-escalation/run")
      .expect(201);
    assert.deepEqual(run.body.decisions, ["DENY"]);
    const prompt = await request(service.app)
      .post("/api/lab/prompt-injection/run")
      .expect(201);
    assert.equal(prompt.body.events.length, 1);
    const repeated = await request(service.app)
      .post("/api/lab/repeated-denials/run")
      .expect(201);
    assert.deepEqual(repeated.body.decisions, ["DENY", "DENY", "DENY"]);
    const tamper = await request(service.app)
      .post("/api/lab/policy-tampering/run")
      .expect(201);
    assert.deepEqual(tamper.body.decisions, ["DENY"]);
    const detections = await request(service.app)
      .get("/api/summary")
      .expect(200);
    assert.ok(detections.body.detections >= 4);
    const reset = await request(service.app).post("/api/lab/reset").expect(200);
    assert.equal(reset.body.status, "reset");
    const summary = await request(service.app).get("/api/summary").expect(200);
    assert.equal(summary.body.events, 3);
  });
});
