# TrustTrace backend note

The backend is a loopback-safe Express service backed by SQLite (`better-sqlite3`). It creates its database at `TRUSTTRACE_DB_PATH` (default `data/trusttrace.db`), seeds synthetic policies and baseline audit events once, and keeps every evaluation as an immutable event record with the matched policy IDs and reasons captured at decision time.

## Policy behavior

Policies have typed `ALLOW`, `DENY`, or `REVIEW` effects and deterministic priority ordering. All matcher groups supplied on a policy (`actions`, `actionPrefixes`, `resourceIncludes`, `sources`, and `actors`) must match. A matching `DENY` always wins, then `REVIEW`, then `ALLOW`; an action with no match defaults to `REVIEW`. Non-allow decisions create an incident and detection record.

## Run locally

```sh
npm ci
npm run typecheck
npm test
TRUSTTRACE_HOST=127.0.0.1 npm start
```

The service listens on `127.0.0.1:8787` by default. Lab scenarios are `prompt-injection`, `data-exfiltration`, `privilege-escalation`, and `destructive-production`. Export routes return JSON by default and CSV with `?format=csv`.
