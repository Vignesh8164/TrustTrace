import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api";
import type {
  Decision,
  EventRecord,
  Incident,
  LabRun,
  Policy,
  Report,
  Summary,
} from "./types";

const navItems = [
  { id: "dashboard", label: "Dashboard", icon: "grid" },
  { id: "events", label: "Events", icon: "pulse" },
  { id: "incidents", label: "Incidents", icon: "shield" },
  { id: "policies", label: "Policies", icon: "sliders" },
  { id: "lab", label: "Attack Lab", icon: "flask" },
] as const;
type View = (typeof navItems)[number]["id"];
const labScenarios = [
  {
    id: "normal-authorized",
    name: "Authorized baseline",
    tag: "CONTROL",
    description:
      "A least-privilege analyst reads a permitted synthetic audit resource.",
    expected: "ALLOW",
    signal: "Explicit allow rule",
  },
  {
    id: "unauthorized-access",
    name: "Restricted secret access",
    tag: "DATA LOSS",
    description:
      "An untrusted agent attempts to read synthetic canary credentials.",
    expected: "DENY",
    signal: "Restricted data",
  },
  {
    id: "prompt-injection",
    name: "Prompt injection",
    tag: "AI SECURITY",
    description:
      "An external instruction attempts to override policy checks before a production deploy.",
    expected: "DENY",
    signal: "Instruction override",
  },
  {
    id: "data-exfiltration",
    name: "Data exfiltration",
    tag: "DATA LOSS",
    description:
      "An external webhook exports customer records to an unknown destination.",
    expected: "REVIEW",
    signal: "External sensitive export",
  },
  {
    id: "privilege-escalation",
    name: "Privilege escalation",
    tag: "IDENTITY",
    description:
      "A non-trusted actor requests an administrative role in production.",
    expected: "DENY",
    signal: "Admin role grant",
  },
  {
    id: "destructive-production",
    name: "Destructive production",
    tag: "PRODUCTION",
    description: "A delete operation targets a production orders table.",
    expected: "DENY",
    signal: "Destructive production action",
  },
  {
    id: "repeated-denials",
    name: "Repeated denial sequence",
    tag: "ANOMALY",
    description:
      "Three blocked destructive requests reveal a repeated-denial pattern.",
    expected: "DENY",
    signal: "Repeated denials",
  },
  {
    id: "policy-tampering",
    name: "Policy tampering",
    tag: "CONTROL PLANE",
    description: "An untrusted agent attempts to disable the policy engine.",
    expected: "DENY",
    signal: "Policy tampering",
  },
] as const;

function Icon({ name, size = 18 }: { name: string; size?: number }) {
  const paths: Record<string, React.ReactNode> = {
    grid: (
      <>
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </>
    ),
    pulse: <path d="M3 12h4l2.2-7 4.1 14 2.2-7H21" />,
    shield: (
      <>
        <path d="M12 3 20 6v5c0 5-3.3 8.5-8 10-4.7-1.5-8-5-8-10V6l8-3Z" />
        <path d="m8.5 12 2.2 2.2 4.8-4.8" />
      </>
    ),
    sliders: (
      <>
        <path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h9M17 18h3" />
        <circle cx="15" cy="6" r="2" />
        <circle cx="9" cy="12" r="2" />
        <circle cx="15" cy="18" r="2" />
      </>
    ),
    flask: (
      <>
        <path d="M9 3h6M10 3v6l-5.5 9.2A2 2 0 0 0 6.2 21h11.6a2 2 0 0 0 1.7-2.8L14 9V3" />
        <path d="M7.7 16h8.6" />
      </>
    ),
    arrow: <path d="M5 12h14M13 6l6 6-6 6" />,
    download: (
      <>
        <path d="M12 3v12M7 10l5 5 5-5M5 21h14" />
      </>
    ),
    refresh: (
      <>
        <path d="M20 11a8 8 0 0 0-14.6-3L3 11M3 5v6h6M4 13a8 8 0 0 0 14.6 3L21 13m0 6v-6h-6" />
      </>
    ),
    search: (
      <>
        <circle cx="10.8" cy="10.8" r="6.8" />
        <path d="m16 16 5 5" />
      </>
    ),
    check: <path d="m5 12 4 4L19 6" />,
    x: (
      <>
        <path d="m6 6 12 12M18 6 6 18" />
      </>
    ),
    warning: (
      <>
        <path d="m12 3 9 17H3L12 3Z" />
        <path d="M12 9v4M12 17h.01" />
      </>
    ),
    clock: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l3 2" />
      </>
    ),
    chevron: <path d="m9 18 6-6-6-6" />,
    bolt: <path d="m13 2-9 12h7l-1 8 9-12h-7l1-8Z" />,
    activity: <path d="M3 12h4l2-6 4 12 2-6h6" />,
  };
  return (
    <svg
      aria-hidden="true"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {paths[name] ?? paths.grid}
    </svg>
  );
}
function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }).format(date);
}
function formatCount(value: number | undefined) {
  return (value ?? 0).toLocaleString();
}
function decisionClass(decision: string) {
  return decision.toLowerCase();
}
function riskClass(score: number) {
  return score >= 80
    ? "critical"
    : score >= 55
      ? "high"
      : score >= 25
        ? "medium"
        : "low";
}
function Badge({ children, tone }: { children: string; tone?: string }) {
  return (
    <span className={`badge ${tone ?? children.toLowerCase()}`}>
      {children}
    </span>
  );
}
function EmptyState({ title, message }: { title: string; message: string }) {
  return (
    <div className="empty-state">
      <div className="empty-icon">
        <Icon name="search" size={21} />
      </div>
      <strong>{title}</strong>
      <p>{message}</p>
    </div>
  );
}
function ErrorState({
  message,
  retry,
}: {
  message: string;
  retry: () => void;
}) {
  return (
    <div className="state-card error-state">
      <Icon name="warning" size={22} />
      <div>
        <strong>Could not load this view</strong>
        <p>{message}</p>
      </div>
      <button className="button secondary" onClick={retry}>
        Try again
      </button>
    </div>
  );
}
function SectionHeading({
  eyebrow,
  title,
  children,
}: {
  eyebrow?: string;
  title: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="section-heading">
      <div>
        {eyebrow && <span className="eyebrow">{eyebrow}</span>}
        <h2>{title}</h2>
      </div>
      {children}
    </div>
  );
}
function StatCard({
  label,
  value,
  detail,
  tone,
  icon,
}: {
  label: string;
  value: string | number;
  detail: string;
  tone: string;
  icon: string;
}) {
  return (
    <article className={`stat-card ${tone}`}>
      <div className="stat-top">
        <span>{label}</span>
        <span className="stat-icon">
          <Icon name={icon} size={17} />
        </span>
      </div>
      <strong>{typeof value === "number" ? formatCount(value) : value}</strong>
      <small>{detail}</small>
    </article>
  );
}

export default function App() {
  const [view, setView] = useState<View>(
    () => (window.location.hash.slice(1) as View) || "dashboard",
  );
  const [summary, setSummary] = useState<Summary | null>(null);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [health, setHealth] = useState<{
    status: string;
    uptimeSeconds: number;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const loadData = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [
        healthResult,
        summaryResult,
        eventsResult,
        incidentsResult,
        policiesResult,
        reportResult,
      ] = await Promise.all([
        api.health(),
        api.summary(),
        api.events("?limit=100"),
        api.incidents("?limit=100"),
        api.policies(),
        api.report(),
      ]);
      setHealth(healthResult);
      setSummary(summaryResult);
      setEvents(eventsResult.items);
      setIncidents(incidentsResult.items);
      setPolicies(policiesResult.items);
      setReport(reportResult);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "The TrustTrace API is unavailable.",
      );
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void loadData();
  }, [loadData]);
  useEffect(() => {
    const onHash = () => {
      const next = window.location.hash.slice(1) as View;
      if (navItems.some((item) => item.id === next)) setView(next);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(""), 3600);
    return () => window.clearTimeout(timer);
  }, [toast]);
  const navigate = (next: View) => {
    window.location.hash = next;
    setView(next);
  };
  const updateIncident = async (
    id: number,
    body: { status?: string; resolution?: string },
    message: string,
  ) => {
    try {
      const updated = await api.updateIncident(id, body);
      setIncidents((current) =>
        current.map((item) => (item.id === id ? updated : item)),
      );
      setToast(message);
    } catch (err) {
      setToast(err instanceof Error ? err.message : "Incident update failed");
    }
  };
  if (loading && !summary)
    return (
      <div className="app-shell">
        <aside className="sidebar">
          <Brand />
        </aside>
        <main className="main-content">
          <div className="loading-page">
            <div className="spinner" />
            <p>Connecting to the TrustTrace control plane…</p>
          </div>
        </main>
      </div>
    );
  if (error && !summary)
    return (
      <div className="app-shell">
        <aside className="sidebar">
          <Brand />
        </aside>
        <main className="main-content">
          <ErrorState message={error} retry={() => void loadData()} />
        </main>
      </div>
    );
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Brand />
        <nav aria-label="Primary navigation">
          {navItems.map((item) => (
            <button
              key={item.id}
              className={`nav-item ${view === item.id ? "active" : ""}`}
              onClick={() => navigate(item.id)}
            >
              <Icon name={item.icon} />
              <span>{item.label}</span>
              {item.id === "incidents" && (summary?.openIncidents ?? 0) > 0 && (
                <em>{summary?.openIncidents}</em>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="status-dot" />
            <div>
              <strong>Gateway online</strong>
              <small>API heartbeat healthy</small>
            </div>
          </div>
          <span className="version">TRUSTTRACE / LOCAL</span>
        </div>
      </aside>
      <main className="main-content">
        <header className="topbar">
          <div className="mobile-brand">
            <Brand />
          </div>
          <div className="breadcrumb">
            <span>SECURITY CONTROL PLANE</span>
            <b>/</b>
            <strong>{navItems.find((item) => item.id === view)?.label}</strong>
          </div>
          <div className="top-actions">
            <span className="health-chip">
              <span className="status-dot" />{" "}
              {health?.status === "ok" ? "Operational" : "Degraded"}
            </span>
            <button
              className="icon-button"
              aria-label="Refresh all data"
              onClick={() => void loadData()}
            >
              <Icon name="refresh" />
            </button>
          </div>
        </header>
        {toast && (
          <div className="toast" role="status">
            <Icon name="check" size={16} />
            {toast}
          </div>
        )}
        <div className="page-content">
          {view === "dashboard" && (
            <Dashboard
              summary={summary!}
              incidents={incidents}
              report={report}
              policies={policies}
              navigate={navigate}
            />
          )}
          {view === "events" && <Events events={events} />}
          {view === "incidents" && (
            <Incidents incidents={incidents} onUpdate={updateIncident} />
          )}
          {view === "policies" && (
            <Policies
              policies={policies}
              onCreated={(policy) => {
                setPolicies((current) =>
                  [...current, policy].sort((a, b) => b.priority - a.priority),
                );
                setToast("Policy created and active");
              }}
            />
          )}
          {view === "lab" && (
            <AttackLab
              policies={policies}
              onChanged={() => void loadData()}
              onToast={setToast}
            />
          )}
        </div>
      </main>
    </div>
  );
}
function Brand() {
  return (
    <div className="brand">
      <div className="brand-mark">
        <span />
        <span />
        <span />
      </div>
      <div>
        <strong>
          Trust<span>Trace</span>
        </strong>
        <small>POLICY GATEWAY</small>
      </div>
    </div>
  );
}

function Dashboard({
  summary,
  incidents,
  report,
  policies,
  navigate,
}: {
  summary: Summary;
  incidents: Incident[];
  report: Report | null;
  policies: Policy[];
  navigate: (view: View) => void;
}) {
  const openIncidents = incidents.filter(
    (incident) => incident.status !== "resolved",
  );
  const totalDecisions =
    Object.values(summary.decisions).reduce(
      (total, value) => total + (value ?? 0),
      0,
    ) || 1;
  const decisionRows: { key: Decision; label: string; color: string }[] = [
    { key: "ALLOW", label: "Allowed", color: "green" },
    { key: "REVIEW", label: "Review", color: "amber" },
    { key: "DENY", label: "Denied", color: "red" },
  ];
  return (
    <>
      <div className="hero">
        <div>
          <span className="eyebrow">LIVE SECURITY POSTURE</span>
          <h1>
            Good afternoon, <span>operator.</span>
          </h1>
          <p>
            Monitor policy decisions, investigate incidents, and exercise your
            controls from one place.
          </p>
        </div>
        <div className="hero-actions">
          <a className="button secondary" href="/api/export/events?format=csv">
            <Icon name="download" size={16} /> Export events
          </a>
          <button className="button primary" onClick={() => navigate("lab")}>
            <Icon name="bolt" size={16} /> Run a scenario
          </button>
        </div>
      </div>
      <div className="stats-grid">
        <StatCard
          label="AUDIT EVENTS"
          value={summary.events}
          detail={`${summary.detections} detections recorded`}
          tone="blue"
          icon="pulse"
        />
        <StatCard
          label="OPEN INCIDENTS"
          value={summary.openIncidents}
          detail={`${summary.incidents} total incidents`}
          tone="red"
          icon="shield"
        />
        <StatCard
          label="POLICY COVERAGE"
          value={policies.length}
          detail="active policy rules"
          tone="purple"
          icon="sliders"
        />
        <StatCard
          label="ALLOW RATE"
          value={`${Math.round(((summary.decisions.ALLOW ?? 0) / totalDecisions) * 100)}%`}
          detail={`${summary.decisions.ALLOW ?? 0} permitted decisions`}
          tone="green"
          icon="check"
        />
      </div>
      <div className="dashboard-grid">
        <section className="panel decision-panel">
          <SectionHeading eyebrow="DECISION MIX" title="Policy outcomes" />
          <div className="decision-bars">
            {decisionRows.map((row) => {
              const count = summary.decisions[row.key] ?? 0;
              return (
                <div className="decision-row" key={row.key}>
                  <div className="decision-label">
                    <span className={`mini-dot ${row.color}`} />
                    {row.label}
                    <strong>{count}</strong>
                  </div>
                  <div className="bar-track">
                    <span
                      className={row.color}
                      style={{ width: `${(count / totalDecisions) * 100}%` }}
                    />
                  </div>
                  <small>{Math.round((count / totalDecisions) * 100)}%</small>
                </div>
              );
            })}
          </div>
          <div className="panel-footer">
            <span>All decisions from the audit ledger</span>
            <button className="text-button" onClick={() => navigate("events")}>
              View event stream <Icon name="arrow" size={14} />
            </button>
          </div>
        </section>
        <section className="panel attention-panel">
          <SectionHeading eyebrow="REQUIRES ATTENTION" title="Incident queue">
            <button
              className="text-button"
              onClick={() => navigate("incidents")}
            >
              View all <Icon name="arrow" size={14} />
            </button>
          </SectionHeading>
          {openIncidents.length === 0 ? (
            <EmptyState
              title="No open incidents"
              message="Your operational queue is clear."
            />
          ) : (
            <div className="compact-list">
              {openIncidents.slice(0, 4).map((incident) => (
                <button
                  className="compact-item"
                  key={incident.id}
                  onClick={() => navigate("incidents")}
                >
                  <div className={`severity-mark ${incident.severity}`} />
                  <div className="compact-copy">
                    <strong>{incident.title}</strong>
                    <span>{incident.summary}</span>
                    <small>{formatDate(incident.createdAt)}</small>
                  </div>
                  <Badge tone={incident.severity}>{incident.severity}</Badge>
                </button>
              ))}
            </div>
          )}
        </section>
      </div>
      <section className="panel recent-panel">
        <SectionHeading eyebrow="AUDIT LEDGER" title="Recent activity">
          <button className="text-button" onClick={() => navigate("events")}>
            Open event stream <Icon name="arrow" size={14} />
          </button>
        </SectionHeading>
        {report?.recentEvents?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Decision</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Resource</th>
                  <th>Risk</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {report.recentEvents.slice(0, 5).map((event) => (
                  <tr key={event.id}>
                    <td>
                      <Badge tone={decisionClass(event.decision)}>
                        {event.decision}
                      </Badge>
                    </td>
                    <td>
                      <code>{event.action}</code>
                    </td>
                    <td>{event.actor}</td>
                    <td>{event.resource}</td>
                    <td>
                      <span
                        className={`risk-number ${riskClass(event.riskScore)}`}
                      >
                        {event.riskScore}
                      </span>
                    </td>
                    <td className="muted">{formatDate(event.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No audit activity"
            message="Events will appear here after the gateway evaluates an action."
          />
        )}
      </section>
    </>
  );
}
function PageIntro({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="page-intro">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <div className="page-actions">{actions}</div>
    </div>
  );
}
function Events({ events }: { events: EventRecord[] }) {
  const [decision, setDecision] = useState("ALL");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<number | null>(null);
  const filtered = useMemo(
    () =>
      events.filter(
        (event) =>
          (decision === "ALL" || event.decision === decision) &&
          [event.actor, event.action, event.resource, event.source]
            .join(" ")
            .toLowerCase()
            .includes(search.toLowerCase()),
      ),
    [events, decision, search],
  );
  const current = events.find((event) => event.id === selected);
  return (
    <>
      <PageIntro
        eyebrow="AUDIT LEDGER"
        title="Events"
        description="Every evaluated action, decision, and reason captured at the gateway boundary."
        actions={
          <>
            <a
              className="button secondary"
              href="/api/export/events?format=csv"
            >
              <Icon name="download" size={16} /> Export CSV
            </a>
            <a className="button secondary" href="/api/export/events">
              JSON
            </a>
          </>
        }
      />
      <section className="panel">
        <div className="filter-row">
          <label className="search-field">
            <Icon name="search" size={16} />
            <span className="sr-only">Search events</span>
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search actor, action, resource…"
            />
          </label>
          <label className="select-field">
            <span>Decision</span>
            <select
              value={decision}
              onChange={(event) => setDecision(event.target.value)}
            >
              <option value="ALL">All decisions</option>
              <option value="ALLOW">Allowed</option>
              <option value="REVIEW">Review</option>
              <option value="DENY">Denied</option>
            </select>
          </label>
          <span className="filter-count">
            {filtered.length} of {events.length} events
          </span>
        </div>
        {filtered.length === 0 ? (
          <EmptyState
            title="No events match"
            message="Try a different decision or search term."
          />
        ) : (
          <div className="table-wrap">
            <table className="interactive-table">
              <thead>
                <tr>
                  <th>Decision</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Resource</th>
                  <th>Source</th>
                  <th>Risk</th>
                  <th>Time</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {filtered.map((event) => (
                  <tr
                    key={event.id}
                    className={selected === event.id ? "selected" : ""}
                    onClick={() =>
                      setSelected(selected === event.id ? null : event.id)
                    }
                  >
                    <td>
                      <Badge tone={decisionClass(event.decision)}>
                        {event.decision}
                      </Badge>
                    </td>
                    <td>
                      <code>{event.action}</code>
                    </td>
                    <td>{event.actor}</td>
                    <td>{event.resource}</td>
                    <td className="muted">{event.source}</td>
                    <td>
                      <span
                        className={`risk-number ${riskClass(event.riskScore)}`}
                      >
                        {event.riskScore}
                      </span>
                    </td>
                    <td className="muted">{formatDate(event.createdAt)}</td>
                    <td>
                      <Icon name="chevron" size={15} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {current && (
        <section className="panel event-detail">
          <SectionHeading
            eyebrow={`EVENT #${current.id}`}
            title="Decision context"
          >
            <button
              className="icon-button"
              aria-label="Close event details"
              onClick={() => setSelected(null)}
            >
              <Icon name="x" />
            </button>
          </SectionHeading>
          <div className="detail-grid">
            <div>
              <span className="detail-label">Decision</span>
              <Badge tone={decisionClass(current.decision)}>
                {current.decision}
              </Badge>
            </div>
            <div>
              <span className="detail-label">Risk score</span>
              <strong
                className={`detail-value ${riskClass(current.riskScore)}`}
              >
                {current.riskScore} / 100
              </strong>
            </div>
            <div>
              <span className="detail-label">Policy IDs</span>
              <strong className="detail-value">
                {current.policyIds.length
                  ? current.policyIds.join(", ")
                  : "None"}
              </strong>
            </div>
            <div>
              <span className="detail-label">Metadata</span>
              <code className="metadata">
                {JSON.stringify(current.metadata)}
              </code>
            </div>
          </div>
          <div className="reason-list">
            <span className="detail-label">Evaluation reasons</span>
            {current.reasons.map((reason) => (
              <div key={reason}>
                <Icon name="check" size={14} />
                {reason}
              </div>
            ))}
          </div>
        </section>
      )}
    </>
  );
}

function Incidents({
  incidents,
  onUpdate,
}: {
  incidents: Incident[];
  onUpdate: (
    id: number,
    body: { status?: string; resolution?: string },
    message: string,
  ) => void;
}) {
  const [status, setStatus] = useState("ALL");
  const [severity, setSeverity] = useState("ALL");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [note, setNote] = useState("");
  const filtered = incidents.filter(
    (incident) =>
      (status === "ALL" || incident.status === status) &&
      (severity === "ALL" || incident.severity === severity),
  );
  const selected = incidents.find((incident) => incident.id === selectedId);
  useEffect(() => {
    if (selected) setNote(selected.resolution ?? "");
  }, [selectedId]);
  const saveNote = () => {
    if (!selected || !note.trim()) return;
    onUpdate(selected.id, { resolution: note.trim() }, "Incident note saved");
  };
  return (
    <>
      <PageIntro
        eyebrow="RESPONSE QUEUE"
        title="Incidents"
        description="Investigate non-allow decisions, capture analyst notes, and close the response loop."
        actions={
          <>
            <a
              className="button secondary"
              href="/api/export/incidents?format=csv"
            >
              <Icon name="download" size={16} /> Export CSV
            </a>
            <a className="button secondary" href="/api/report">
              Report JSON
            </a>
          </>
        }
      />
      <div className="split-layout">
        <section className="panel incident-list-panel">
          <div className="filter-row">
            <label className="select-field">
              <span>Status</span>
              <select
                value={status}
                onChange={(event) => setStatus(event.target.value)}
              >
                <option value="ALL">All statuses</option>
                <option value="open">Open</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="resolved">Resolved</option>
              </select>
            </label>
            <label className="select-field">
              <span>Severity</span>
              <select
                value={severity}
                onChange={(event) => setSeverity(event.target.value)}
              >
                <option value="ALL">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </label>
            <span className="filter-count">{filtered.length} incidents</span>
          </div>
          {filtered.length === 0 ? (
            <EmptyState
              title="No incidents match"
              message="Try widening the response queue filters."
            />
          ) : (
            <div className="incident-list">
              {filtered.map((incident) => (
                <button
                  className={`incident-card ${selectedId === incident.id ? "selected" : ""}`}
                  key={incident.id}
                  onClick={() => setSelectedId(incident.id)}
                >
                  <div className={`severity-mark ${incident.severity}`} />
                  <div className="incident-card-copy">
                    <div className="incident-title">
                      <strong>{incident.title}</strong>
                      <Badge tone={incident.severity}>
                        {incident.severity}
                      </Badge>
                    </div>
                    <p>{incident.summary}</p>
                    <small>
                      INC-{String(incident.id).padStart(4, "0")} ·{" "}
                      {formatDate(incident.createdAt)}
                    </small>
                  </div>
                  <Badge tone={incident.status}>{incident.status}</Badge>
                </button>
              ))}
            </div>
          )}
        </section>
        <section className="panel incident-detail-panel">
          {selected ? (
            <>
              <SectionHeading
                eyebrow={`INC-${String(selected.id).padStart(4, "0")}`}
                title="Incident detail"
              >
                <Badge tone={selected.status}>{selected.status}</Badge>
              </SectionHeading>
              <div className="incident-meta">
                <div>
                  <span className="detail-label">Severity</span>
                  <Badge tone={selected.severity}>{selected.severity}</Badge>
                </div>
                <div>
                  <span className="detail-label">Event</span>
                  <strong>#{selected.eventId}</strong>
                </div>
                <div>
                  <span className="detail-label">Created</span>
                  <strong>{formatDate(selected.createdAt)}</strong>
                </div>
              </div>
              <p className="detail-summary">{selected.summary}</p>
              {selected.event && (
                <div className="event-callout">
                  <div className="callout-header">
                    <span>TRIGGERING EVENT</span>
                    <Badge tone={decisionClass(selected.event.decision)}>
                      {selected.event.decision}
                    </Badge>
                  </div>
                  <code>{selected.event.action}</code>
                  <span>
                    {selected.event.actor} → {selected.event.resource}
                  </span>
                  <div className="callout-risk">
                    Risk score{" "}
                    <strong className={riskClass(selected.event.riskScore)}>
                      {selected.event.riskScore}
                    </strong>
                  </div>
                </div>
              )}
              <div className="detection-section">
                <span className="detail-label">
                  Detections ({selected.detections.length})
                </span>
                {selected.detections.map((detection) => (
                  <div className="detection" key={detection.id}>
                    <div
                      className={`mini-dot ${detection.severity === "critical" || detection.severity === "high" ? "red" : "amber"}`}
                    />
                    <div>
                      <strong>{detection.rule}</strong>
                      <p>{detection.signal}</p>
                    </div>
                    <Badge tone={detection.severity}>
                      {detection.severity}
                    </Badge>
                  </div>
                ))}
              </div>
              <label className="textarea-field">
                <span>Resolution note</span>
                <textarea
                  value={note}
                  maxLength={500}
                  onChange={(event) => setNote(event.target.value)}
                  placeholder="Record what you found or how this was resolved…"
                />
                <small>{note.length}/500</small>
              </label>
              <div className="detail-actions">
                {selected.status === "open" && (
                  <button
                    className="button secondary"
                    onClick={() =>
                      onUpdate(
                        selected.id,
                        { status: "acknowledged" },
                        "Incident acknowledged",
                      )
                    }
                  >
                    <Icon name="clock" size={16} /> Acknowledge
                  </button>
                )}
                {selected.status !== "resolved" && (
                  <button
                    className="button primary"
                    onClick={() =>
                      onUpdate(
                        selected.id,
                        { status: "resolved", resolution: note.trim() },
                        "Incident resolved",
                      )
                    }
                  >
                    <Icon name="check" size={16} /> Resolve incident
                  </button>
                )}
                {note.trim() && (
                  <button className="text-button" onClick={saveNote}>
                    Save note
                  </button>
                )}
              </div>
            </>
          ) : (
            <EmptyState
              title="Select an incident"
              message="Choose an item from the response queue to inspect evidence and update status."
            />
          )}
        </section>
      </div>
    </>
  );
}
function Policies({
  policies,
  onCreated,
}: {
  policies: Policy[];
  onCreated: (policy: Policy) => void;
}) {
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [effect, setEffect] = useState<Decision>("REVIEW");
  const [priority, setPriority] = useState("50");
  const [actions, setActions] = useState("");
  const [resourceIncludes, setResourceIncludes] = useState("");
  const [sources, setSources] = useState("");
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setFormError("");
    if (!name.trim()) {
      setFormError("A policy name is required.");
      return;
    }
    const parsedPriority = Number(priority);
    if (
      !Number.isInteger(parsedPriority) ||
      parsedPriority < 0 ||
      parsedPriority > 1000
    ) {
      setFormError("Priority must be a whole number between 0 and 1000.");
      return;
    }
    const match: Record<string, string[]> = {};
    if (actions.trim())
      match.actions = actions
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
    if (resourceIncludes.trim())
      match.resourceIncludes = resourceIncludes
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
    if (sources.trim())
      match.sources = sources
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
    if (!Object.keys(match).length) {
      setFormError("Add at least one matcher so this rule has a scope.");
      return;
    }
    setSaving(true);
    try {
      const created = await api.createPolicy({
        name: name.trim(),
        description: description.trim() || undefined,
        effect,
        priority: parsedPriority,
        match,
      });
      onCreated(created);
      setName("");
      setDescription("");
      setActions("");
      setResourceIncludes("");
      setSources("");
      setShowForm(false);
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : "Policy could not be created.",
      );
    } finally {
      setSaving(false);
    }
  };
  return (
    <>
      <PageIntro
        eyebrow="CONTROL LIBRARY"
        title="Policies"
        description="Deterministic rules that shape every gateway decision, ordered by priority."
        actions={
          <button
            className="button primary"
            onClick={() => setShowForm((current) => !current)}
          >
            <Icon name="sliders" size={16} />{" "}
            {showForm ? "Close form" : "New policy"}
          </button>
        }
      />
      {showForm && (
        <form className="panel policy-form" onSubmit={submit}>
          <SectionHeading eyebrow="NEW CONTROL" title="Create a policy">
            <span className="form-required">* Required</span>
          </SectionHeading>
          <div className="form-grid">
            <label className="field">
              <span>Policy name *</span>
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="e.g. review-finance-export"
                maxLength={100}
              />
            </label>
            <label className="field">
              <span>Effect *</span>
              <select
                value={effect}
                onChange={(event) => setEffect(event.target.value as Decision)}
              >
                <option value="ALLOW">ALLOW</option>
                <option value="REVIEW">REVIEW</option>
                <option value="DENY">DENY</option>
              </select>
            </label>
            <label className="field">
              <span>Priority *</span>
              <input
                type="number"
                min="0"
                max="1000"
                value={priority}
                onChange={(event) => setPriority(event.target.value)}
              />
            </label>
            <label className="field full">
              <span>Description</span>
              <input
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                placeholder="What does this rule protect?"
                maxLength={300}
              />
            </label>
            <label className="field">
              <span>
                Actions <small>(comma separated)</small>
              </span>
              <input
                value={actions}
                onChange={(event) => setActions(event.target.value)}
                placeholder="data.export, data.share"
              />
            </label>
            <label className="field">
              <span>
                Resource includes <small>(comma separated)</small>
              </span>
              <input
                value={resourceIncludes}
                onChange={(event) => setResourceIncludes(event.target.value)}
                placeholder="customer, production"
              />
            </label>
            <label className="field">
              <span>
                Sources <small>(comma separated)</small>
              </span>
              <input
                value={sources}
                onChange={(event) => setSources(event.target.value)}
                placeholder="external, unknown"
              />
            </label>
          </div>
          {formError && (
            <div className="form-error" role="alert">
              <Icon name="warning" size={16} />
              {formError}
            </div>
          )}
          <div className="form-actions">
            <button className="button primary" disabled={saving}>
              {saving ? "Creating…" : "Create policy"}
            </button>
            <button
              type="button"
              className="button secondary"
              onClick={() => setShowForm(false)}
            >
              Cancel
            </button>
          </div>
        </form>
      )}
      <section className="policy-grid">
        {policies.length === 0 ? (
          <div className="panel">
            <EmptyState
              title="No policies configured"
              message="Create the first policy to begin evaluating actions."
            />
          </div>
        ) : (
          policies.map((policy) => (
            <article className="panel policy-card" key={policy.id}>
              <div className="policy-card-top">
                <Badge tone={decisionClass(policy.effect)}>
                  {policy.effect}
                </Badge>
                <span className="priority">Priority {policy.priority}</span>
              </div>
              <h3>{policy.name}</h3>
              <p>{policy.description || "No description provided."}</p>
              <div className="policy-match">
                <span>MATCHES</span>
                {Object.entries(policy.match).map(([key, values]) => (
                  <div key={key}>
                    <b>{key.replace(/([A-Z])/g, " $1").toLowerCase()}</b>
                    <span>{values.join(", ")}</span>
                  </div>
                ))}
              </div>
              <footer>
                <span className={`enabled-dot ${policy.enabled ? "on" : ""}`} />
                {policy.enabled ? "Active" : "Disabled"}
                <small>Added {formatDate(policy.createdAt)}</small>
              </footer>
            </article>
          ))
        )}
      </section>
    </>
  );
}

function AttackLab({
  policies,
  onChanged,
  onToast,
}: {
  policies: Policy[];
  onChanged: () => void;
  onToast: (message: string) => void;
}) {
  const [running, setRunning] = useState("");
  const [result, setResult] = useState<LabRun | null>(null);
  const [customResult, setCustomResult] = useState<{
    decision: string;
    reasons: string[];
    riskScore: number;
    matchedPolicies: { name: string; effect: string; reason: string }[];
  } | null>(null);
  const [custom, setCustom] = useState({
    actor: "operator.manual",
    action: "data.export",
    resource: "customer-records",
    source: "external",
  });
  const run = async (scenario: string) => {
    setRunning(scenario);
    try {
      const next = await api.runLab(scenario);
      setResult(next);
      onChanged();
      onToast(
        `${labScenarios.find((item) => item.id === scenario)?.name} scenario complete`,
      );
    } catch (err) {
      onToast(err instanceof Error ? err.message : "Scenario failed");
    } finally {
      setRunning("");
    }
  };
  const evaluate = async (event: React.FormEvent) => {
    event.preventDefault();
    try {
      const next = await api.evaluate({
        ...custom,
        metadata: { from: "attack-lab", synthetic: true },
      });
      setCustomResult(next);
      onChanged();
      onToast("Custom action evaluated");
    } catch (err) {
      onToast(err instanceof Error ? err.message : "Evaluation failed");
    }
  };
  const activeScenario = result
    ? labScenarios.find((item) => item.id === result.scenario)
    : undefined;
  const event = result?.events[0];
  const policyName = (id: number) =>
    policies.find((policy) => policy.id === id)?.name ?? `Policy #${id}`;
  return (
    <>
      <PageIntro
        eyebrow="CONTROL VALIDATION"
        title="Attack Lab"
        description="Safely exercise the gateway with synthetic threats and compare expected controls with actual enforcement."
        actions={
          <button
            className="button secondary"
            onClick={() => {
              if (
                window.confirm(
                  "Reset all operational events, incidents, and detections back to the seeded baseline?",
                )
              ) {
                void api
                  .resetLab()
                  .then(() => {
                    setResult(null);
                    setCustomResult(null);
                    onChanged();
                    onToast("Lab data reset to baseline");
                  })
                  .catch((err) =>
                    onToast(
                      err instanceof Error ? err.message : "Reset failed",
                    ),
                  );
              }
            }}
          >
            <Icon name="refresh" size={16} /> Reset lab data
          </button>
        }
      />
      <div className="lab-banner">
        <div className="lab-orbit">
          <Icon name="flask" size={25} />
        </div>
        <div>
          <strong>Controlled adversarial testing</strong>
          <p>
            Each scenario creates real audit events and incidents in the local
            SQLite ledger. Reset restores the seeded baseline.
          </p>
        </div>
        <span className="lab-safe">
          <span className="status-dot" /> SAFE MODE
        </span>
      </div>
      <div className="scenario-grid">
        {labScenarios.map((scenario) => (
          <article
            className={`scenario-card ${result?.scenario === scenario.id ? "active" : ""}`}
            key={scenario.id}
          >
            <div className="scenario-top">
              <span className="scenario-tag">{scenario.tag}</span>
              <span className="scenario-number">
                0{labScenarios.indexOf(scenario) + 1}
              </span>
            </div>
            <h3>{scenario.name}</h3>
            <p>{scenario.description}</p>
            <div className="scenario-expected">
              <span>EXPECTED</span>
              <Badge tone={decisionClass(scenario.expected)}>
                {scenario.expected}
              </Badge>
            </div>
            <button
              className="button primary full-width"
              disabled={Boolean(running)}
              onClick={() => void run(scenario.id)}
            >
              {running === scenario.id ? (
                <>
                  <span className="button-spinner" /> Running…
                </>
              ) : (
                <>
                  <Icon name="bolt" size={15} /> Run scenario
                </>
              )}
            </button>
          </article>
        ))}
      </div>
      {activeScenario && event && (
        <section className="panel lab-result">
          <SectionHeading eyebrow="SCENARIO RESULT" title={activeScenario.name}>
            <Badge tone={decisionClass(event.decision)}>{event.decision}</Badge>
          </SectionHeading>
          <div className="comparison">
            <div className="comparison-cell">
              <span>EXPECTED OUTCOME</span>
              <strong>
                <Badge tone={decisionClass(activeScenario.expected)}>
                  {activeScenario.expected}
                </Badge>
              </strong>
              <small>Based on the seeded scenario threat model</small>
            </div>
            <div className="comparison-arrow">
              <Icon name="arrow" size={22} />
            </div>
            <div className="comparison-cell">
              <span>ACTUAL OUTCOME</span>
              <strong>
                <Badge tone={decisionClass(event.decision)}>
                  {event.decision}
                </Badge>
              </strong>
              <small>
                {event.decision === activeScenario.expected
                  ? "Control behaved as expected"
                  : "Control drift detected"}
              </small>
            </div>
          </div>
          <div className="lab-evidence-grid">
            <div className="evidence-block">
              <span className="detail-label">Evidence captured</span>
              <div className="evidence-row">
                <Icon name="activity" size={15} />
                <code>
                  {event.actor} → {event.action}
                </code>
              </div>
              <div className="evidence-row">
                <Icon name="shield" size={15} />
                <span>
                  {event.resource} · {event.source}
                </span>
              </div>
              {event.reasons.map((reason) => (
                <div className="evidence-row" key={reason}>
                  <Icon name="check" size={15} />
                  <span>{reason}</span>
                </div>
              ))}
            </div>
            <div className="evidence-block">
              <span className="detail-label">Risk assessment</span>
              <div className="risk-gauge">
                <strong className={riskClass(event.riskScore)}>
                  {event.riskScore}
                </strong>
                <span>/ 100</span>
              </div>
              <div className="risk-track">
                <span
                  className={riskClass(event.riskScore)}
                  style={{ width: `${event.riskScore}%` }}
                />
              </div>
              <small>Detection signal: {activeScenario.signal}</small>
            </div>
            <div className="evidence-block">
              <span className="detail-label">Matched rules</span>
              {event.policyIds.length ? (
                event.policyIds.map((id) => (
                  <div className="rule-row" key={id}>
                    <span className="rule-icon">
                      <Icon name="shield" size={13} />
                    </span>
                    <span>{policyName(id)}</span>
                  </div>
                ))
              ) : (
                <small>No policy matched; default review applies.</small>
              )}
            </div>
          </div>
        </section>
      )}
      <section className="panel custom-eval">
        <SectionHeading eyebrow="MANUAL TEST" title="Evaluate a custom action">
          <span className="muted">POST /api/events/evaluate</span>
        </SectionHeading>
        <form onSubmit={evaluate} className="custom-grid">
          {(
            [
              ["actor", "Actor"],
              ["action", "Action"],
              ["resource", "Resource"],
              ["source", "Source"],
            ] as const
          ).map(([key, label]) => (
            <label className="field" key={key}>
              <span>{label}</span>
              <input
                value={custom[key]}
                onChange={(event) =>
                  setCustom({ ...custom, [key]: event.target.value })
                }
                required
              />
            </label>
          ))}
          <button className="button primary" type="submit">
            <Icon name="pulse" size={16} /> Evaluate action
          </button>
        </form>
        {customResult && (
          <div className="custom-result">
            <Badge tone={decisionClass(customResult.decision)}>
              {customResult.decision}
            </Badge>
            <span>
              Risk{" "}
              <strong className={riskClass(customResult.riskScore)}>
                {customResult.riskScore}
              </strong>
            </span>
            <span>{customResult.reasons.join(" · ")}</span>
          </div>
        )}
      </section>
    </>
  );
}
