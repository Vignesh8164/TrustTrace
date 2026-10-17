import type {
  ApiEnvelope,
  EventRecord,
  Incident,
  LabRun,
  Policy,
  Report,
  Summary,
} from "./types";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...options?.headers },
  });
  const payload = (await response.json().catch(() => null)) as
    | { error?: string; details?: string[] }
    | T
    | null;
  if (!response.ok) {
    const error =
      payload && typeof payload === "object" && "error" in payload
        ? payload.error
        : undefined;
    throw new Error(error || `Request failed (${response.status})`);
  }
  return payload as T;
}

export const api = {
  health: () =>
    request<{ status: string; service: string; uptimeSeconds: number }>(
      "/api/health",
    ),
  summary: () => request<Summary>("/api/summary"),
  events: (query = "") =>
    request<ApiEnvelope<EventRecord>>(`/api/events${query}`),
  incidents: (query = "") =>
    request<ApiEnvelope<Incident>>(`/api/incidents${query}`),
  policies: () => request<ApiEnvelope<Policy>>("/api/policies"),
  report: () => request<Report>("/api/report"),
  updateIncident: (
    id: number,
    body: { status?: string; resolution?: string },
  ) =>
    request<Incident>(`/api/incidents/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  createPolicy: (body: unknown) =>
    request<Policy>("/api/policies", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  evaluate: (body: unknown) =>
    request<{
      event: EventRecord;
      decision: string;
      reasons: string[];
      riskScore: number;
      matchedPolicies: {
        id: number;
        name: string;
        effect: string;
        priority: number;
        reason: string;
      }[];
      incidentId: number | null;
    }>("/api/events/evaluate", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  runLab: (scenario: string) =>
    request<LabRun>(`/api/lab/${scenario}/run`, { method: "POST" }),
  resetLab: () =>
    request<{ status: string; summary: { events: number; incidents: number } }>(
      "/api/lab/reset",
      { method: "POST" },
    ),
};
