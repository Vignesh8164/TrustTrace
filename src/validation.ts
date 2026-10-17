import { ActionInput, DECISIONS, PolicyInput, PolicyMatch } from "./types";

export class ValidationError extends Error {
  statusCode = 400;
  details: string[];
  constructor(details: string[]) {
    super("Request validation failed");
    this.details = details;
  }
}

const text = (value: unknown, field: string, max = 300): string => {
  if (typeof value !== "string" || value.trim().length === 0)
    throw new ValidationError([`${field} must be a non-empty string`]);
  if (value.length > max)
    throw new ValidationError([`${field} must be at most ${max} characters`]);
  return value.trim();
};

const optionalText = (
  value: unknown,
  field: string,
  max = 300,
): string | undefined => {
  if (value === undefined) return undefined;
  return text(value, field, max);
};

const stringArray = (value: unknown, field: string): string[] | undefined => {
  if (value === undefined) return undefined;
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== "string" || item.trim() === "")
  )
    throw new ValidationError([
      `${field} must be an array of non-empty strings`,
    ]);
  return value.map((item) => item.trim()).slice(0, 50);
};

export function parseActionInput(body: unknown): ActionInput {
  if (!body || typeof body !== "object" || Array.isArray(body))
    throw new ValidationError(["body must be an object"]);
  const input = body as Record<string, unknown>;
  const metadata = input.metadata === undefined ? {} : input.metadata;
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata))
    throw new ValidationError(["metadata must be an object"]);
  const timestamp = optionalText(input.timestamp, "timestamp", 80);
  if (timestamp && Number.isNaN(Date.parse(timestamp)))
    throw new ValidationError(["timestamp must be an ISO-8601 date"]);
  const classifications = ["public", "internal", "confidential", "restricted"];
  if (
    input.dataClassification !== undefined &&
    (typeof input.dataClassification !== "string" ||
      !classifications.includes(input.dataClassification))
  )
    throw new ValidationError([
      "dataClassification must be public, internal, confidential, or restricted",
    ]);
  if (
    input.authorizationContext !== undefined &&
    (!input.authorizationContext ||
      typeof input.authorizationContext !== "object" ||
      Array.isArray(input.authorizationContext))
  )
    throw new ValidationError(["authorizationContext must be an object"]);
  return {
    eventId: optionalText(input.eventId, "eventId", 120),
    agentId: optionalText(input.agentId, "agentId", 160),
    sessionId: optionalText(input.sessionId, "sessionId", 160),
    taskId: optionalText(input.taskId, "taskId", 160),
    toolName: optionalText(input.toolName, "toolName", 160),
    operation: optionalText(input.operation, "operation", 160),
    dataClassification:
      input.dataClassification as ActionInput["dataClassification"],
    authorizationContext: input.authorizationContext as
      | Record<string, unknown>
      | undefined,
    parentDelegationId: optionalText(
      input.parentDelegationId,
      "parentDelegationId",
      160,
    ),
    actor: text(input.actor, "actor", 160),
    action: text(input.action, "action", 160),
    resource: text(input.resource, "resource", 300),
    source: optionalText(input.source, "source", 160) ?? "api",
    metadata: metadata as Record<string, unknown>,
    timestamp,
  };
}

export function parsePolicyInput(body: unknown): PolicyInput {
  if (!body || typeof body !== "object" || Array.isArray(body))
    throw new ValidationError(["body must be an object"]);
  const input = body as Record<string, unknown>;
  const effect = text(input.effect, "effect", 10).toUpperCase();
  if (!DECISIONS.includes(effect as (typeof DECISIONS)[number]))
    throw new ValidationError(["effect must be ALLOW, DENY, or REVIEW"]);
  if (
    !input.match ||
    typeof input.match !== "object" ||
    Array.isArray(input.match)
  )
    throw new ValidationError(["match must be an object"]);
  const raw = input.match as Record<string, unknown>;
  const match: PolicyMatch = {
    actions: stringArray(raw.actions, "match.actions"),
    actionPrefixes: stringArray(raw.actionPrefixes, "match.actionPrefixes"),
    resourceIncludes: stringArray(
      raw.resourceIncludes,
      "match.resourceIncludes",
    ),
    sources: stringArray(raw.sources, "match.sources"),
    actors: stringArray(raw.actors, "match.actors"),
  };
  if (!Object.values(match).some((items) => items && items.length > 0))
    throw new ValidationError(["match must include at least one matcher"]);
  const priority = input.priority === undefined ? 50 : input.priority;
  if (
    typeof priority !== "number" ||
    !Number.isInteger(priority) ||
    priority < 0 ||
    priority > 1000
  )
    throw new ValidationError(["priority must be an integer from 0 to 1000"]);
  if (input.enabled !== undefined && typeof input.enabled !== "boolean")
    throw new ValidationError(["enabled must be boolean"]);
  return {
    name: text(input.name, "name", 120),
    description: optionalText(input.description, "description", 500),
    effect: effect as PolicyInput["effect"],
    priority,
    match,
    enabled: input.enabled ?? true,
  };
}

export function parseId(value: string, field = "id"): number {
  if (!/^\d+$/.test(value))
    throw new ValidationError([`${field} must be a positive integer`]);
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id < 1)
    throw new ValidationError([`${field} must be a positive integer`]);
  return id;
}
