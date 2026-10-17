import Database from "better-sqlite3";
import { listPolicies } from "./db";
import {
  ActionInput,
  EvaluationResult,
  Policy,
  PolicyMatchResult,
} from "./types";

function matches(policy: Policy, action: ActionInput): boolean {
  const match = policy.match;
  const exactAction =
    !match.actions ||
    match.actions.length === 0 ||
    match.actions.includes(action.action);
  const prefixAction =
    !match.actionPrefixes ||
    match.actionPrefixes.length === 0 ||
    match.actionPrefixes.some((prefix) => action.action.startsWith(prefix));
  const resource =
    !match.resourceIncludes ||
    match.resourceIncludes.length === 0 ||
    match.resourceIncludes.some((value) =>
      action.resource.toLowerCase().includes(value.toLowerCase()),
    );
  const source =
    !match.sources ||
    match.sources.length === 0 ||
    match.sources.includes(action.source ?? "api");
  const actor =
    !match.actors ||
    match.actors.length === 0 ||
    match.actors.includes(action.actor);
  return exactAction && prefixAction && resource && source && actor;
}

function reason(policy: Policy): string {
  return `${policy.name} (${policy.effect})`;
}

export function evaluate(
  db: Database.Database,
  action: ActionInput,
): EvaluationResult {
  const matchedPolicies: PolicyMatchResult[] = listPolicies(db)
    .filter((policy) => policy.enabled && matches(policy, action))
    .sort((a, b) => b.priority - a.priority || a.id - b.id)
    .map((policy) => ({ policy, reason: reason(policy) }));
  const decision = matchedPolicies.some(
    ({ policy }) => policy.effect === "DENY",
  )
    ? "DENY"
    : matchedPolicies.some(({ policy }) => policy.effect === "REVIEW")
      ? "REVIEW"
      : matchedPolicies.some(({ policy }) => policy.effect === "ALLOW")
        ? "ALLOW"
        : "REVIEW";
  const reasons =
    matchedPolicies.length > 0
      ? matchedPolicies.map((match) => match.reason)
      : ["No matching policy; default REVIEW"];
  if (decision === "DENY") reasons.unshift("Deny precedence applied");
  const riskScore = decision === "DENY" ? 90 : decision === "REVIEW" ? 60 : 10;
  return { decision, reasons, matchedPolicies, riskScore };
}
