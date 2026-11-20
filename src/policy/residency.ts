import {
  ProviderEndpointSchema,
  ResidencyRuleSchema,
  RouteDecisionSchema,
  type IngressTag,
  type ProviderEndpoint,
  type ResidencyRule,
  type RouteDecision,
} from "../types.js";

export interface EvaluateRouteInput {
  tag: IngressTag;
  candidate: ProviderEndpoint;
  /** Optional alternate endpoints for reroute suggestions. */
  alternatives?: ProviderEndpoint[];
  now?: () => Date;
}

/**
 * Residency-aware route policy hooks for a smart-router.
 * Pure evaluation: callers enforce the decision before egress.
 */
export class ResidencyPolicyEngine {
  private rules: ResidencyRule[];

  constructor(rules: ResidencyRule[] = []) {
    this.rules = rules
      .map((r) => ResidencyRuleSchema.parse(r))
      .sort((a, b) => a.priority - b.priority);
  }

  listRules(): ResidencyRule[] {
    return [...this.rules];
  }

  replaceRules(rules: ResidencyRule[]): void {
    this.rules = rules
      .map((r) => ResidencyRuleSchema.parse(r))
      .sort((a, b) => a.priority - b.priority);
  }

  evaluate(input: EvaluateRouteInput): RouteDecision {
    const candidate = ProviderEndpointSchema.parse(input.candidate);
    const alternatives = (input.alternatives ?? []).map((e) =>
      ProviderEndpointSchema.parse(e),
    );
    const now = (input.now?.() ?? new Date()).toISOString();
    const applicable = this.rules.filter((rule) => matchesRule(rule, input.tag));

    if (applicable.length === 0) {
      return RouteDecisionSchema.parse({
        decision: "allow",
        reason: "No residency rules matched; default allow.",
        blockedResidencies: [],
        evaluatedAt: now,
      });
    }

    for (const rule of applicable) {
      if (rule.denyLeavePerimeter && candidate.leavesPerimeter) {
        const local = alternatives.find(
          (a) => !a.leavesPerimeter && rule.allowResidencies.includes(a.residency),
        );
        if (local) {
          return RouteDecisionSchema.parse({
            decision: "reroute",
            reason: `Rule ${rule.id}: destination leaves perimeter; suggest local.`,
            matchedRuleId: rule.id,
            suggestedEndpoint: local,
            blockedResidencies: [candidate.residency],
            evaluatedAt: now,
          });
        }
        return RouteDecisionSchema.parse({
          decision: "require_local",
          reason: `Rule ${rule.id}: destination leaves perimeter; no local alternative.`,
          matchedRuleId: rule.id,
          blockedResidencies: [candidate.residency],
          evaluatedAt: now,
        });
      }

      if (!rule.allowResidencies.includes(candidate.residency)) {
        const alt = alternatives.find((a) =>
          rule.allowResidencies.includes(a.residency),
        );
        if (alt) {
          return RouteDecisionSchema.parse({
            decision: "reroute",
            reason: `Rule ${rule.id}: ${candidate.residency} not in allow list ${rule.allowResidencies.join(",")}.`,
            matchedRuleId: rule.id,
            suggestedEndpoint: alt,
            blockedResidencies: [candidate.residency],
            evaluatedAt: now,
          });
        }
        return RouteDecisionSchema.parse({
          decision: "deny",
          reason: `Rule ${rule.id}: residency ${candidate.residency} not allowed; no alternative.`,
          matchedRuleId: rule.id,
          blockedResidencies: [candidate.residency],
          evaluatedAt: now,
        });
      }

      if (rule.preferLocal && candidate.leavesPerimeter) {
        const local = alternatives.find(
          (a) =>
            !a.leavesPerimeter && rule.allowResidencies.includes(a.residency),
        );
        if (local) {
          return RouteDecisionSchema.parse({
            decision: "reroute",
            reason: `Rule ${rule.id}: prefer local; candidate leaves perimeter.`,
            matchedRuleId: rule.id,
            suggestedEndpoint: local,
            blockedResidencies: [],
            evaluatedAt: now,
          });
        }
      }
    }

    const last = applicable[applicable.length - 1];
    return RouteDecisionSchema.parse({
      decision: "allow",
      reason: `Matched ${applicable.length} rule(s); candidate permitted.`,
      matchedRuleId: last?.id,
      blockedResidencies: [],
      evaluatedAt: now,
    });
  }
}

function matchesRule(rule: ResidencyRule, tag: IngressTag): boolean {
  if (rule.tenants.length > 0 && !rule.tenants.includes(tag.tenantId)) {
    return false;
  }
  if (rule.whenDataClasses.length === 0) {
    return true;
  }
  return rule.whenDataClasses.some((c) => tag.dataClasses.includes(c));
}

/** Convenience hook signature routers can call mid-pipeline. */
export type RoutePolicyHook = (
  tag: IngressTag,
  candidate: ProviderEndpoint,
  alternatives?: ProviderEndpoint[],
) => RouteDecision;

export function createRoutePolicyHook(
  engine: ResidencyPolicyEngine,
): RoutePolicyHook {
  return (tag, candidate, alternatives) =>
    engine.evaluate({ tag, candidate, alternatives });
}
