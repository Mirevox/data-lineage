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

interface EndpointFit {
  ok: boolean;
  /** Why it failed the first blocking rule, if any. */
  blockReason?: string;
  blockedResidency?: ProviderEndpoint["residency"];
  /** True when failure is specifically "leaves perimeter" under denyLeavePerimeter. */
  perimeterBlock?: boolean;
  matchedRuleId?: string;
}

/**
 * Residency-aware route policy hooks for a smart-router.
 * Pure evaluation: callers enforce the decision before egress.
 *
 * Multi-rule soundness: a reroute suggestion must satisfy *all* applicable rules.
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

    const candidateFit = fitsAllRules(candidate, applicable, { preferLocalSoft: true });
    if (candidateFit.ok) {
      return RouteDecisionSchema.parse({
        decision: "allow",
        reason: `Matched ${applicable.length} rule(s); candidate permitted.`,
        matchedRuleId: applicable[applicable.length - 1]?.id,
        blockedResidencies: [],
        evaluatedAt: now,
      });
    }

    // Prefer an alternative that hard-satisfies every applicable rule
    // (including preferLocal / denyLeavePerimeter).
    const hardAlt = alternatives.find(
      (a) => fitsAllRules(a, applicable, { preferLocalSoft: false }).ok,
    );
    if (hardAlt) {
      return RouteDecisionSchema.parse({
        decision: "reroute",
        reason:
          candidateFit.blockReason ??
          "Candidate rejected; suggesting alternative that satisfies all rules.",
        matchedRuleId: candidateFit.matchedRuleId,
        suggestedEndpoint: hardAlt,
        blockedResidencies: candidateFit.blockedResidency
          ? [candidateFit.blockedResidency]
          : [],
        evaluatedAt: now,
      });
    }

    if (candidateFit.perimeterBlock) {
      return RouteDecisionSchema.parse({
        decision: "require_local",
        reason:
          candidateFit.blockReason ??
          "Candidate leaves perimeter; no compliant local alternative.",
        matchedRuleId: candidateFit.matchedRuleId,
        blockedResidencies: candidateFit.blockedResidency
          ? [candidateFit.blockedResidency]
          : [],
        evaluatedAt: now,
      });
    }

    return RouteDecisionSchema.parse({
      decision: "deny",
      reason:
        candidateFit.blockReason ??
        "Candidate residency not allowed; no compliant alternative.",
      matchedRuleId: candidateFit.matchedRuleId,
      blockedResidencies: candidateFit.blockedResidency
        ? [candidateFit.blockedResidency]
        : [],
      evaluatedAt: now,
    });
  }
}

/**
 * @param preferLocalSoft When true, preferLocal violations do not hard-fail
 *   (used when checking the original candidate so we can still allow if no
 *   local alternative exists). When false, preferLocal is a hard constraint
 *   for suggested alternatives.
 */
function fitsAllRules(
  endpoint: ProviderEndpoint,
  rules: ResidencyRule[],
  opts: { preferLocalSoft: boolean },
): EndpointFit {
  for (const rule of rules) {
    // Perimeter checks before residency allow-list so denyLeavePerimeter
    // yields require_local (not deny) when no compliant alternative exists.
    if (rule.denyLeavePerimeter && endpoint.leavesPerimeter) {
      return {
        ok: false,
        blockReason: `Rule ${rule.id}: destination leaves perimeter.`,
        blockedResidency: endpoint.residency,
        matchedRuleId: rule.id,
        perimeterBlock: true,
      };
    }
    if (!rule.allowResidencies.includes(endpoint.residency)) {
      return {
        ok: false,
        blockReason: `Rule ${rule.id}: residency ${endpoint.residency} not in allow list ${rule.allowResidencies.join(",")}.`,
        blockedResidency: endpoint.residency,
        matchedRuleId: rule.id,
        perimeterBlock: false,
      };
    }
    if (rule.preferLocal && endpoint.leavesPerimeter && !opts.preferLocalSoft) {
      return {
        ok: false,
        blockReason: `Rule ${rule.id}: prefer local; endpoint leaves perimeter.`,
        blockedResidency: endpoint.residency,
        matchedRuleId: rule.id,
        perimeterBlock: true,
      };
    }
  }
  return { ok: true };
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
