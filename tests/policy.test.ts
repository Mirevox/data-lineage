import { describe, expect, it } from "vitest";
import { ZodError } from "zod";
import { IngressTagger } from "../src/ingress/tagger.js";
import {
  createRoutePolicyHook,
  ResidencyPolicyEngine,
} from "../src/policy/residency.js";
import { ProviderEndpointSchema } from "../src/types.js";
import type { ProviderEndpoint, ResidencyRule } from "../src/types.js";

const rules: ResidencyRule[] = [
  {
    id: "eu-pii-stay",
    description: "EU PII stay",
    tenants: [],
    allowResidencies: ["eu", "onprem"],
    whenDataClasses: ["pii"],
    preferLocal: true,
    denyLeavePerimeter: true,
    priority: 10,
  },
];

const bedrockUs: ProviderEndpoint = {
  providerId: "bedrock",
  modelId: "claude",
  residency: "us",
  endpoint: "https://bedrock.amazonaws.com",
  leavesPerimeter: true,
};

const localEu: ProviderEndpoint = {
  providerId: "local",
  modelId: "llama",
  residency: "onprem",
  endpoint: "local://llama",
  leavesPerimeter: false,
};

describe("ResidencyPolicyEngine", () => {
  it("reroutes PII leaving perimeter to local", () => {
    const engine = new ResidencyPolicyEngine(rules);
    const tag = new IngressTagger().tag({
      tenantId: "t1",
      sourceId: "chat",
      declaredResidency: "eu",
      dataClasses: ["pii"],
    });
    const decision = engine.evaluate({
      tag,
      candidate: bedrockUs,
      alternatives: [localEu],
    });
    expect(decision.decision).toBe("reroute");
    expect(decision.suggestedEndpoint?.providerId).toBe("local");
  });

  it("allows on-prem for PII", () => {
    const engine = new ResidencyPolicyEngine(rules);
    const tag = new IngressTagger().tag({
      tenantId: "t1",
      sourceId: "chat",
      declaredResidency: "eu",
      dataClasses: ["pii"],
    });
    const decision = engine.evaluate({ tag, candidate: localEu });
    expect(decision.decision).toBe("allow");
  });

  it("denies when no alternative matches", () => {
    const engine = new ResidencyPolicyEngine(rules);
    const tag = new IngressTagger().tag({
      tenantId: "t1",
      sourceId: "chat",
      declaredResidency: "eu",
      dataClasses: ["pii"],
    });
    const decision = engine.evaluate({ tag, candidate: bedrockUs, alternatives: [] });
    expect(decision.decision).toBe("require_local");
  });

  it("rejects non-http(s)/local endpoint schemes", () => {
    expect(() =>
      ProviderEndpointSchema.parse({
        ...bedrockUs,
        endpoint: "ftp://evil.example/x",
      }),
    ).toThrow(ZodError);
    expect(() =>
      ProviderEndpointSchema.parse({
        ...bedrockUs,
        endpoint: "javascript:alert(1)",
      }),
    ).toThrow(ZodError);
  });

  it("matches createRoutePolicyHook to engine.evaluate", () => {
    const engine = new ResidencyPolicyEngine(rules);
    const hook = createRoutePolicyHook(engine);
    const tag = new IngressTagger().tag({
      tenantId: "t1",
      sourceId: "chat",
      declaredResidency: "eu",
      dataClasses: ["pii"],
      now: () => new Date("2026-11-20T00:00:00.000Z"),
    });
    const viaEngine = engine.evaluate({
      tag,
      candidate: bedrockUs,
      alternatives: [localEu],
      now: () => new Date("2026-11-20T00:00:00.000Z"),
    });
    const viaHook = hook(tag, bedrockUs, [localEu]);
    expect(viaHook.decision).toBe(viaEngine.decision);
    expect(viaHook.matchedRuleId).toBe(viaEngine.matchedRuleId);
    expect(viaHook.suggestedEndpoint).toEqual(viaEngine.suggestedEndpoint);
  });
});
