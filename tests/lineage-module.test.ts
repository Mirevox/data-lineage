import { describe, expect, it } from "vitest";
import { DataLineageModule } from "../src/module.js";
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

const local: ProviderEndpoint = {
  providerId: "local",
  modelId: "llama",
  residency: "onprem",
  endpoint: "local://llama",
  leavesPerimeter: false,
};

const cloudUs: ProviderEndpoint = {
  providerId: "openai",
  modelId: "gpt",
  residency: "us",
  endpoint: "https://api.openai.com/v1",
  leavesPerimeter: true,
};

describe("DataLineageModule", () => {
  it("traces allow path and issues within-perimeter proof", () => {
    const mod = new DataLineageModule(rules);
    const result = mod.traceRequest({
      tenantId: "acme",
      sourceId: "vscode",
      declaredResidency: "eu",
      dataClasses: ["pii"],
      payload: "hello",
      candidate: local,
    });
    expect(result.decision.decision).toBe("allow");
    expect(result.proof.claimLevel).toBe("software_attested");
    expect(result.proof.withinPerimeter).toBe(true);
    expect(result.graph.edges.length).toBeGreaterThan(0);
    expect(result.proof.digest).toMatch(/^sha256:/);
  });

  it("marks egress leaving perimeter when allow + external", () => {
    const mod = new DataLineageModule([]);
    const result = mod.traceRequest({
      tenantId: "acme",
      sourceId: "chat",
      declaredResidency: "us",
      dataClasses: ["public"],
      candidate: cloudUs,
    });
    expect(result.decision.decision).toBe("allow");
    expect(result.proof.withinPerimeter).toBe(false);
    expect(result.proof.egressHops.some((h) => h.leavesPerimeter)).toBe(true);
  });

  it("keeps denied traffic within perimeter in the proof", () => {
    const mod = new DataLineageModule(rules);
    const result = mod.traceRequest({
      tenantId: "acme",
      sourceId: "chat",
      declaredResidency: "eu",
      dataClasses: ["pii"],
      candidate: cloudUs,
    });
    expect(["deny", "require_local", "reroute"]).toContain(result.decision.decision);
    expect(result.proof.withinPerimeter).toBe(true);
  });
});
