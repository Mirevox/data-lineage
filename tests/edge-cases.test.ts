import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ZodError } from "zod";
import { LineageGraph } from "../src/graph/lineage.js";
import { IngressTagger, parseIngressTag } from "../src/ingress/tagger.js";
import { DataLineageModule } from "../src/module.js";
import { createRoutePolicyHook, ResidencyPolicyEngine } from "../src/policy/residency.js";
import { PerimeterProver } from "../src/prove/perimeter.js";
import {
  DataClassSchema,
  IngressTagSchema,
  LineageEdgeSchema,
  LineageNodeSchema,
  PerimeterProofSchema,
  ProviderEndpointSchema,
  ResidencyRegionSchema,
  ResidencyRuleSchema,
  RouteDecisionSchema,
  type DataClass,
  type IngressTag,
  type LineageGraphSnapshot,
  type PerimeterProof,
  type ProviderEndpoint,
  type ResidencyRule,
  type RouteDecision,
} from "../src/types.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function loadConfigRules(): ResidencyRule[] {
  const raw: unknown = JSON.parse(
    readFileSync(resolve(root, "config/residency-rules.json"), "utf8"),
  );
  if (!Array.isArray(raw)) {
    throw new Error("config/residency-rules.json must be an array");
  }
  return raw.map((rule) => ResidencyRuleSchema.parse(rule));
}

const configRules = loadConfigRules();

const cloudUs: ProviderEndpoint = {
  providerId: "openai",
  modelId: "gpt",
  residency: "us",
  endpoint: "https://api.openai.com/v1",
  leavesPerimeter: true,
};

const cloudEu: ProviderEndpoint = {
  providerId: "mistral",
  modelId: "large",
  residency: "eu",
  endpoint: "https://eu.example.com/v1",
  leavesPerimeter: true,
};

const cloudCa: ProviderEndpoint = {
  providerId: "azure",
  modelId: "gpt",
  residency: "ca",
  endpoint: "https://ca.example.com/v1",
  leavesPerimeter: true,
};

const localOnprem: ProviderEndpoint = {
  providerId: "local",
  modelId: "llama",
  residency: "onprem",
  endpoint: "local://llama",
  leavesPerimeter: false,
};

const localEu: ProviderEndpoint = {
  providerId: "local-eu",
  modelId: "llama",
  residency: "eu",
  endpoint: "local://eu-llama",
  leavesPerimeter: false,
};

const localCa: ProviderEndpoint = {
  providerId: "local-ca",
  modelId: "llama",
  residency: "ca",
  endpoint: "local://ca-llama",
  leavesPerimeter: false,
};

const globalInside: ProviderEndpoint = {
  providerId: "global-box",
  modelId: "x",
  residency: "global",
  endpoint: "local://global",
  leavesPerimeter: false,
};

const fixedNow = () => new Date("2026-03-01T00:00:00.000Z");

function tagFor(
  tenantId: string,
  dataClasses: DataClass[],
  correlationId = "corr-policy",
): IngressTag {
  return new IngressTagger().tag({
    tenantId,
    sourceId: "chat",
    declaredResidency: "eu",
    dataClasses,
    correlationId,
    now: fixedNow,
  });
}

function decide(
  engine: ResidencyPolicyEngine,
  tenantId: string,
  dataClasses: DataClass[],
  candidate: ProviderEndpoint,
  alternatives: ProviderEndpoint[] = [],
): RouteDecision {
  return engine.evaluate({
    tag: tagFor(tenantId, dataClasses),
    candidate,
    alternatives,
    now: fixedNow,
  });
}

function endpointIds(snap: LineageGraphSnapshot): Set<string> {
  const ids = new Set<string>();
  for (const edge of snap.edges) {
    ids.add(edge.from);
    ids.add(edge.to);
  }
  return ids;
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      out[key] = sortKeys(obj[key]);
    }
    return out;
  }
  return value;
}

function reverseKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reverseKeys);
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).reverse()) {
      out[key] = reverseKeys(obj[key]);
    }
    return out;
  }
  return value;
}

function canonicalDigest(body: unknown): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(sortKeys(body))).digest("hex")}`;
}

describe("tenant-scoped rules (tenant-acme-ca)", () => {
  const engine = new ResidencyPolicyEngine(configRules);

  it("loads the shipped rules sorted by priority", () => {
    expect(configRules.map((rule) => rule.id)).toEqual([
      "eu-pii-stay",
      "secrets-local",
      "tenant-acme-ca",
    ]);
    const reversed = new ResidencyPolicyEngine([...configRules].reverse());
    expect(reversed.listRules().map((rule) => rule.id)).toEqual([
      "eu-pii-stay",
      "secrets-local",
      "tenant-acme-ca",
    ]);
    const listed = engine.listRules();
    listed.pop();
    expect(engine.listRules().map((rule) => rule.id)).toEqual([
      "eu-pii-stay",
      "secrets-local",
      "tenant-acme-ca",
    ]);
  });

  it("denies tenant acme outside ca/onprem", () => {
    const decision = decide(engine, "acme", ["internal"], cloudUs);
    expect(decision).toMatchObject({
      decision: "deny",
      matchedRuleId: "tenant-acme-ca",
      reason: "Rule tenant-acme-ca: residency us not in allow list ca,onprem.",
      blockedResidencies: ["us"],
      evaluatedAt: "2026-03-01T00:00:00.000Z",
    });
    expect(decision.suggestedEndpoint).toBeUndefined();
  });

  it("reroutes tenant acme to the first ca/onprem alternative", () => {
    const decision = decide(engine, "acme", ["internal"], cloudUs, [cloudEu, localCa]);
    expect(decision).toMatchObject({
      decision: "reroute",
      matchedRuleId: "tenant-acme-ca",
      reason: "Rule tenant-acme-ca: residency us not in allow list ca,onprem.",
      blockedResidencies: ["us"],
      suggestedEndpoint: localCa,
    });
  });

  it("allows tenant acme in ca even when the hop leaves the perimeter", () => {
    const decision = decide(engine, "acme", ["confidential"], cloudCa);
    expect(decision).toMatchObject({
      decision: "allow",
      matchedRuleId: "tenant-acme-ca",
      reason: "Matched 1 rule(s); candidate permitted.",
      blockedResidencies: [],
    });
  });

  it("allows tenant acme on-prem", () => {
    const decision = decide(engine, "acme", [], localOnprem);
    expect(decision.decision).toBe("allow");
    expect(decision.matchedRuleId).toBe("tenant-acme-ca");
  });

  it("does not apply tenant-acme-ca to other tenants or to a different id casing", () => {
    for (const tenantId of ["globex", "Acme", "acme "]) {
      const decision = decide(engine, tenantId, ["public"], cloudUs);
      expect(decision.decision, tenantId).toBe("allow");
      expect(decision.reason, tenantId).toBe("No residency rules matched; default allow.");
      expect(decision.matchedRuleId, tenantId).toBeUndefined();
    }
  });

  it("still applies the tenant rule when an earlier class rule already allowed the hop", () => {
    const denied = decide(engine, "acme", ["pii"], localEu);
    expect(denied).toMatchObject({
      decision: "deny",
      matchedRuleId: "tenant-acme-ca",
      reason: "Rule tenant-acme-ca: residency eu not in allow list ca,onprem.",
      blockedResidencies: ["eu"],
    });

    // localCa fails eu-pii-stay (ca ∉ eu|onprem); multi-rule soundness → deny
    const stillDenied = decide(engine, "acme", ["pii"], localEu, [localCa]);
    expect(stillDenied).toMatchObject({
      decision: "deny",
      matchedRuleId: "tenant-acme-ca",
    });
    const rerouted = decide(engine, "acme", ["pii"], localEu, [localOnprem]);
    // localOnprem fails tenant-acme-ca (onprem ok for tenant, but wait — onprem IS allowed)
    // tenant allows ca|onprem; eu-pii allows eu|onprem → intersection onprem
    expect(rerouted).toMatchObject({
      decision: "reroute",
      matchedRuleId: "tenant-acme-ca",
      suggestedEndpoint: localOnprem,
    });
  });

  it("lets the higher-precedence EU PII rule answer before the tenant rule", () => {
    const decision = decide(engine, "acme", ["pii", "phi"], cloudUs, [localOnprem]);
    expect(decision).toMatchObject({
      decision: "reroute",
      matchedRuleId: "eu-pii-stay",
      reason: "Rule eu-pii-stay: destination leaves perimeter.",
      suggestedEndpoint: localOnprem,
      blockedResidencies: ["us"],
    });
  });

  it("matches phi alone on the shipped EU rule", () => {
    const decision = decide(engine, "globex", ["phi"], cloudUs);
    expect(decision).toMatchObject({
      decision: "require_local",
      matchedRuleId: "eu-pii-stay",
      reason: "Rule eu-pii-stay: destination leaves perimeter.",
      blockedResidencies: ["us"],
    });
  });

  it("uses priority, not input order, when two tenant rules disagree", () => {
    const tight: ResidencyRule = {
      id: "tight-deny",
      description: "on-prem only",
      tenants: ["acme"],
      allowResidencies: ["onprem"],
      whenDataClasses: [],
      preferLocal: false,
      denyLeavePerimeter: false,
      priority: 5,
    };
    const wide: ResidencyRule = {
      id: "wide-reroute",
      description: "ca or on-prem",
      tenants: ["acme"],
      allowResidencies: ["ca", "onprem"],
      whenDataClasses: [],
      preferLocal: false,
      denyLeavePerimeter: false,
      priority: 20,
    };

    const tightFirst = new ResidencyPolicyEngine([wide, tight]);
    const denied = decide(tightFirst, "acme", ["internal"], cloudUs, [localCa]);
    expect(denied).toMatchObject({
      decision: "deny",
      matchedRuleId: "tight-deny",
      reason: "Rule tight-deny: residency us not in allow list onprem.",
    });
    expect(decide(tightFirst, "globex", ["internal"], cloudUs).decision).toBe("allow");

    const wideFirst = new ResidencyPolicyEngine([
      { ...tight, priority: 50 },
      { ...wide, priority: 5 },
    ]);
    // localCa fails the tight onprem-only rule; need onprem alternative
    expect(
      decide(wideFirst, "acme", ["internal"], cloudUs, [localCa]).decision,
    ).toBe("deny");
    const rerouted = decide(wideFirst, "acme", ["internal"], cloudUs, [localOnprem]);
    expect(rerouted).toMatchObject({
      decision: "reroute",
      matchedRuleId: "wide-reroute",
      suggestedEndpoint: localOnprem,
    });
  });

  it("exposes the tenant rule through the route hook and traceRequest", () => {
    const hook = createRoutePolicyHook(engine);
    const hooked = hook(tagFor("acme", ["internal"], "corr-hook"), cloudUs, [cloudCa]);
    expect(hooked.decision).toBe("reroute");
    expect(hooked.matchedRuleId).toBe("tenant-acme-ca");
    expect(hooked.suggestedEndpoint?.residency).toBe("ca");

    const traced = new DataLineageModule(configRules).traceRequest({
      tenantId: "acme",
      sourceId: "chat",
      declaredResidency: "ca",
      dataClasses: ["internal"],
      correlationId: "corr-acme",
      candidate: cloudUs,
      alternatives: [localCa],
    });
    expect(traced.decision.matchedRuleId).toBe("tenant-acme-ca");
    expect(traced.decision.decision).toBe("reroute");
    expect(traced.proof.withinPerimeter).toBe(true);
    expect(traced.graph.edges.every((edge) => edge.correlationId === "corr-acme")).toBe(
      true,
    );
  });
});

describe("secrets prefer-local", () => {
  const engine = new ResidencyPolicyEngine(configRules);

  it("allows secrets that stay on-prem", () => {
    const decision = decide(engine, "globex", ["secrets"], localOnprem);
    expect(decision).toMatchObject({
      decision: "allow",
      matchedRuleId: "secrets-local",
      reason: "Matched 1 rule(s); candidate permitted.",
      blockedResidencies: [],
    });
  });

  it("reroutes a leaving secrets hop to a local alternative", () => {
    const decision = decide(engine, "globex", ["secrets"], cloudUs, [cloudEu, localOnprem]);
    expect(decision).toMatchObject({
      decision: "reroute",
      matchedRuleId: "secrets-local",
      reason: "Rule secrets-local: destination leaves perimeter.",
      suggestedEndpoint: localOnprem,
      blockedResidencies: ["us"],
    });
  });

  it("requires local when every secrets alternative still leaves", () => {
    const decision = decide(engine, "globex", ["secrets"], cloudUs, [cloudEu]);
    expect(decision).toMatchObject({
      decision: "require_local",
      matchedRuleId: "secrets-local",
      reason: "Rule secrets-local: destination leaves perimeter.",
      blockedResidencies: ["us"],
    });
    expect(decision.suggestedEndpoint).toBeUndefined();
  });

  it("denies a secrets residency outside the allow list when the hop stays inside", () => {
    const denied = decide(engine, "globex", ["secrets"], globalInside);
    expect(denied).toMatchObject({
      decision: "deny",
      matchedRuleId: "secrets-local",
      reason: "Rule secrets-local: residency global not in allow list onprem.",
      blockedResidencies: ["global"],
    });

    const rerouted = decide(engine, "globex", ["secrets"], globalInside, [localOnprem]);
    expect(rerouted).toMatchObject({
      decision: "reroute",
      matchedRuleId: "secrets-local",
      reason: "Rule secrets-local: residency global not in allow list onprem.",
      suggestedEndpoint: localOnprem,
    });
  });

  it("evaluates secrets-local before the acme region rule", () => {
    const staying = decide(engine, "acme", ["secrets"], localOnprem);
    expect(staying).toMatchObject({
      decision: "allow",
      matchedRuleId: "tenant-acme-ca",
      reason: "Matched 2 rule(s); candidate permitted.",
    });

    const leaving = decide(engine, "acme", ["secrets"], cloudUs, [localOnprem]);
    expect(leaving).toMatchObject({
      decision: "reroute",
      matchedRuleId: "secrets-local",
      suggestedEndpoint: localOnprem,
    });
  });

  it("prefers a non-leaving alternative when denyLeavePerimeter is off", () => {
    const preferLocal: ResidencyRule = {
      id: "secrets-prefer-local",
      description: "soft local preference for secrets",
      tenants: [],
      allowResidencies: ["onprem", "us", "eu"],
      whenDataClasses: ["secrets"],
      preferLocal: true,
      denyLeavePerimeter: false,
      priority: 1,
    };
    const soft = new ResidencyPolicyEngine([preferLocal]);

    const rerouted = decide(soft, "globex", ["secrets"], cloudUs, [cloudEu, localOnprem]);
    expect(rerouted).toMatchObject({
      decision: "reroute",
      matchedRuleId: "secrets-prefer-local",
      reason: "Rule secrets-prefer-local: prefer local; candidate leaves perimeter.",
      suggestedEndpoint: localOnprem,
      blockedResidencies: [],
    });

    const noLegalLocal = decide(soft, "globex", ["secrets"], cloudUs, [cloudEu]);
    expect(noLegalLocal).toMatchObject({
      decision: "allow",
      matchedRuleId: "secrets-prefer-local",
      reason: "Matched 1 rule(s); candidate permitted.",
      blockedResidencies: [],
    });

    const alreadyLocal = decide(soft, "globex", ["secrets"], localOnprem, [cloudUs]);
    expect(alreadyLocal.decision).toBe("allow");

    const notSecrets = decide(soft, "globex", ["public"], cloudUs, [localOnprem]);
    expect(notSecrets.reason).toBe("No residency rules matched; default allow.");
  });

  it("does not treat an out-of-policy local endpoint as the preferred target", () => {
    const preferLocal: ResidencyRule = {
      id: "secrets-prefer-local",
      description: "local must also be in the allow list",
      tenants: [],
      allowResidencies: ["us", "eu"],
      whenDataClasses: ["secrets"],
      preferLocal: true,
      denyLeavePerimeter: false,
      priority: 1,
    };
    const decision = decide(new ResidencyPolicyEngine([preferLocal]), "globex", ["secrets"], cloudUs, [
      localOnprem,
    ]);
    expect(decision.decision).toBe("allow");
    expect(decision.suggestedEndpoint).toBeUndefined();
  });
});

describe("empty rules default allow", () => {
  it("allows every candidate when the engine is constructed with no rules", () => {
    for (const engine of [new ResidencyPolicyEngine(), new ResidencyPolicyEngine([])]) {
      const decision = decide(engine, "acme", ["pii", "secrets"], cloudUs, [localOnprem]);
      expect(decision).toMatchObject({
        decision: "allow",
        reason: "No residency rules matched; default allow.",
        blockedResidencies: [],
        evaluatedAt: "2026-03-01T00:00:00.000Z",
      });
      expect(decision.matchedRuleId).toBeUndefined();
      expect(engine.listRules()).toEqual([]);
    }
  });

  it("allows when rules exist but none match the tenant or data class", () => {
    const engine = new ResidencyPolicyEngine([
      configRules.find((rule) => rule.id === "eu-pii-stay")!,
      configRules.find((rule) => rule.id === "tenant-acme-ca")!,
    ]);
    const decision = decide(engine, "globex", ["confidential"], cloudUs);
    expect(decision.reason).toBe("No residency rules matched; default allow.");
    expect(decision.decision).toBe("allow");
  });

  it("returns to default allow after rules are cleared", () => {
    const engine = new ResidencyPolicyEngine(configRules);
    engine.replaceRules([]);
    const decision = decide(engine, "acme", ["pii"], cloudUs);
    expect(decision.decision).toBe("allow");
    expect(decision.reason).toBe("No residency rules matched; default allow.");

    const hook = createRoutePolicyHook(engine);
    expect(hook(tagFor("acme", ["secrets"]), cloudUs).decision).toBe("allow");
  });
});

describe("graph snapshot filtering by correlationId", () => {
  it("returns only the edges and incident nodes for that id", () => {
    const mod = new DataLineageModule([]);
    const first = mod.traceRequest({
      tenantId: "acme",
      sourceId: "vscode",
      declaredResidency: "us",
      dataClasses: ["public"],
      correlationId: "corr-a",
      candidate: cloudUs,
    });
    const second = mod.traceRequest({
      tenantId: "globex",
      sourceId: "slack",
      declaredResidency: "ca",
      dataClasses: ["public"],
      correlationId: "corr-a-suffix",
      candidate: localCa,
    });

    const filtered = mod.getGraph("corr-a");
    expect(filtered.edges.map((edge) => edge.kind)).toEqual([
      "ingress",
      "route",
      "policy_eval",
      "egress",
      "egress",
    ]);
    expect(filtered.edges.every((edge) => edge.correlationId === "corr-a")).toBe(true);
    expect(new Set(filtered.nodes.map((node) => node.id))).toEqual(endpointIds(filtered));
    expect(filtered.nodes.map((node) => node.id)).toEqual(
      expect.arrayContaining([
        "client:vscode",
        "ingress:corr-a",
        "router:default",
        "policy:corr-a",
        "provider:openai:gpt",
        "region:us",
      ]),
    );
    for (const absent of [
      "client:slack",
      "ingress:corr-a-suffix",
      "policy:corr-a-suffix",
      "provider:local-ca:llama",
      "region:ca",
    ]) {
      expect(filtered.nodes.map((node) => node.id), absent).not.toContain(absent);
    }

    const suffix = mod.getGraph("corr-a-suffix");
    expect(suffix.edges.every((edge) => edge.correlationId === "corr-a-suffix")).toBe(true);
    expect(suffix.nodes.map((node) => node.id)).toContain("router:default");
    expect(suffix.nodes.map((node) => node.id)).not.toContain("ingress:corr-a");

    expect(mod.graph.edgesFor("corr-a")).toHaveLength(5);
    expect(mod.graph.edgesFor("corr")).toEqual([]);
    expect(mod.getGraph("missing").edges).toEqual([]);
    expect(mod.getGraph("missing").nodes).toEqual([]);

    const all = mod.getGraph();
    expect(all.edges).toHaveLength(first.graph.edges.length + second.graph.edges.length);
    expect(all.edges.filter((edge) => edge.correlationId === "corr-a")).toHaveLength(5);
    expect(all.edges.filter((edge) => edge.correlationId === "corr-a-suffix")).toHaveLength(5);

    const firstIds = new Set(first.graph.edges.map((edge) => edge.id));
    for (const edge of second.graph.edges) {
      expect(firstIds.has(edge.id)).toBe(false);
    }
    expect(filtered.edges.filter((edge) => edge.kind === "egress").map((edge) => edge.leavesPerimeter)).toEqual([
      true,
      true,
    ]);
    expect(suffix.edges.filter((edge) => edge.kind === "egress").map((edge) => edge.leavesPerimeter)).toEqual([
      false,
      false,
    ]);
  });

  it("keeps orphan nodes in the full snapshot and drops them when filtering", () => {
    const graph = new LineageGraph();
    graph.recordAiHop({
      tag: tagFor("acme", ["public"], "corr-a"),
      candidate: localOnprem,
      decision: RouteDecisionSchema.parse({
        decision: "allow",
        reason: "ok",
        blockedResidencies: [],
        evaluatedAt: "2026-03-01T00:00:00.000Z",
      }),
      now: fixedNow,
    });
    graph.upsertNode({
      id: "tool:orphan",
      kind: "tool",
      label: "orphan",
      meta: {},
    });

    expect(graph.snapshot().nodes.map((node) => node.id)).toContain("tool:orphan");
    const filtered = graph.snapshot("corr-a");
    expect(filtered.nodes.map((node) => node.id)).not.toContain("tool:orphan");
    expect(new Set(filtered.nodes.map((node) => node.id))).toEqual(endpointIds(filtered));

    graph.clear();
    expect(graph.snapshot().nodes).toEqual([]);
    expect(graph.snapshot().edges).toEqual([]);
    expect(() =>
      graph.addEdge({
        from: "client:chat",
        to: "nowhere",
        kind: "route",
        correlationId: "corr-a",
        leavesPerimeter: false,
        at: "2026-03-01T00:00:00.000Z",
        meta: {},
      }),
    ).toThrow(/missing node/);
  });
});

describe("perimeter proof digest and withinPerimeter", () => {
  const tag = tagFor("acme", ["pii"], "corr-fixed");
  const prover = new PerimeterProver();
  const issued = () => new Date("2026-06-01T00:00:00.000Z");

  function decision(name: RouteDecision["decision"]): RouteDecision {
    return RouteDecisionSchema.parse({
      decision: name,
      reason: name,
      blockedResidencies: [],
      evaluatedAt: "2026-03-01T00:00:00.000Z",
    });
  }

  function build(name: RouteDecision["decision"], egressLeaves: boolean[]): PerimeterProof {
    const nodes = egressLeaves.map((_, index) =>
      LineageNodeSchema.parse({
        id: `hop-${index}`,
        kind: "provider",
        label: `hop-${index}`,
        residency: "us",
        meta: {},
      }),
    );
    const edges = egressLeaves.map((leavesPerimeter, index) =>
      LineageEdgeSchema.parse({
        id: `edge-${index}`,
        from: "policy:corr-fixed",
        to: `hop-${index}`,
        kind: "egress",
        correlationId: tag.correlationId,
        leavesPerimeter,
        at: "2026-03-01T00:00:00.000Z",
        meta: {},
      }),
    );
    return prover.build({
      tag,
      decision: decision(name),
      edges,
      nodes,
      now: issued,
    });
  }

  it("binds the digest to the canonical proof body, including key order", () => {
    const proof = build("allow", [false]);
    const { digest, ...body } = proof;
    expect(digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(canonicalDigest(body)).toBe(digest);
    expect(canonicalDigest(reverseKeys(body))).toBe(digest);
    expect(canonicalDigest({ ...body, withinPerimeter: !body.withinPerimeter })).not.toBe(digest);
    expect(proof.claimLevel).toBe("software_attested");
  });

  it("changes the digest across builds because proofId is inside the preimage", () => {
    const first = build("allow", [false]);
    const second = build("allow", [false]);
    expect(first.proofId).not.toBe(second.proofId);
    expect(first.digest).not.toBe(second.digest);
    expect(first.withinPerimeter).toBe(true);
    expect(second.withinPerimeter).toBe(true);
    expect(first.issuedAt).toBe("2026-06-01T00:00:00.000Z");
    expect(second.issuedAt).toBe(first.issuedAt);
    expect(first.correlationId).toBe("corr-fixed");
  });

  it.each([
    ["allow", [false, false], true],
    ["allow", [false, true], false],
    ["allow", [true], false],
    ["allow", [], false],
    ["deny", [true, true], true],
    ["reroute", [true], true],
    ["require_local", [true], true],
  ] as const)(
    "sets withinPerimeter for %s egress %j to %s",
    (name, leaves, expected) => {
      const proof = build(name, [...leaves]);
      expect(proof.withinPerimeter).toBe(expected);
      expect(proof.egressHops.map((hop) => hop.leavesPerimeter)).toEqual([...leaves]);
    },
  );

  it("ignores leavesPerimeter on non-egress edges", () => {
    const proof = prover.build({
      tag,
      decision: decision("allow"),
      edges: [
        LineageEdgeSchema.parse({
          id: "route-1",
          from: "ingress",
          to: "router",
          kind: "route",
          correlationId: tag.correlationId,
          leavesPerimeter: true,
          at: "2026-03-01T00:00:00.000Z",
          meta: {},
        }),
      ],
      nodes: [],
      now: issued,
    });
    expect(proof.egressHops).toEqual([]);
    // allow + no egress/tool_call hops cannot attest a perimeter stay
    expect(proof.withinPerimeter).toBe(false);
  });
});

describe("schema rejection", () => {
  const validTag = {
    correlationId: "c1",
    tenantId: "acme",
    sourceId: "vscode",
    declaredResidency: "eu",
    dataClasses: ["pii"],
    labels: { team: "clinical" },
    taggedAt: "2026-01-01T00:00:00.000Z",
  };

  function reject(run: () => unknown): ZodError {
    try {
      run();
    } catch (err) {
      expect(err).toBeInstanceOf(ZodError);
      return err as ZodError;
    }
    throw new Error("expected ZodError");
  }

  it("rejects unknown residency regions and accepts the enum", () => {
    for (const region of ["eu", "us", "uk", "ca", "apac", "global", "onprem", "unknown"]) {
      expect(ResidencyRegionSchema.parse(region)).toBe(region);
    }
    for (const region of ["mars", "EU", "on-prem", "Canada", ""]) {
      expect(reject(() => ResidencyRegionSchema.parse(region)).issues.length).toBeGreaterThan(0);
    }
  });

  it("rejects unknown data classes", () => {
    expect(DataClassSchema.parse("secrets")).toBe("secrets");
    for (const value of ["secret", "PII", "pci", ""]) {
      expect(() => DataClassSchema.parse(value)).toThrow(ZodError);
    }
  });

  it("rejects malformed ingress tags and fills defaults", () => {
    expect(parseIngressTag(validTag).contentDigest).toBeUndefined();

    const residency = reject(() =>
      IngressTagSchema.parse({ ...validTag, declaredResidency: "antarctica" }),
    );
    expect(residency.issues.some((issue) => issue.path[0] === "declaredResidency")).toBe(true);

    const dataClass = reject(() =>
      IngressTagSchema.parse({ ...validTag, dataClasses: ["pii", "secret"] }),
    );
    expect(dataClass.issues.some((issue) => issue.path[0] === "dataClasses")).toBe(true);

    for (const override of [
      { correlationId: "" },
      { tenantId: "" },
      { sourceId: "" },
      { taggedAt: "yesterday" },
      { taggedAt: "2026-01-01" },
    ]) {
      expect(() => IngressTagSchema.parse({ ...validTag, ...override })).toThrow(ZodError);
    }

    const parsed = IngressTagSchema.parse({
      correlationId: "c1",
      tenantId: "acme",
      sourceId: "vscode",
      declaredResidency: "eu",
      taggedAt: "2026-01-01T00:00:00.000Z",
    });
    expect(parsed.dataClasses).toEqual([]);
    expect(parsed.labels).toEqual({});
  });

  it("rejects bad tags and endpoints at the tagger and policy engine", () => {
    const tagger = new IngressTagger();
    expect(() =>
      tagger.tag({
        tenantId: "acme",
        sourceId: "vscode",
        declaredResidency: "antarctica" as "eu",
      }),
    ).toThrow(ZodError);
    expect(() =>
      tagger.tag({
        tenantId: "",
        sourceId: "vscode",
        declaredResidency: "eu",
      }),
    ).toThrow(ZodError);
    expect(() =>
      tagger.tag({
        tenantId: "acme",
        sourceId: "vscode",
        declaredResidency: "eu",
        dataClasses: ["secret" as "secrets"],
      }),
    ).toThrow(ZodError);

    expect(() =>
      ProviderEndpointSchema.parse({ ...cloudUs, endpoint: "not a url" }),
    ).toThrow(ZodError);
    expect(() =>
      ProviderEndpointSchema.parse({ ...cloudUs, endpoint: "not-a-url" }),
    ).toThrow(ZodError);
    expect(() =>
      ProviderEndpointSchema.parse({ ...cloudUs, residency: "moon" }),
    ).toThrow(ZodError);
    expect(ProviderEndpointSchema.parse({ ...localOnprem }).endpoint).toBe("local://llama");

    const tag = tagFor("acme", ["public"]);
    const engine = new ResidencyPolicyEngine([]);
    expect(() =>
      engine.evaluate({
        tag,
        candidate: { ...cloudUs, residency: "moon" as "us" },
      }),
    ).toThrow(ZodError);
    expect(() =>
      engine.evaluate({
        tag,
        candidate: localOnprem,
        alternatives: [{ ...cloudUs, endpoint: "not-a-url" }],
      }),
    ).toThrow(ZodError);
  });

  it("rejects invalid residency rules and keeps the previous bundle", () => {
    expect(() =>
      ResidencyRuleSchema.parse({
        id: "empty-allow",
        description: "none",
        allowResidencies: [],
      }),
    ).toThrow(ZodError);
    const badRegion = reject(() =>
      ResidencyRuleSchema.parse({
        id: "bad-region",
        description: "nope",
        allowResidencies: ["eu", "mars"],
      }),
    );
    expect(badRegion.issues.some((issue) => issue.path[0] === "allowResidencies")).toBe(true);
    expect(() =>
      ResidencyRuleSchema.parse({
        id: "bad-class",
        description: "nope",
        allowResidencies: ["eu"],
        whenDataClasses: ["secret"],
      }),
    ).toThrow(ZodError);
    expect(() =>
      ResidencyRuleSchema.parse({
        id: "bad-priority",
        description: "nope",
        allowResidencies: ["eu"],
        priority: 1.5,
      }),
    ).toThrow(ZodError);
    expect(() =>
      ResidencyRuleSchema.parse({
        id: "",
        description: "nope",
        allowResidencies: ["eu"],
      }),
    ).toThrow(ZodError);

    const minimal = ResidencyRuleSchema.parse({
      id: "minimal",
      description: "eu only",
      allowResidencies: ["eu"],
    });
    expect(minimal).toMatchObject({
      tenants: [],
      whenDataClasses: [],
      preferLocal: false,
      denyLeavePerimeter: false,
      priority: 100,
    });

    expect(() =>
      new ResidencyPolicyEngine([
        {
          id: "bad-region",
          description: "nope",
          tenants: [],
          allowResidencies: ["mars" as "eu"],
          whenDataClasses: [],
          preferLocal: false,
          denyLeavePerimeter: false,
          priority: 1,
        },
      ]),
    ).toThrow(ZodError);

    const engine = new ResidencyPolicyEngine(configRules);
    expect(() =>
      engine.replaceRules([
        {
          id: "broken",
          description: "broken",
          allowResidencies: [],
        } as unknown as ResidencyRule,
      ]),
    ).toThrow(ZodError);
    const decision = decide(engine, "acme", ["internal"], cloudUs, [localCa]);
    expect(decision.decision).toBe("reroute");
    expect(decision.matchedRuleId).toBe("tenant-acme-ca");
  });

  it("rejects a proof whose claim level is not software_attested", () => {
    const proof = new PerimeterProver().build({
      tag: tagFor("acme", ["public"], "corr-schema"),
      decision: RouteDecisionSchema.parse({
        decision: "deny",
        reason: "no",
        blockedResidencies: ["us"],
        evaluatedAt: "2026-03-01T00:00:00.000Z",
      }),
      edges: [],
      nodes: [],
      now: fixedNow,
    });
    expect(() =>
      PerimeterProofSchema.parse({ ...proof, claimLevel: "tee" }),
    ).toThrow(ZodError);
    expect(() =>
      LineageNodeSchema.parse({ id: "", kind: "client", label: "x", meta: {} }),
    ).toThrow(ZodError);
    expect(() =>
      LineageNodeSchema.parse({ id: "n1", kind: "llm", label: "x", meta: {} }),
    ).toThrow(ZodError);
  });
});
