import { describe, expect, it } from "vitest";
import { ZodError } from "zod";
import {
  digestPayload,
  IngressTagger,
  parseIngressTag,
} from "../src/ingress/tagger.js";
import { DataLineageModule } from "../src/module.js";
import type { ProviderEndpoint } from "../src/types.js";

const local: ProviderEndpoint = {
  providerId: "local",
  modelId: "llama",
  residency: "onprem",
  endpoint: "local://llama",
  leavesPerimeter: false,
};

describe("IngressTagger", () => {
  it("tags a request with correlation id and digest", () => {
    const tagger = new IngressTagger();
    const tag = tagger.tag({
      tenantId: "acme",
      sourceId: "vscode",
      declaredResidency: "eu",
      dataClasses: ["pii"],
      payload: "patient note",
      correlationId: "corr-1",
    });
    expect(tag.correlationId).toBe("corr-1");
    expect(tag.declaredResidency).toBe("eu");
    expect(tag.dataClasses).toEqual(["pii"]);
    expect(tag.contentDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("matches Uint8Array and string digests", () => {
    const text = "patient note";
    expect(digestPayload(text)).toBe(
      digestPayload(new TextEncoder().encode(text)),
    );
  });

  it("omits contentDigest when payload is absent", () => {
    const tag = new IngressTagger().tag({
      tenantId: "acme",
      sourceId: "vscode",
      declaredResidency: "eu",
    });
    expect(tag.contentDigest).toBeUndefined();
  });

  it("rejects invalid enums via parseIngressTag", () => {
    expect(() =>
      parseIngressTag({
        correlationId: "c1",
        tenantId: "acme",
        sourceId: "vscode",
        declaredResidency: "mars",
        dataClasses: [],
        labels: {},
        taggedAt: "2026-11-20T00:00:00.000Z",
      }),
    ).toThrow(ZodError);
  });

  it("preserves labels and rejects non-string values", () => {
    const tagger = new IngressTagger();
    const tag = tagger.tag({
      tenantId: "acme",
      sourceId: "vscode",
      declaredResidency: "eu",
      labels: { appcode: "appcode-xyz-0", evalRunId: "eval-42" },
    });
    expect(tag.labels).toEqual({
      appcode: "appcode-xyz-0",
      evalRunId: "eval-42",
    });
    expect(() =>
      tagger.tag({
        tenantId: "acme",
        sourceId: "vscode",
        declaredResidency: "eu",
        labels: { count: 42 } as never,
      }),
    ).toThrow(ZodError);
  });

  it("never stores canary plaintext on tag/graph/proof (NFR-04)", () => {
    const canary = "CANARY_PRIVATE_PAYLOAD_123";
    const mod = new DataLineageModule([]);
    const result = mod.traceRequest({
      tenantId: "acme",
      sourceId: "vscode",
      declaredResidency: "eu",
      dataClasses: ["pii"],
      payload: canary,
      labels: { appcode: "appcode-xyz-0" },
      candidate: local,
      correlationId: "corr-canary",
      now: () => new Date("2026-11-20T00:00:00.000Z"),
    });
    const blob = `${JSON.stringify(result)}\n${JSON.stringify(mod.getGraph())}`;
    expect(blob).not.toContain(canary);
    expect(result.tag.contentDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(result.proof.ingressTag.labels.appcode).toBe("appcode-xyz-0");
  });
});
