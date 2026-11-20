import { describe, expect, it } from "vitest";
import { IngressTagger } from "../src/ingress/tagger.js";

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
});
