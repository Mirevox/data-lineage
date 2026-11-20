import { afterEach, describe, expect, it } from "vitest";
import type { Server } from "node:http";
import { AddressInfo } from "node:net";
import { DataLineageModule } from "../src/module.js";
import { createApp } from "../src/server/main.js";
import type { ResidencyRule } from "../src/types.js";

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

describe("demo HTTP server", () => {
  let server: Server | undefined;

  afterEach(async () => {
    if (!server) return;
    await new Promise<void>((resolve, reject) => {
      server!.close((err) => (err ? reject(err) : resolve()));
    });
    server = undefined;
  });

  async function listen(): Promise<string> {
    const app = createApp(new DataLineageModule(rules));
    server = app;
    await new Promise<void>((resolve) => {
      app.listen(0, "127.0.0.1", () => resolve());
    });
    const { port } = app.address() as AddressInfo;
    return `http://127.0.0.1:${port}`;
  }

  it("serves health and rejects bad trace bodies with 400", async () => {
    const base = await listen();
    const health = await fetch(`${base}/health`);
    expect(health.status).toBe(200);
    expect((await health.json()).ok).toBe(true);

    const nullBody = await fetch(`${base}/v1/trace`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "null",
    });
    expect(nullBody.status).toBe(400);

    const badTypes = await fetch(`${base}/v1/trace`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        tenantId: "acme",
        sourceId: "vscode",
        declaredResidency: "eu",
        dataClasses: "pii",
        candidate: {
          providerId: "local",
          modelId: "llama",
          residency: "onprem",
          endpoint: "local://llama",
          leavesPerimeter: false,
        },
      }),
    });
    expect(badTypes.status).toBe(400);

    const badScheme = await fetch(`${base}/v1/trace`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        tenantId: "acme",
        sourceId: "vscode",
        declaredResidency: "eu",
        candidate: {
          providerId: "x",
          modelId: "y",
          residency: "us",
          endpoint: "ftp://evil.example/x",
          leavesPerimeter: true,
        },
      }),
    });
    expect(badScheme.status).toBe(400);

    const ok = await fetch(`${base}/v1/trace`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        tenantId: "acme",
        sourceId: "vscode",
        declaredResidency: "eu",
        dataClasses: ["pii"],
        candidate: {
          providerId: "local",
          modelId: "llama",
          residency: "onprem",
          endpoint: "local://llama",
          leavesPerimeter: false,
        },
      }),
    });
    expect(ok.status).toBe(200);

    const missing = await fetch(`${base}/nope`);
    expect(missing.status).toBe(404);
  });

  it("returns 413 for oversized bodies", async () => {
    const base = await listen();
    const huge = "x".repeat(1_048_576 + 8);
    const res = await fetch(`${base}/v1/trace`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: `{"tenantId":"acme","pad":"${huge}"}`,
    });
    expect(res.status).toBe(413);
  });
});
