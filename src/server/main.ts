import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { DataLineageModule } from "../module.js";
import {
  ProviderEndpointSchema,
  ResidencyRuleSchema,
  type ProviderEndpoint,
  type ResidencyRule,
} from "../types.js";

const PORT = Number(process.env.MIREVOX_LINEAGE_PORT ?? 3847);
const HOST = process.env.MIREVOX_LINEAGE_HOST ?? "127.0.0.1";

function loadRules(): ResidencyRule[] {
  const path =
    process.env.MIREVOX_LINEAGE_RULES ??
    resolve(process.cwd(), "config/residency-rules.json");
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (!Array.isArray(raw)) {
      throw new Error("rules file must be a JSON array");
    }
    return raw.map((r) => ResidencyRuleSchema.parse(r));
  } catch (err) {
    console.warn(`[lineage] using built-in demo rules (${String(err)})`);
    return demoRules();
  }
}

function demoRules(): ResidencyRule[] {
  return [
    ResidencyRuleSchema.parse({
      id: "eu-pii-stay",
      description: "EU PII must stay in eu or onprem and not leave perimeter",
      tenants: [],
      allowResidencies: ["eu", "onprem"],
      whenDataClasses: ["pii", "phi"],
      preferLocal: true,
      denyLeavePerimeter: true,
      priority: 10,
    }),
    ResidencyRuleSchema.parse({
      id: "secrets-local",
      description: "Secrets prefer on-prem",
      tenants: [],
      allowResidencies: ["onprem", "eu", "us", "uk", "ca", "apac"],
      whenDataClasses: ["secrets"],
      preferLocal: true,
      denyLeavePerimeter: true,
      priority: 20,
    }),
  ];
}

const module_ = new DataLineageModule(loadRules());

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const body = Buffer.concat(chunks).toString("utf8");
  if (!body) return {};
  return JSON.parse(body) as unknown;
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "access-control-allow-origin": "*",
  });
  res.end(payload);
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", `http://${HOST}:${PORT}`);
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET,POST,OPTIONS",
        "access-control-allow-headers": "content-type",
      });
      res.end();
      return;
    }

    if (req.method === "GET" && url.pathname === "/health") {
      send(res, 200, { ok: true, service: "@mirevox/data-lineage", version: "0.1.0" });
      return;
    }

    if (req.method === "GET" && url.pathname === "/rules") {
      send(res, 200, { rules: module_.policy.listRules() });
      return;
    }

    if (req.method === "GET" && url.pathname === "/graph") {
      const correlationId = url.searchParams.get("correlationId") ?? undefined;
      send(res, 200, module_.getGraph(correlationId));
      return;
    }

    if (req.method === "POST" && url.pathname === "/v1/trace") {
      const body = (await readJson(req)) as {
        tenantId?: string;
        sourceId?: string;
        declaredResidency?: string;
        dataClasses?: string[];
        labels?: Record<string, string>;
        payload?: string;
        candidate?: ProviderEndpoint;
        alternatives?: ProviderEndpoint[];
        routerId?: string;
      };
      if (!body.tenantId || !body.sourceId || !body.declaredResidency || !body.candidate) {
        send(res, 400, {
          error:
            "tenantId, sourceId, declaredResidency, and candidate are required",
        });
        return;
      }
      const candidate = ProviderEndpointSchema.parse(body.candidate);
      const alternatives = (body.alternatives ?? []).map((a) =>
        ProviderEndpointSchema.parse(a),
      );
      const result = module_.traceRequest({
        tenantId: body.tenantId,
        sourceId: body.sourceId,
        declaredResidency: body.declaredResidency as never,
        dataClasses: body.dataClasses as never,
        labels: body.labels,
        payload: body.payload,
        candidate,
        alternatives,
        routerId: body.routerId,
      });
      send(res, 200, result);
      return;
    }

    if (req.method === "GET" && url.pathname === "/") {
      send(res, 200, {
        name: "@mirevox/data-lineage",
        endpoints: {
          "GET /health": "liveness",
          "GET /rules": "active residency rules",
          "GET /graph?correlationId=": "lineage snapshot",
          "POST /v1/trace": "tag → policy → graph → perimeter proof",
        },
      });
      return;
    }

    send(res, 404, { error: "not found" });
  } catch (err) {
    send(res, 500, { error: err instanceof Error ? err.message : String(err) });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Mirevox data-lineage listening on http://${HOST}:${PORT}`);
});
