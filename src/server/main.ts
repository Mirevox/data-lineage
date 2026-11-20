import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { ZodError } from "zod";
import { DataLineageModule } from "../module.js";
import {
  ProviderEndpointSchema,
  ResidencyRuleSchema,
  type ProviderEndpoint,
  type ResidencyRule,
} from "../types.js";

const PORT = Number(process.env.MIREVOX_LINEAGE_PORT ?? 3847);
const HOST = process.env.MIREVOX_LINEAGE_HOST ?? "127.0.0.1";
const MAX_BODY_BYTES = 1_048_576; // 1 MiB
const explicitRulesPath = process.env.MIREVOX_LINEAGE_RULES;

function loadRules(): ResidencyRule[] {
  const path = explicitRulesPath ?? resolve(process.cwd(), "config/residency-rules.json");
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (!Array.isArray(raw)) {
      throw new Error("rules file must be a JSON array");
    }
    return raw.map((r) => ResidencyRuleSchema.parse(r));
  } catch (err) {
    // Explicit env path must fail closed; default config path may fall back to demos.
    if (explicitRulesPath) {
      throw new Error(
        `Failed to load MIREVOX_LINEAGE_RULES=${explicitRulesPath}: ${String(err)}`,
      );
    }
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
      description: "Secrets must stay on-prem",
      tenants: [],
      allowResidencies: ["onprem"],
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
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > MAX_BODY_BYTES) {
      const err = new Error(`request body exceeds ${MAX_BODY_BYTES} bytes`);
      (err as Error & { statusCode?: number }).statusCode = 413;
      throw err;
    }
    chunks.push(buf);
  }
  const body = Buffer.concat(chunks).toString("utf8");
  if (!body) return {};
  try {
    return JSON.parse(body) as unknown;
  } catch {
    const err = new Error("invalid JSON body");
    (err as Error & { statusCode?: number }).statusCode = 400;
    throw err;
  }
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
    const statusFromErr =
      err && typeof err === "object" && "statusCode" in err
        ? Number((err as { statusCode?: number }).statusCode)
        : undefined;
    if (err instanceof ZodError) {
      send(res, 400, { error: "validation failed", details: err.flatten() });
      return;
    }
    if (statusFromErr === 400 || statusFromErr === 413) {
      send(res, statusFromErr, {
        error: err instanceof Error ? err.message : String(err),
      });
      return;
    }
    send(res, 500, { error: err instanceof Error ? err.message : String(err) });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Mirevox data-lineage listening on http://${HOST}:${PORT}`);
});
