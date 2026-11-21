import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { z, ZodError } from "zod";
import { DataLineageModule } from "../module.js";
import {
  DataClassSchema,
  ProviderEndpointSchema,
  ResidencyRegionSchema,
  ResidencyRuleSchema,
  type ResidencyRule,
} from "../types.js";

const PORT = Number(process.env.MIREVOX_LINEAGE_PORT ?? 3847);
const HOST = process.env.MIREVOX_LINEAGE_HOST ?? "127.0.0.1";
const CORS_ORIGIN = process.env.MIREVOX_LINEAGE_CORS_ORIGIN ?? "*";
const MAX_BODY_BYTES = 1_048_576; // 1 MiB
const explicitRulesPath = process.env.MIREVOX_LINEAGE_RULES;

const TraceRequestBodySchema = z.object({
  tenantId: z.string().min(1),
  sourceId: z.string().min(1),
  declaredResidency: ResidencyRegionSchema,
  dataClasses: z.array(DataClassSchema).optional(),
  labels: z.record(z.string(), z.string()).optional(),
  payload: z.union([z.string(), z.instanceof(Uint8Array)]).optional(),
  autoClassify: z.boolean().optional(),
  correlationId: z.string().min(1).optional(),
  candidate: ProviderEndpointSchema,
  alternatives: z.array(ProviderEndpointSchema).optional(),
  routerId: z.string().min(1).optional(),
});

function packageVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkgPath = resolve(here, "../../package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

const VERSION = packageVersion();

export function loadRules(
  rulesPath = explicitRulesPath ?? resolve(process.cwd(), "config/residency-rules.json"),
  opts: { explicit?: boolean } = {},
): ResidencyRule[] {
  const explicit = opts.explicit ?? Boolean(explicitRulesPath && rulesPath === explicitRulesPath);
  try {
    const raw = JSON.parse(readFileSync(rulesPath, "utf8")) as unknown;
    if (!Array.isArray(raw)) {
      throw new Error("rules file must be a JSON array");
    }
    return raw.map((r) => ResidencyRuleSchema.parse(r));
  } catch (err) {
    if (explicit || explicitRulesPath) {
      throw new Error(
        `Failed to load MIREVOX_LINEAGE_RULES=${rulesPath}: ${String(err)}`,
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
    "access-control-allow-origin": CORS_ORIGIN,
  });
  res.end(payload);
}

export function createApp(module_ = new DataLineageModule(loadRules())) {
  const graphFile = process.env.MIREVOX_LINEAGE_GRAPH_FILE?.trim();
  if (graphFile) {
    module_.graph.loadFromFile(graphFile);
  }
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", `http://${HOST}:${PORT}`);
      if (req.method === "OPTIONS") {
        res.writeHead(204, {
          "access-control-allow-origin": CORS_ORIGIN,
          "access-control-allow-methods": "GET,POST,OPTIONS",
          "access-control-allow-headers": "content-type",
        });
        res.end();
        return;
      }

      if (
        req.method === "GET" &&
        (url.pathname === "/health" || url.pathname === "/readyz")
      ) {
        send(res, 200, {
          ok: true,
          service: "@mirevox/data-lineage",
          version: VERSION,
          role: "demo-trace-api",
        });
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
        const raw = await readJson(req);
        if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
          send(res, 400, { error: "request body must be a JSON object" });
          return;
        }
        const body = TraceRequestBodySchema.parse(raw);
        const result = module_.traceRequest({
          tenantId: body.tenantId,
          sourceId: body.sourceId,
          declaredResidency: body.declaredResidency,
          dataClasses: body.dataClasses,
          labels: body.labels,
          payload: body.payload,
          autoClassify: body.autoClassify,
          correlationId: body.correlationId,
          candidate: body.candidate,
          alternatives: body.alternatives,
          routerId: body.routerId,
        });
        if (graphFile) {
          module_.graph.saveToFile(graphFile);
        }
        send(res, 200, result);
        return;
      }

      if (req.method === "GET" && url.pathname === "/") {
        send(res, 200, {
          name: "@mirevox/data-lineage",
          version: VERSION,
          role: "demo-trace-api",
          note: "Decision-record / residency-policy demo — not an enforcing gateway. Callers must enforce RouteDecision before egress.",
          endpoints: {
            "GET /health": "liveness",
            "GET /readyz": "readiness (same checks as /health in v1)",
            "GET /rules": "active residency rules",
            "GET /graph?correlationId=": "in-memory lineage snapshot (ephemeral)",
            "POST /v1/trace": "tag → policy → graph → decision checksum (PerimeterProof)",
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
}

export function startServer(
  port = PORT,
  host = HOST,
  module_?: DataLineageModule,
) {
  const server = createApp(module_);
  server.listen(port, host, () => {
    console.log(`Mirevox data-lineage listening on http://${host}:${port}`);
  });
  return server;
}

const isMain =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isMain) {
  startServer();
}
