#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { DataLineageModule } from "./module.js";
import {
  ProviderEndpointSchema,
  ResidencyRuleSchema,
  type ProviderEndpoint,
  type ResidencyRule,
} from "./types.js";

function usage(): never {
  console.error(`Usage:
  mirevox-lineage trace <request.json> [--rules rules.json]
  mirevox-lineage graph <correlationId>   # requires prior in-process trace (demo only)

trace: read a JSON request body matching POST /v1/trace and print the result.
`);
  process.exit(2);
}

function loadRules(path?: string): ResidencyRule[] {
  if (!path) return [];
  const raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
  if (!Array.isArray(raw)) throw new Error("rules must be a JSON array");
  return raw.map((r) => ResidencyRuleSchema.parse(r));
}

const args = process.argv.slice(2);
const cmd = args[0];
if (!cmd) usage();

if (cmd === "trace") {
  const file = args[1];
  if (!file) usage();
  const rulesIdx = args.indexOf("--rules");
  const rulesPath = rulesIdx >= 0 ? args[rulesIdx + 1] : undefined;
  const body = JSON.parse(readFileSync(file, "utf8")) as {
    tenantId: string;
    sourceId: string;
    declaredResidency: string;
    dataClasses?: string[];
    labels?: Record<string, string>;
    payload?: string;
    candidate: ProviderEndpoint;
    alternatives?: ProviderEndpoint[];
    routerId?: string;
  };
  const mod = new DataLineageModule(loadRules(rulesPath));
  const result = mod.traceRequest({
    tenantId: body.tenantId,
    sourceId: body.sourceId,
    declaredResidency: body.declaredResidency as never,
    dataClasses: body.dataClasses as never,
    labels: body.labels,
    payload: body.payload,
    candidate: ProviderEndpointSchema.parse(body.candidate),
    alternatives: (body.alternatives ?? []).map((a) =>
      ProviderEndpointSchema.parse(a),
    ),
    routerId: body.routerId,
  });
  console.log(JSON.stringify(result, null, 2));
  process.exit(0);
}

usage();
