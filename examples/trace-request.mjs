/**
 * Minimal router-side hook demo (run after `npm run build`).
 *   node examples/trace-request.mjs
 */
import { DataLineageModule } from "../dist/index.js";

const lineage = new DataLineageModule([
  {
    id: "eu-pii-stay",
    description: "EU PII stay local",
    tenants: [],
    allowResidencies: ["eu", "onprem"],
    whenDataClasses: ["pii"],
    preferLocal: true,
    denyLeavePerimeter: true,
    priority: 10,
  },
]);

const result = lineage.traceRequest({
  tenantId: "demo",
  sourceId: "vscode",
  declaredResidency: "eu",
  dataClasses: ["pii"],
  payload: "redacted clinical note",
  candidate: {
    providerId: "bedrock",
    modelId: "claude-3",
    residency: "us",
    endpoint: "https://bedrock.amazonaws.com",
    leavesPerimeter: true,
  },
  alternatives: [
    {
      providerId: "local",
      modelId: "llama-3",
      residency: "onprem",
      endpoint: "local://llama",
      leavesPerimeter: false,
    },
  ],
});

console.log(JSON.stringify(result, null, 2));
