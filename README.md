# @mirevox/data-lineage

Router-side **AI data lineage and residency tracing** for [Mirevox](https://github.com/Mirevox).

Tag ingress, evaluate residency-aware route policy, record an egress/lineage graph, and issue a **software-attested** perimeter proof for AI traffic. Designed to plug into a smart-router — not a new LLM, not a full compliance suite.

## v1 slice

| Piece | What it does |
| --- | --- |
| Ingress tagging | Correlation id, tenant, residency, data classes, optional content digest |
| Residency policy hooks | `allow` / `deny` / `reroute` / `require_local` against rules |
| Lineage graph | Client → ingress → router → policy → provider → region |
| Perimeter proof | `claimLevel: software_attested` over the recorded path |

Honest limit: proofs attest the **observed policy path in this module**, not TEE or network enforcement.

## Quick start

```bash
npm install
npm test
npm run build
npm run dev   # http://127.0.0.1:3847
```

Trace a request:

```bash
curl -s http://127.0.0.1:3847/v1/trace -H 'content-type: application/json' -d '{
  "tenantId": "demo",
  "sourceId": "vscode",
  "declaredResidency": "eu",
  "dataClasses": ["pii"],
  "payload": "redacted note",
  "candidate": {
    "providerId": "bedrock",
    "modelId": "claude",
    "residency": "us",
    "endpoint": "https://bedrock.amazonaws.com",
    "leavesPerimeter": true
  },
  "alternatives": [{
    "providerId": "local",
    "modelId": "llama",
    "residency": "onprem",
    "endpoint": "local://llama",
    "leavesPerimeter": false
  }]
}'
```

Library hook:

```ts
import { DataLineageModule } from "@mirevox/data-lineage";

const lineage = new DataLineageModule(/* residency rules */);
const { tag, decision, graph, proof } = lineage.traceRequest({ /* ... */ });
// Enforce `decision` in your router before provider egress.
```

## Compose with other Mirevox modules

- **smart-router** — call `policyHook` / `traceRequest` before fan-out to Foundry, Bedrock, Vertex, or local models.
- **evals** — correlate eval runs via `correlationId` on the same path.
- Homelab Docker later; this repo already has a `Dockerfile`.

## Docs

- [Problem & opportunity](docs/problem-opportunity.md)
- [Requirements](docs/requirements.md) (locked after council)
- [Architecture](docs/architecture.md)
- [Market gap](docs/market-gap.md)
- [Devil’s advocate](docs/devils-advocate.md)

## License

Apache-2.0
