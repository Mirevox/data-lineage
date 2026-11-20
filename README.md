# @mirevox/data-lineage

Router-side **decision record** for AI traffic lineage and residency policy — a Mirevox [module](https://github.com/Mirevox).

Tag ingress, evaluate residency-aware route policy hooks, record an egress/lineage graph, and emit a **software checksum** over that recorded path. Plug into a smart-router before provider egress. Not a new LLM, not a network perimeter, not a compliance product.

## v1 slice

| Piece | What it does |
| --- | --- |
| Ingress tagging | Correlation id, tenant, `declaredResidency`, `dataClasses`, optional `contentDigest` |
| Residency policy hooks | `allow` / `deny` / `reroute` / `require_local` (caller must enforce) |
| Lineage graph | Client → ingress → router → policy → provider → region (in-process, ephemeral) |
| Decision checksum (`PerimeterProof`) | `claimLevel: software_attested` = SHA-256 of the recorded JSON decision, not TEE/network proof |

**Honest limit:** `declaredResidency`, `dataClasses`, `candidate.residency`, and `leavesPerimeter` are caller-declared and untrusted. This library does not open sockets, observe DNS/TLS, read CloudTrail, or prove bytes stayed inside a perimeter. **Do not treat `PerimeterProof` or `claimLevel: software_attested` as network-perimeter enforcement or GDPR/HIPAA/EU AI Act/SOC2 compliance evidence.** Default with no matching rule is **allow** (fail-open until you add rules). In-memory `LineageGraph` state is ephemeral per process — call `lineage.graph.clear()` periodically in long-running routers until durable storage ships.

## Quick start

```bash
npm install
npm test
npm run build
npm run dev   # http://127.0.0.1:3847
```

Demo HTTP endpoints (default `127.0.0.1:3847`, configured via `MIREVOX_LINEAGE_HOST`, `MIREVOX_LINEAGE_PORT`, `MIREVOX_LINEAGE_RULES`):

- `GET /health` — liveness
- `GET /rules` — active residency rules (`config/residency-rules.json`)
- `GET /graph?correlationId=<id>` — in-memory lineage snapshot
- `POST /v1/trace` — tag → policy → graph → decision checksum

CLI trace:

```bash
node dist/cli.js trace examples/sample-request.json --rules config/residency-rules.json
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
