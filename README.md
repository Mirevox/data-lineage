# @mirevox/data-lineage

Router-side **decision record** for AI traffic lineage and residency policy — a Mirevox [module](https://github.com/Mirevox).

Tag ingress, evaluate residency-aware route policy hooks, record an egress/lineage graph, and emit a **software checksum** over that recorded path. Plug into a smart-router before provider egress. Not a new LLM, not a network perimeter, not a compliance product.

## Problem

AI gateways can log provider, model, cost, and latency. Data-lineage tools can map jobs and datasets. Teams routing across cloud and local models still need a small way to connect **declared data-residency tags** to the **policy decision made immediately before a provider call**—without adopting another gateway or storing prompt bodies.

Mirevox Data Lineage is a TypeScript hook for that decision boundary. It records ingress tags, an `allow` / `deny` / `reroute` / `require_local` result, the candidate provider/region, an in-memory lineage graph, and a deterministic SHA-256 checksum of the recorded decision. **Your router remains responsible for enforcing the result.**

- Inputs such as data classes, residency, endpoint, and `leavesPerimeter` are supplied by the caller; the library does not verify them.
- v1 does not inspect network traffic, classify/redact content, confirm provider processing location, detect bypass, or persist records across processes.

Full statement: [docs/problem-statement.md](docs/problem-statement.md). Market: [docs/market-gap.md](docs/market-gap.md).

## v1 slice

| Piece | What it does |
| --- | --- |
| Ingress tagging | Correlation id, tenant, `declaredResidency`, `dataClasses`, optional `contentDigest` |
| Residency policy hooks | `allow` / `deny` / `reroute` / `require_local` (caller must enforce) |
| Lineage graph | Client → ingress → router → policy → provider → region (in-process, ephemeral) |
| Decision checksum (`PerimeterProof`) | `claimLevel: software_attested` = SHA-256 of the recorded JSON decision, not TEE/network proof |

**Honest limit:** `declaredResidency`, `dataClasses`, `candidate.residency`, and `leavesPerimeter` are caller-declared and untrusted. This library does not open sockets, observe DNS/TLS, read CloudTrail, or prove bytes stayed inside a perimeter. **Do not treat `PerimeterProof` or `claimLevel: software_attested` as network-perimeter enforcement or GDPR/HIPAA/EU AI Act/SOC2 compliance evidence.** Default with no matching rule is **allow** (fail-open until you add rules). In-memory `LineageGraph` state is ephemeral per process — call `lineage.graph.clear()` periodically in long-running routers until durable storage ships.

## One-command Docker standup

```bash
cp .env.example .env
docker compose up --build -d
curl -s http://127.0.0.1:${MIREVOX_LINEAGE_PORT:-3847}/health
```

- Compose service: `data-lineage` (healthcheck on `GET /health`, non-root image, read-only rootfs + `/tmp` tmpfs, caps dropped).
- Config: mount `./config/residency-rules.json` (compose pins `MIREVOX_LINEAGE_RULES` so a bad mount **fails closed**).
- Env knobs: see [`.env.example`](.env.example).

Stop: `docker compose down`.

## Library / local quick start

```bash
npm ci
npm test
npm run build
npm run dev   # http://127.0.0.1:3847  (loopback default outside Docker)
```

Demo HTTP endpoints (`MIREVOX_LINEAGE_HOST`, `MIREVOX_LINEAGE_PORT`, `MIREVOX_LINEAGE_RULES`, `MIREVOX_LINEAGE_CORS_ORIGIN`):

- `GET /health` / `GET /readyz` — liveness / readiness
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

## Production gaps (honest)

Hardened for **local/demo one-command standup**, not a full production control plane:

| Gap | Status |
| --- | --- |
| No authn/authz on HTTP demo API | Open — put behind router/mesh or use in-process library only |
| CORS default `*` | Configurable via `MIREVOX_LINEAGE_CORS_ORIGIN`; tighten on shared nets |
| No TLS in compose | Terminate at reverse proxy / ingress |
| In-memory graph only | Lost on restart; no durable ledger in v1 |
| Not an enforcing proxy | Caller must honor `RouteDecision` before egress |
| No provider audit correlation (CloudTrail etc.) | Deferred |
| Multi-replica / HA | Not supported (ephemeral process state) |

Prefer embedding `DataLineageModule` in `smart-router` for production paths; treat the HTTP server as a demo/trace sidecar.

## Compose with other Mirevox modules

- **smart-router** — call `policyHook` / `traceRequest` before fan-out to Foundry, Bedrock, Vertex, or local models.
- **evals** — correlate eval runs via `correlationId` on the same path.
- Showcase website (dark + purple/neon-blue) owns UI chrome; this repo has no product UI.

## Docs

- [Problem statement](docs/problem-statement.md) (locked honesty for v1)
- [Problem & opportunity](docs/problem-opportunity.md) (pre-lock exploration draft)
- [Requirements](docs/requirements.md) (locked after council)
- [Architecture](docs/architecture.md)
- [Market gap](docs/market-gap.md)
- [Devil’s advocate](docs/devils-advocate.md)
- [Acceptance report](docs/acceptance.md)

## License

Apache-2.0

## Verification

Test suite, smoke test, and container verification results are recorded in [`VERIFICATION.md`](./VERIFICATION.md).
