# Architecture — @mirevox/data-lineage v1

## Role

Library-first **router-side module**. A smart-router (or any gateway) imports it, tags requests, evaluates residency policy **before** provider egress, and optionally records a declared-path lineage graph + decision checksum.

```text
Client / harness
    │
    ▼
┌─────────────────────────────────────┐
│  smart-router (future) / demo caller│
│                                     │
│  DataLineageModule.traceRequest()   │
│    1. IngressTagger                 │
│    2. ResidencyPolicyEngine         │
│    3. LineageGraph.recordAiHop      │
│    4. PerimeterProver.build         │
│                                     │
│  ENFORCE decision → then open socket│
└──────────────────┬──────────────────┘
                   │ only if allow
        ┌──────────┼──────────┐
        ▼          ▼          ▼
     local      regional    other
     model      cloud API   MCP…
```

## Packages / modules

| Path | Responsibility |
| --- | --- |
| `src/types.ts` | Zod schemas: tags, rules, endpoints, graph, proof |
| `src/ingress/tagger.ts` | Mint ingress tags + optional payload digest |
| `src/policy/residency.ts` | Rule engine + `createRoutePolicyHook` |
| `src/graph/lineage.ts` | In-memory node/edge store; `recordAiHop` |
| `src/prove/perimeter.ts` | Decision-record SHA-256 (`software_attested`) |
| `src/module.ts` | Facade `DataLineageModule` |
| `src/server/main.ts` | Demo HTTP API (not an enforcing proxy) |
| `src/cli.ts` | `mirevox-lineage trace` |
| `config/residency-rules.json` | Sample rules |

## `POST /v1/trace` sequence

1. Parse JSON body (tenant, source, declared residency, data classes, candidate, alternatives).
2. `tagger.tag` → `IngressTag`.
3. `policy.evaluate` → `RouteDecision`.
4. `graph.recordAiHop` → nodes/edges (including on deny; edges mark `leavesPerimeter` only when decision is `allow` and candidate leaves).
5. `prover.build` → checksum over assembled record.
6. Return `{ tag, decision, graph, proof }`.

Caller must not treat HTTP 200 as “egress happened.”

## Policy evaluation order

Rules sorted by ascending `priority`. First applicable rule that denies, requires local, or suggests reroute wins. Applicability: tenant list (empty = all) and `whenDataClasses` (empty = all classes). If no rule matches → **allow**.

## Trust boundaries

| Input | Trust |
| --- | --- |
| `declaredResidency`, `dataClasses`, `leavesPerimeter` | Caller-declared; untrusted |
| Rule file | Operator-trusted |
| Proof digest | Self-hash of this process’s JSON; not an external trust anchor |
| Graph store | Process memory; lost on restart |

## Docker

`Dockerfile` multi-stage build exposes port `3847`. Optional for cloud-VM `npm run dev`. Not a homelab dependency.

## Explicit non-architecture (v1)

No sidecar MITM proxy, no persistent ledger, no provider adapters, no OTel SDK, no UI.

## Evolution

When smart-router lands, prefer importing `DataLineageModule` / `policyHook` in-process. Demo server may remain for manual traces. See kill/merge notes in `docs/devils-advocate.md`.
