# Problem statement — Mirevox `data-lineage`

**Module:** [`@mirevox/data-lineage`](https://github.com/Mirevox/data-lineage)  
**Status:** Honest v1 (library + optional demo HTTP sidecar)  
**License:** Apache-2.0

## The problem

Teams that route AI traffic across cloud providers (Bedrock, Foundry, Vertex) and local models lose a clear answer to: *for this request, what data class left, under which residency rule, to which declared endpoint?*

Unified routers hide that path. Fallbacks and remote tool calls make it worse: an “EU-primary” route with an unrestricted global fallback is not an EU-resident route. Hyperscaler audit logs only see their own cloud. Gateway observability products log requests well, but rarely bind **ingress classification → policy decision → chosen route** into one portable, content-minimized evidence record.

## What v1 actually solves

A small **router-side TypeScript module** that:

1. **Tags** AI-bound requests (`tenantId`, `declaredResidency`, `dataClasses`, optional SHA-256 `contentDigest` — no raw payload retention on the tag).
2. **Evaluates** residency rules into `allow | deny | reroute | require_local` (caller must enforce before opening an upstream socket).
3. **Records** an in-memory declared-hop lineage graph for the request correlation id.
4. **Emits** a `PerimeterProof` with `claimLevel: "software_attested"` — a SHA-256 checksum over the recorded decision JSON, **not** TEE, network, or provider-region proof.

## What v1 does **not** claim

- Not a network perimeter, proxy, or firewall.
- Not GDPR / HIPAA / EU AI Act / SOC 2 compliance evidence.
- Not proof of where a provider physically processed bytes.
- Not durable storage, DLP classification, or a general-purpose AI gateway.

`declaredResidency`, `dataClasses`, `candidate.residency`, and `leavesPerimeter` are **caller-declared**. Default with zero matching rules is **allow** (fail-open until you add rules).

## Why this is still worth shipping

The market already has gateways, DLP, OTel, and OpenLineage. The narrow gap v1 targets is a **vendor-neutral decision-record contract at the AI router boundary** that sibling Mirevox modules (especially `smart-router`) can embed without standing up another compliance platform.

## One-command local demo

```bash
cp .env.example .env
docker compose up --build -d
curl -s http://127.0.0.1:3847/health
```

See the root [README](../README.md) for library usage, honesty limits, and known production gaps.
