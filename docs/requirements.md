# Mirevox data-lineage — Locked requirements (v1)

**Status:** Locked for acceptance  
**Inputs:** product-synthesis §6, requirements-draft, market-gap, devil’s-advocate, shipped code in `src/`  
**Repo:** https://github.com/Mirevox/data-lineage (push pending org create)

## 1. Product statement (honest)

v1 is a **router-side TypeScript library** that:

1. Tags an AI-bound request (ingress),
2. Evaluates residency route policy hooks,
3. Records an in-process egress/lineage graph of the *declared* path,
4. Returns a **decision record** with a software checksum of that record.

The router (or demo caller) **must enforce** allow/deny/reroute before opening an upstream socket. This module does not open sockets, observe DNS/TLS, or prove provider-side residency.

## 2. v1 IN scope

| ID | Capability | Acceptance |
| --- | --- | --- |
| FR-01 | **Ingress tagging** via `IngressTagger` / `DataLineageModule.traceRequest`: `correlationId`, `tenantId`, `sourceId`, `declaredResidency`, `dataClasses`, optional `contentDigest` | Unit test tags PII request; digest matches `sha256:` hex when payload provided |
| FR-02 | **Residency policy engine** with rules: tenant filter, data-class filter, allow-list residencies, `preferLocal`, `denyLeavePerimeter`; decisions `allow` \| `deny` \| `reroute` \| `require_local` | Tests: PII+US cloud → reroute/require_local; onprem allow; empty rules → allow |
| FR-03 | **`RoutePolicyHook`** exported for smart-router mid-pipeline | Hook returns same decision as engine for identical inputs |
| FR-04 | **Lineage graph** nodes/edges for client→ingress→router→policy→provider→region; filterable by `correlationId` | After `traceRequest`, snapshot has ≥1 egress edge; filter returns only that correlation |
| FR-05 | **Decision record checksum** (`PerimeterProof` type name kept for API; `claimLevel: software_attested` means SHA-256 of assembled JSON only) | Proof includes tag, decision, egress hops, digest; docs/README state non-TEE |
| FR-06 | **Demo HTTP server** (`POST /v1/trace`, `GET /graph`, `GET /rules`, `GET /health`) on configurable port | Smoke: health 200; trace returns decision+graph+proof |
| FR-07 | **Config file** `config/residency-rules.json` loaded by server | EU PII rule + onprem-only secrets rule present |
| FR-08 | **CLI** `mirevox-lineage trace <json> [--rules …]` | Prints JSON decision for sample request |

## 3. v1 OUT of scope (non-goals)

- Network perimeter, firewall, proxy enforcement, socket/DNS/SNI/cert observation
- TEE / TPM / Nitro quotes, Ed25519 keys, hash-chained ledgers, offline verifiers
- GDPR / HIPAA / EU AI Act / SOC2 evidence claims
- Provider audit ingest (CloudTrail, Foundry, Vertex location APIs)
- DLP/ML classifiers, prompt persistence stores, graph databases, UI dashboards
- MCP fan-out tracing, OpenLineage export, OTel collector dependency
- Full homelab / Sherali stack; n8n/Instagram

## 4. Non-functional requirements

| ID | Requirement | Measure |
| --- | --- | --- |
| NFR-01 | Core library works in-process with no network | `npm test` passes offline |
| NFR-02 | TypeScript, Node ≥20, Apache-2.0 | `package.json` + `LICENSE` |
| NFR-03 | Docker-friendly layout | `Dockerfile` builds server image (optional; not required to run v1) |
| NFR-04 | Claim honesty | README forbids treating proofs as perimeter/compliance evidence |
| NFR-05 | Default policy posture | No matching rule → **allow** (fail-open); documented |
| NFR-06 | Declared vs observed | Fields that are caller-supplied are documented as declared (`declaredResidency`, `leavesPerimeter`) |

## 5. Language rules (from devil’s advocate, partial adopt)

**Allowed with qualification:** decision record, software checksum, declared residency, lineage graph (in-process, declared hops).

**Banned in marketing / site copy without qualifier:** perimeter-provable, compliance-ready, GDPR-safe, tamper-evident, 100% coverage, “where data actually went.”

Type name `PerimeterProof` may remain for API stability; README and `claimLevel` docs must state software-checksum semantics.

## 6. Composition

Primary consumer: future **smart-router**. Until that exists, the library + demo server are the runnable slice. Kill/merge criteria into smart-router are recorded in `docs/devils-advocate.md`; not blocking this v1 tag.

## 7. Acceptance exit

v1 accepted when:

1. `npm test` green  
2. `npm run build` green  
3. Demo `/health` + `/v1/trace` smoke pass  
4. Docs present: problem-opportunity, requirements (this file), architecture, market-gap, devil’s-advocate, README  
5. Claims in README match §1–§5  
