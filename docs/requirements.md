# Mirevox `data-lineage` — Locked v1 Requirements (FR / NFR)

- **Module:** `@mirevox/data-lineage` (`https://github.com/Mirevox/data-lineage`)
- **Status:** Locked for v1 Acceptance & Hardening
- **Date:** 2026-11-20
- **Runtime:** Router-side TypeScript / Node.js (>= 20, ESM) library + optional local demo HTTP server & CLI
- **Inputs Vetted:**
  - `docs/problem-opportunity.md`
  - `docs/requirements-draft.md`
  - `docs/market-gap.md`
  - `docs/devils-advocate.md`
  - `docs/architecture.md`
  - Shipped v1 code under `src/` (`types.ts`, `ingress/tagger.ts`, `policy/residency.ts`, `graph/lineage.ts`, `prove/perimeter.ts`, `module.ts`, `server/main.ts`, `cli.ts`, `index.ts`), `config/residency-rules.json`, `package.json`, `tests/`

---

## 1. Honest Trust-Boundary Note & Language Rules (Non-Negotiable)

> **What "perimeter-provable" / `software_attested` means in v1:**
> A `PerimeterProof` emitted by `@mirevox/data-lineage` carries `claimLevel: "software_attested"`. It is a deterministic SHA-256 checksum over the **recorded policy path and declared hops assembled inside this module** (tag + decision + graph edges). The router or caller **must enforce** `allow` / `deny` / `reroute` / `require_local` before opening an upstream socket.
>
> It is **NOT**:
> - hardware or confidential-computing enforcement (no TEE / TPM / Nitro Enclave / SEV-SNP quote);
> - network, firewall, proxy, or eBPF enforcement (this module opens no sockets and cannot prove an application did not bypass the router or obey a `deny`);
> - cryptographic proof of physical GPU location, sub-processor routing, or retention inside an upstream AI provider;
> - an external tamper-proof audit anchor (a self-hash computed by the same process is a decision-record integrity checksum, not non-repudiable third-party attestation).
>
> `IngressTag.declaredResidency`, `IngressTag.dataClasses`, `ProviderEndpoint.residency`, and `ProviderEndpoint.leavesPerimeter` are **caller-declared inputs**, not network measurements. Stronger guarantees require pairing this module with network egress controls and provider-side audit records (deferred to v2+).

### Language Guardrails (Adopted from `docs/devils-advocate.md`)

- **Allowed (with explicit scope):** router decision record, software checksum, declared residency/region, in-process lineage graph of declared hops, `PerimeterProof` / `claimLevel: "software_attested"` (retained for v1 TypeScript API stability and explicitly documented as software-checksum semantics).
- **Banned unqualified in README, site copy, or release notes:** "perimeter-provable", "compliance-ready", "GDPR-safe", "EU AI Act compliant", "HIPAA-ready", "tamper-evident", "100% coverage", "where data actually went".

---

## 2. Draft-vs-Code Vetting Verdict

**Overall Verdict: `FAIL` (Draft Requirements vs. Shipped v1 Code)**

`docs/requirements-draft.md` specifies a heavyweight multi-subsystem compliance service (SQLite WAL hash-chained ledger, Ed25519 signing, HTTP egress proxy with resolved IP + TLS leaf-certificate fingerprinting and 3xx redirect blocking, built-in regex PII/secrets DLP classifier, YAML policy DSL with `CONSTRAIN`/`AUDIT_ONLY`, dynamic target discovery registry, OTel/Prometheus/Mermaid exporters, and offline `verify-evidence`/`policy test` CLIs).

The actual v1 TypeScript codebase (`@mirevox/data-lineage` v0.1.0, ~530 LOC, single runtime dependency `zod`) ships a lean, shippable **router-side TypeScript library** (`IngressTagger`, `ResidencyPolicyEngine`, `LineageGraph`, `PerimeterProver`, `DataLineageModule`) plus a minimal loopback demo HTTP server (`src/server/main.ts`) and trace CLI (`src/cli.ts`). Both `docs/market-gap.md` and `docs/devils-advocate.md` independently confirm that shipping a DLP engine, custom policy DSL, observability backend, or compliance-suite claims in v1 is the wrong scope.

### 2.1 Major Draft-vs-Code Divergences Resolved in This Spec

| Draft Area | Draft Expectation | Shipped v1 Code (`src/`) | Locked v1 Resolution |
| --- | --- | --- | --- |
| **Ingress Schema** | `X-Mirevox-*` HTTP headers, identity mapping table, `jurisdictions[]`, single `data_class` ladder, provenance precedence, regex DLP hook | `IngressTagger.tag()` with `tenantId`, `sourceId`, `declaredResidency` enum, `dataClasses[]`, `labels`, optional `contentDigest` | **Lock to code schema.** Header parsing, identity lookup, and external DLP belong to the host router or v2 adapters. |
| **Target Registry** | `TargetResidencyRegistry` with YAML config, discovery sync API, `registry_snapshot_sha256`, `declared_zdr` | Stateless `ProviderEndpoint` passed per call (`providerId`, `modelId`, `residency`, `endpoint`, `leavesPerimeter`) | **Lock to stateless `ProviderEndpoint` input.** Host router (`smart-router`) owns discovery and passes candidate + alternatives. |
| **Policy Engine** | `ALLOW\|DENY\|CONSTRAIN\|AUDIT_ONLY`, YAML DSL, `policy test` CLI, fail-closed default | `ResidencyPolicyEngine` with JSON `ResidencyRule[]`, `allow\|deny\|reroute\|require_local`, `createRoutePolicyHook`, `replaceRules`, default-allow on 0 matches | **Lock to 4-state `PolicyDecision` and JSON rules.** Explicitly document default-allow posture when 0 rules match; tighten multi-rule `reroute` soundness. |
| **Egress & Graph** | SQLite WAL / JSONL store, live IP + TLS cert SHA-256 observation, 3xx redirect blocking, filtered query API, Mermaid/DOT/OTel | In-memory `LineageGraph` (`client -> ingress -> router -> policy -> provider -> region`, plus `tool`/`tool_call` schema types) | **Lock to pure in-memory graph.** Core library performs zero network I/O; transport observation and durable stores are v2+. |
| **Perimeter Proofs** | Hash-chained ledger (`seq`, `prev_hash`), Ed25519 signing, tar bundle export, `verify-evidence` CLI | `PerimeterProver.build()` emitting `claimLevel: "software_attested"` + canonical SHA-256 `digest` | **Lock to per-request software-checksum proof + add offline digest verification.** Chained ledger & Ed25519 stay out of v1. |

### 2.2 Concrete Hardening Gaps Found in Current `src/` Code

While `cecb084` already fixed `config/residency-rules.json` (`secrets-local` now restricts `allowResidencies` to `["onprem"]`), added `src/cli.ts`, and tightened comments in `src/prove/perimeter.ts` and `README.md`, vetting the current code uncovered **5 remaining gaps** to close before final v1 hardening sign-off (or explicitly track as follow-up):

1. **Multi-rule `reroute` bypass (`src/policy/residency.ts`):** `evaluate()` returns immediately on the first rule that finds an alternative (`reroute`) without verifying that `suggestedEndpoint` satisfies all remaining applicable rules (e.g., a higher-priority tenant rule could reroute `secrets` traffic to a regional cloud endpoint forbidden by a lower-priority `denyLeavePerimeter` rule).
2. **`tool_call` edges & empty-edge handling in `PerimeterProver` (`src/prove/perimeter.ts`):** `build()` filters only `e.kind === "egress"`, ignoring `e.kind === "tool_call"` edges even when `leavesPerimeter: true`. Also, `egress.every(...)` returns `true` vacuously when `decision === "allow"` and `edges` is empty.
3. **No exported offline digest verifier (`src/prove/perimeter.ts`):** `PerimeterProver` computes a canonical SHA-256 `digest` but exports no `verify()` helper so callers/tests can verify a proof's checksum integrity cleanly.
4. **Silent fail-open rule loading in demo server (`src/server/main.ts`):** When `MIREVOX_LINEAGE_RULES` is explicitly configured to a missing or malformed file, `loadRules()` logs a warning and silently falls back to `demoRules()` instead of failing fast.
5. **Wrong HTTP status & unbounded body in demo server (`src/server/main.ts`):** Invalid JSON or `ZodError` on `POST /v1/trace` falls into the generic `catch` block and returns `500` instead of `400 Bad Request`, and `readJson()` has no body size cap.

---

## 3. Explicit v1 Scope

### 3.1 IN Scope for v1

1. **Ingress Tagging (`IngressTagger`, `digestPayload`, `parseIngressTag`):**
   - Validate and stamp AI-bound requests with `correlationId`, `tenantId`, `sourceId`, `declaredResidency`, `dataClasses`, `labels`, `taggedAt`, and optional SHA-256 `contentDigest` without retaining raw payload bytes on the tag.
2. **Residency Route Policy Hooks (`ResidencyPolicyEngine`, `createRoutePolicyHook`):**
   - Pure, synchronous, priority-ordered evaluation of a candidate `ProviderEndpoint` and optional `alternatives` against validated `ResidencyRule[]`, returning `allow | deny | reroute | require_local` with `reason`, `matchedRuleId`, `suggestedEndpoint`, and `blockedResidencies`.
   - Runtime rule inspection (`listRules`) and atomic validated replacement (`replaceRules`).
3. **In-Memory Egress / Lineage Graph (`LineageGraph`):**
   - Referential-integrity node/edge store (`client`, `ingress`, `router`, `policy`, `provider`, `region`, `tool`; edges `ingress`, `route`, `policy_eval`, `egress`, `tool_call`).
   - Standard hop recording (`recordAiHop`), correlation-scoped edge lookup (`edgesFor`), snapshot export (`snapshot`), and reset (`clear`).
4. **Software-Attested Perimeter Proofs (`PerimeterProver`):**
   - Deterministic `PerimeterProof` generation with `claimLevel: "software_attested"` (decision-record SHA-256 checksum), honest `withinPerimeter` calculation over all recorded perimeter-leaving hops (`egress` and `tool_call`), canonical sorted-key SHA-256 `digest`, and offline digest verification.
5. **Facade, Demo HTTP Server, Config & CLI (`DataLineageModule`, `src/server/main.ts`, `src/cli.ts`, `config/residency-rules.json`):**
   - Single-call `traceRequest()` facade plus `policyHook` and `getGraph()` for direct in-process embedding in `smart-router`.
   - Minimal loopback demo HTTP server (`GET /`, `GET /health`, `GET /rules`, `GET /graph`, `POST /v1/trace`) on `127.0.0.1:3847` (explicitly a demo/trace endpoint, NOT an enforcing proxy), sample rules (`config/residency-rules.json`), `mirevox-lineage trace <request.json> [--rules <rules.json>]` CLI, optional `Dockerfile`, and `Apache-2.0` `LICENSE`.
6. **Offline Deterministic Test Suite:**
   - Vitest unit and integration tests covering all four primitives, the facade, negative validation paths, and claim-honesty assertions with zero network I/O.

### 3.2 OUT of Scope for v1 (Explicit Non-Goals / Deferred to v2+)

- **No network perimeter, proxy, or transport observation:** No outbound HTTP client, MITM proxy, DNS/IP capture, TLS SNI/certificate fingerprinting, SSE stream interception, or HTTP 3xx redirect blocking.
- **No TEE / hardware attestation or cryptographic signing:** No TPM/Nitro quotes, no Ed25519 signing keys, no hash-chained ledger (`seq`/`prev_hash`), no tar evidence bundles, and no external transparency log.
- **No durable storage or graph database:** No SQLite, Postgres, Neo4j, or append-only JSONL disk store in v1 (`LineageGraph` is process-memory only; lost on restart).
- **No compliance-framework evidence claims:** No GDPR, Schrems II, HIPAA, EU AI Act, or SOC 2 compliance assertions.
- **No provider-side audit correlation:** No AWS CloudTrail `inferenceRegion`, Azure Foundry deployment verification, or Vertex audit log ingestion.
- **No built-in DLP / ML classifiers or raw prompt archiving:** No regex secret/PII scanners, prompt redaction, or prompt/completion storage (callers concerned about prompt transit should omit `payload` or hash upstream).
- **No custom policy DSL or external PDP:** No YAML parser, CEL, OPA/Rego engine, or `AUDIT_ONLY` shadow mode in v1.
- **No Target Residency Registry or discovery polling loop:** Host routers pass `ProviderEndpoint` directly.
- **No OTel SDK/collector, Prometheus `/metrics`, OpenLineage export, Mermaid/DOT export, or Web UI dashboard.**
- **No full homelab / Sherali stack dependency; no n8n / Instagram integration.**

*(Future evolution note: per `docs/devils-advocate.md` and `docs/architecture.md`, when `smart-router` lands, prefer importing `DataLineageModule` / `policyHook` in-process and evaluate merging into `smart-router` if no second runtime consumes this package standalone.)*

---

## 4. Normative v1 Data Contracts

All public inputs and outputs MUST conform to the strict Zod schemas exported from `@mirevox/data-lineage` (`src/types.ts`):

- **`ResidencyRegion`**: `"eu" | "us" | "uk" | "ca" | "apac" | "global" | "onprem" | "unknown"`
- **`DataClass`**: `"public" | "internal" | "confidential" | "restricted" | "pii" | "phi" | "secrets"`
- **`IngressTag`**: `{ correlationId, tenantId, sourceId, declaredResidency, dataClasses[], labels, taggedAt, contentDigest? }`
- **`ProviderEndpoint`**: `{ providerId, modelId, residency, endpoint (valid http/https URL or "local://..."), leavesPerimeter }`
- **`ResidencyRule`**: `{ id, description, tenants[], allowResidencies[1..], whenDataClasses[], preferLocal, denyLeavePerimeter, priority (int) }`
- **`PolicyDecision`**: `"allow" | "deny" | "reroute" | "require_local"`
- **`RouteDecision`**: `{ decision, reason, matchedRuleId?, suggestedEndpoint?, blockedResidencies[], evaluatedAt }`
- **`LineageNode`**: `{ id, kind ("client"|"ingress"|"router"|"policy"|"provider"|"region"|"tool"), label, residency?, meta }`
- **`LineageEdge`**: `{ id, from, to, kind ("ingress"|"route"|"egress"|"tool_call"|"policy_eval"), correlationId, leavesPerimeter, at, meta }`
- **`LineageGraphSnapshot`**: `{ nodes[], edges[], capturedAt }`
- **`PerimeterProof`**: `{ proofId, correlationId, tenantId, claimLevel: "software_attested", withinPerimeter, egressHops[], policyDecision, ingressTag, digest, issuedAt }`

---

## 5. Functional Requirements (FR)

### 5.1 Ingress Tagging (`FR-ING`)

#### `FR-ING-01` — Structured Ingress Tagging & Strict Validation
`IngressTagger.tag(input)` MUST validate all inputs via `IngressTagSchema` and return a normalized `IngressTag`. `parseIngressTag(raw)` MUST validate arbitrary unknown values against `IngressTagSchema`.
- **Acceptance Criteria:**
  1. Valid input `{ tenantId, sourceId, declaredResidency, dataClasses?, labels?, correlationId? }` returns a schema-valid `IngressTag` with `dataClasses` defaulting to `[]` and `labels` defaulting to `{}`.
  2. Missing or empty `tenantId` / `sourceId`, an unsupported `declaredResidency` (e.g., `"mars"`), or an unsupported `dataClasses` entry (e.g., `"top_secret"`) throws `ZodError` synchronously without producing a tag.
  3. `parseIngressTag(validObject)` returns the typed `IngressTag`; `parseIngressTag(invalidObject)` throws `ZodError`.

#### `FR-ING-02` — Optional Privacy-Preserving Payload Digesting
When optional `payload` (`string | Uint8Array`) is supplied to `IngressTagger.tag()`, the module MUST compute `contentDigest = digestPayload(payload)` in the format `sha256:<64-lowercase-hex>` over UTF-8 bytes (for strings) or raw bytes (for `Uint8Array`), and MUST NOT retain the raw `payload` on the returned `IngressTag`. Callers that do not want raw prompt bytes crossing into the module MAY omit `payload` entirely.
- **Acceptance Criteria:**
  1. `digestPayload("patient note")` and `digestPayload(new TextEncoder().encode("patient note"))` return identical strings matching `/^sha256:[a-f0-9]{64}$/`.
  2. When `payload` is omitted (`undefined`), `tag.contentDigest` is `undefined`.
  3. Serializing `JSON.stringify(tag)` for a request with canary payload `"CANARY_SECRET_XYZ_999"` contains `contentDigest` and contains `"CANARY_SECRET_XYZ_999"` zero times.

#### `FR-ING-03` — Deterministic Correlation & Injectable Clock
`IngressTagger.tag()` MUST preserve a caller-provided non-empty `correlationId` or generate a UUIDv4 when omitted, and MUST stamp `taggedAt` as an ISO-8601 UTC timestamp using `input.now?.() ?? new Date()`.
- **Acceptance Criteria:**
  1. Calling `tag()` with `correlationId: "corr-1"` and `now: () => new Date("2026-11-20T00:00:00.000Z")` returns `correlationId === "corr-1"` and `taggedAt === "2026-11-20T00:00:00.000Z"`.
  2. Calling `tag()` twice without `correlationId` produces two distinct valid UUID strings.

#### `FR-ING-04` — Extensible String Labels for Cross-Module Correlation
`IngressTag.labels` (`Record<string, string>`) MUST accept string key-value pairs so sibling Mirevox modules (e.g., `evalRunId`, `appcode`, `sourceRef`) can correlate traces without changing core schemas.
- **Acceptance Criteria:**
  1. Passing `labels: { appcode: "appcode-xyz-0", evalRunId: "eval-42" }` preserves both pairs verbatim on `IngressTag` and inside `PerimeterProof.ingressTag.labels`.
  2. Passing non-string label values (e.g., numbers or nested objects) throws `ZodError`.

---

### 5.2 Residency Route Policy Hooks (`FR-POL`)

#### `FR-POL-01` — Pure Synchronous Route Evaluation & Router Hook
`ResidencyPolicyEngine.evaluate({ tag, candidate, alternatives?, now? })` MUST be a pure, synchronous function (zero I/O, zero mutation of inputs or engine state) returning a schema-valid `RouteDecision` with `decision` in `{"allow", "deny", "reroute", "require_local"}`. `createRoutePolicyHook(engine)` MUST expose `(tag, candidate, alternatives?) => RouteDecision` for router mid-pipeline embedding.
- **Acceptance Criteria:**
  1. Evaluating a candidate and alternatives never mutates `tag`, `candidate`, `alternatives`, or `engine.listRules()`.
  2. Invalid `candidate` or `alternatives` endpoints (e.g., malformed URL neither `http(s)://` nor `local://`, or invalid `residency`) throw `ZodError` before returning a decision.
  3. `createRoutePolicyHook(engine)(tag, candidate, alternatives)` returns the same `decision`, `matchedRuleId`, `suggestedEndpoint`, and `blockedResidencies` as `engine.evaluate(...)`.

#### `FR-POL-02` — Deterministic Rule Matching & Priority Semantics
Rules MUST be sorted by ascending integer `priority` (lower number = higher precedence; ties preserve declaration order). A rule matches `tag` iff:
- `rule.tenants` is empty OR `rule.tenants.includes(tag.tenantId)`, AND
- `rule.whenDataClasses` is empty OR at least one element of `rule.whenDataClasses` is present in `tag.dataClasses`.

For matching rules, evaluation MUST enforce:
1. **`denyLeavePerimeter: true` + `candidate.leavesPerimeter === true`:** return `reroute` with an eligible local alternative (`!leavesPerimeter`) if one exists, otherwise `require_local` with `blockedResidencies: [candidate.residency]`.
2. **`candidate.residency` not in `rule.allowResidencies`:** return `reroute` with an eligible alternative if one exists, otherwise `deny` with `blockedResidencies: [candidate.residency]`.
3. **`preferLocal: true` + `candidate.leavesPerimeter === true`:** return `reroute` with an eligible local alternative if one exists, otherwise continue evaluation.
4. **Zero matching rules:** return `allow` with an explicit reason stating no rules matched (default fail-open posture when unconfigured, documented explicitly in `README.md`; operators wanting default-deny add a catch-all rule with `tenants: []`, `whenDataClasses: []`).
- **Acceptance Criteria:**
  1. Given `eu-pii-stay` (`allowResidencies: ["eu", "onprem"]`, `whenDataClasses: ["pii"]`, `denyLeavePerimeter: true`, `priority: 10`), candidate `bedrock/us` (`leavesPerimeter: true`), and alternative `local/onprem` (`leavesPerimeter: false`), `evaluate()` returns `{ decision: "reroute", matchedRuleId: "eu-pii-stay", suggestedEndpoint: local, blockedResidencies: ["us"] }`.
  2. With the same rule and `alternatives: []`, `evaluate()` returns `{ decision: "require_local", matchedRuleId: "eu-pii-stay", blockedResidencies: ["us"] }`.
  3. Given a rule with `denyLeavePerimeter: false`, `allowResidencies: ["ca", "onprem"]`, candidate `us`, and `alternatives: []`, `evaluate()` returns `{ decision: "deny", blockedResidencies: ["us"] }`.
  4. Given rules supplied in reverse priority order (`priority: 20` then `priority: 10`), `priority: 10` is evaluated first.

#### `FR-POL-03` — Multi-Rule Soundness on `reroute` & Unknown-Residency Safety
Any `suggestedEndpoint` returned in a `reroute` decision MUST satisfy **all** applicable rules for `tag` (not only the first rule that rejected `candidate`), preventing a higher-priority rule from suggesting an endpoint forbidden by another matching rule. A candidate with `residency: "unknown"` MUST be rejected (`deny` or `reroute` to a compliant alternative) whenever any applicable rule omits `"unknown"` from `allowResidencies`.
- **Acceptance Criteria:**
  1. Given Rule A (`priority: 10`, `tenants: ["acme"]`, `allowResidencies: ["eu", "onprem"]`, `denyLeavePerimeter: false`) and Rule B (`priority: 20`, `whenDataClasses: ["secrets"]`, `allowResidencies: ["onprem"]`, `denyLeavePerimeter: true`), evaluating tenant `"acme"` with `dataClasses: ["secrets"]`, candidate `us/cloud`, and alternatives `[eu/cloud (leavesPerimeter: true), local/onprem (leavesPerimeter: false)]` MUST NOT suggest `eu/cloud`; it MUST suggest `local/onprem` (or return `require_local`/`deny` if only `eu/cloud` is offered).
  2. Evaluating a candidate with `residency: "unknown"` against any rule whose `allowResidencies` is `["eu", "onprem"]` returns `deny` (or `reroute` to an eligible alternative) with `"unknown"` in `blockedResidencies`.

#### `FR-POL-04` — Atomic Validated Rule Management
`ResidencyPolicyEngine` MUST expose `listRules()` (returning a defensive shallow copy) and `replaceRules(rules)` which validates every rule against `ResidencyRuleSchema` before replacing the active rule set.
- **Acceptance Criteria:**
  1. Mutating the array returned by `listRules()` (e.g., `.pop()`) does not alter subsequent `evaluate()` outcomes.
  2. Calling `replaceRules()` with one valid rule and one invalid rule (e.g., `allowResidencies: []`) throws `ZodError` and leaves the previously active rules unchanged.

#### `FR-POL-05` — Multi-Hop & Fallback Re-Evaluation Contract
Because `evaluate()` is stateless per call, a host router performing retries, fallbacks, fan-out sub-requests, or remote tool calls MUST be able to invoke `policyHook(tag, hopCandidate, hopAlternatives)` independently for each candidate using the same `IngressTag`.
- **Acceptance Criteria:**
  1. Calling `policyHook` sequentially for 3 hops sharing one `IngressTag` (`dataClasses: ["pii"]`) — `local/onprem`, `bedrock/us`, and a remote `us` endpoint (`leavesPerimeter: true`) — deterministically returns `allow`, `require_local`, and `require_local` with zero cross-call state leakage.

---

### 5.3 Egress / Lineage Graph (`FR-GRF`)

#### `FR-GRF-01` — Typed Node & Edge Store with Referential Integrity
`LineageGraph` MUST validate nodes via `LineageNodeSchema` and edges via `LineageEdgeSchema`, and MUST enforce referential integrity in `addEdge()`: adding an edge whose `from` or `to` node does not exist MUST throw an `Error`.
- **Acceptance Criteria:**
  1. `upsertNode()` stores a valid node and updates in place when called again with the same `id` (no duplicate node IDs).
  2. `addEdge()` referencing an unknown `from` or `to` throws an error identifying the missing node(s) and leaves `edges` unchanged.

#### `FR-GRF-02` — Standard AI Hop Recording (`recordAiHop`)
`LineageGraph.recordAiHop({ tag, routerId?, candidate, decision, now? })` MUST record the canonical 6-node / 5-edge declared path:
- Nodes: `client:<sourceId>`, `ingress:<correlationId>`, `<routerId>` (default `"router:default"`), `policy:<correlationId>`, `provider:<providerId>:<modelId>`, `region:<residency>`
- Edges: `client -> ingress` (`ingress`), `ingress -> router` (`route`), `router -> policy` (`policy_eval`), `policy -> provider` (`egress`), `provider -> region` (`egress`)
- Perimeter flag: `leavesPerimeter` MUST be `true` on `egress` edges **if and only if** `decision.decision === "allow" && candidate.leavesPerimeter === true`; on `deny`, `reroute`, or `require_local`, `leavesPerimeter` MUST be `false` and `meta.decision` MUST record the decision value so consumers can distinguish blocked attempts from permitted egress.
- **Acceptance Criteria:**
  1. Allowed external hop (`decision: "allow"`, `leavesPerimeter: true`) creates 6 nodes and 5 edges where both `egress` edges have `leavesPerimeter === true` and all 5 edges share `tag.correlationId`.
  2. Denied external hop (`decision: "deny"`, `leavesPerimeter: true`) creates edges where every edge has `leavesPerimeter === false` and `policy -> provider` records `meta.decision === "deny"`.
  3. Allowed local hop (`decision: "allow"`, `leavesPerimeter: false`) creates edges where every edge has `leavesPerimeter === false`.

#### `FR-GRF-03` — Multi-Hop & Tool-Call Extensibility
`LineageGraph` MUST support attaching additional `tool` nodes and `tool_call` edges linked to an existing `correlationId` via `upsertNode()` / `addEdge()` without overwriting prior edges for that `correlationId`.
- **Acceptance Criteria:**
  1. After `recordAiHop()` for `correlationId: "c-1"`, adding a `tool` node (`kind: "tool"`, `residency: "us"`) and `tool_call` edge (`from: "router:default"`, `to: "tool:mcp-search"`, `correlationId: "c-1"`, `leavesPerimeter: true`) causes `edgesFor("c-1")` to return 6 edges and `snapshot("c-1")` to include the `tool` node.

#### `FR-GRF-04` — Scoped Snapshots & Lifecycle Reset
`LineageGraph` MUST expose `edgesFor(correlationId)`, `snapshot(correlationId?)` returning a schema-valid `LineageGraphSnapshot`, and `clear()` to reset process memory.
- **Acceptance Criteria:**
  1. After recording two requests (`corr-A`, `corr-B`), `snapshot("corr-A")` returns **only** edges with `correlationId === "corr-A"` and **only** nodes referenced by those edges.
  2. `snapshot()` with no argument returns all stored nodes and edges.
  3. `clear()` empties both nodes and edges so subsequent `snapshot()` returns `{ nodes: [], edges: [], capturedAt }`.

---

### 5.4 Software-Attested Perimeter Proofs (`FR-PRV`)

#### `FR-PRV-01` — Decision-Record Proof Construction
`PerimeterProver.build({ tag, decision, edges, nodes, now? })` MUST emit a schema-valid `PerimeterProof` containing:
- `proofId` (UUIDv4), `correlationId`, `tenantId`, `issuedAt` (ISO-8601 UTC)
- `claimLevel`: strict literal `"software_attested"` (meaning: software checksum over the recorded decision JSON; NOT TEE or hardware/network enforcement)
- `egressHops`: array of all perimeter-relevant recorded edges (`edge.kind === "egress"` or `edge.kind === "tool_call"`), each with `{ edgeId, to, residency?, leavesPerimeter }`
- `withinPerimeter`: boolean
- `policyDecision`: the `RouteDecision`
- `ingressTag`: the `IngressTag`
- `digest`: `sha256:<64-lowercase-hex>`
- **Acceptance Criteria:**
  1. `PerimeterProofSchema.parse(proof)` succeeds and `proof.claimLevel === "software_attested"`.
  2. Passing any other `claimLevel` (e.g., `"tee_attested"`, `"hardware_enforced"`) into `PerimeterProofSchema.parse()` throws `ZodError`.

#### `FR-PRV-02` — Honest Containment Semantics (`withinPerimeter`)
`PerimeterProver.build()` MUST compute `withinPerimeter` strictly from the recorded decision and recorded hops (never claiming network enforcement):
- If ANY recorded `egress` OR `tool_call` edge has `leavesPerimeter === true`: `withinPerimeter = false` (regardless of `decision`).
- If `decision.decision !== "allow"` (`deny`, `require_local`, `reroute`) AND zero recorded `egress`/`tool_call` edges have `leavesPerimeter === true`: `withinPerimeter = true` (reflecting the recorded non-allow decision; caller must still enforce the deny).
- If `decision.decision === "allow"` and `egressHops.length === 0`: MUST fail closed (either set `withinPerimeter = false` or throw — never vacuously attest `withinPerimeter: true` with zero hop records).
- **Acceptance Criteria:**
  1. Allowed local hop (`leavesPerimeter: false` on all egress edges) -> `withinPerimeter === true`.
  2. Allowed external hop (`leavesPerimeter: true` on egress edge) -> `withinPerimeter === false`.
  3. Denied / `require_local` / `reroute` hop (zero edges with `leavesPerimeter: true`) -> `withinPerimeter === true`.
  4. Allowed local model hop plus an allowed external `tool_call` edge (`leavesPerimeter: true`) -> `withinPerimeter === false` and the `tool_call` hop appears in `egressHops`.
  5. Calling `build()` with `decision: "allow"` and `edges: []` does NOT return `withinPerimeter === true`.

#### `FR-PRV-03` — Canonical SHA-256 Digest & Offline Checksum Verification
`PerimeterProof.digest` MUST be computed as `sha256:<hex>` over recursively key-sorted JSON (`stableStringify`) of the proof payload excluding `digest`. The module MUST export an offline verification helper (e.g., `verifyPerimeterProof(proof)` / `prover.verify(proof)`) that validates schema conformance and recomputes the canonical SHA-256 digest.
- **Acceptance Criteria:**
  1. For any `proof` produced by `PerimeterProver.build()`, verifying `proof` and verifying `JSON.parse(JSON.stringify(proof))` both pass.
  2. Mutating any single field (e.g., flipping `withinPerimeter`, changing `ingressTag.declaredResidency`, altering `policyDecision.decision`, or dropping an `egressHops` entry) causes verification to fail deterministically.
  3. Reordering object keys in JSON before parsing does not break verification.

#### `FR-PRV-04` — Explicit Claim Boundary (No Overclaiming)
`README.md`, `src/prove/perimeter.ts`, and `docs/requirements.md` MUST explicitly state that `software_attested` is a decision-record checksum over the policy path recorded by this module, NOT TEE attestation, NOT network bypass protection, and NOT provider-region proof.
- **Acceptance Criteria:**
  1. `PerimeterProofSchema` locks `claimLevel` to `z.literal("software_attested")`.
  2. `README.md` contains the explicit honest-limit statement and none of the banned unqualified compliance/perimeter claims in §1.

---

### 5.5 Module Facade, Demo HTTP Server, Config & CLI (`FR-MOD`)

#### `FR-MOD-01` — End-to-End `DataLineageModule` Facade
`DataLineageModule` MUST compose `tagger`, `policy`, `graph`, `prover`, and `policyHook` and expose:
- `traceRequest(input: TraceRequestInput): TraceRequestResult` executing `tag -> evaluate -> recordAiHop -> buildProof` synchronously and returning `{ tag, decision, graph, proof }`.
- `getGraph(correlationId?): LineageGraphSnapshot`.
- **Acceptance Criteria:**
  1. `traceRequest()` returns a `TraceRequestResult` where `tag.correlationId === proof.correlationId`, `decision === proof.policyDecision`, `graph.edges` contains only edges for `tag.correlationId`, and `proof.digest` verifies cleanly offline.

#### `FR-MOD-02` — Minimal Loopback Demo HTTP Server (`src/server/main.ts`)
The optional HTTP server (explicitly a demo/trace API, NOT an enforcing proxy) MUST expose:
- `GET /` — service metadata and endpoint index (`200`)
- `GET /health` — liveness (`200`, `{ ok: true, service: "@mirevox/data-lineage", version }`)
- `GET /rules` — active `ResidencyRule[]` (`200`)
- `GET /graph?correlationId=<id>` — full or filtered `LineageGraphSnapshot` (`200`)
- `POST /v1/trace` — runs `traceRequest()` and returns `TraceRequestResult` (`200`)
- **Acceptance Criteria:**
  1. Missing required fields, malformed JSON, or `ZodError` schema violations on `POST /v1/trace` return `400 Bad Request` with JSON `{ error: string }` (NOT `500`), without stack traces.
  2. Unknown routes return `404 Not Found` with JSON `{ error: "not found" }`.

#### `FR-MOD-03` — Config File & Fail-Closed Explicit Rule Loading
`config/residency-rules.json` MUST ship valid default rules (including EU PII/PHI residency and `onprem`-only secrets rule). When `MIREVOX_LINEAGE_RULES` is explicitly set in the environment, the demo server MUST fail fast (non-zero exit with a clear error) if the file is unreadable, not a JSON array, or fails `ResidencyRuleSchema` validation. Built-in demo rules may load ONLY when `MIREVOX_LINEAGE_RULES` is unset and no default `config/residency-rules.json` exists.
- **Acceptance Criteria:**
  1. `config/residency-rules.json` parses cleanly against `ResidencyRuleSchema[]` and restricts `secrets` to `allowResidencies: ["onprem"]` with `denyLeavePerimeter: true`.
  2. Starting the server with `MIREVOX_LINEAGE_RULES=/nonexistent/rules.json` or an invalid rules file exits non-zero rather than silently falling back to `demoRules()`.

#### `FR-MOD-04` — Trace CLI (`src/cli.ts`)
The `mirevox-lineage` bin (`dist/cli.js`) MUST support `mirevox-lineage trace <request.json> [--rules <rules.json>]`, printing the JSON `TraceRequestResult` to stdout and exiting `0` on valid input, or printing usage/error to stderr and exiting non-zero on invalid arguments or malformed input.
- **Acceptance Criteria:**
  1. Running `node dist/cli.js trace examples/sample-request.json --rules config/residency-rules.json` prints valid JSON containing `tag`, `decision`, `graph`, and `proof` and exits `0`.
  2. Invoking with missing arguments exits `2` with usage message on stderr.

---

## 6. Non-Functional Requirements (NFR)

| ID | Category | Requirement | Measurable Acceptance Criterion |
| --- | --- | --- | --- |
| **`NFR-01`** | **In-Process Latency Budget** | Core synchronous router-path calls (`evaluate`, `traceRequest`) MUST add negligible overhead inside a host router event loop. | Benchmarked in-process on a standard 2-vCPU Linux VM (Node >= 20) over 1,000 iterations with 100 residency rules and a 16 KiB payload: `ResidencyPolicyEngine.evaluate()` **p95 < 1.0 ms** (median < 0.2 ms); `DataLineageModule.traceRequest()` **p95 < 2.0 ms** (median < 0.5 ms). |
| **`NFR-02`** | **Zero Network Required for Core Library** | Importing and executing the library exports (`@mirevox/data-lineage`) and running the full unit/integration test suite MUST require zero network connectivity, zero external daemons, and zero cloud SDKs/API keys. | Core modules under `src/` (excluding optional `src/server/main.ts`) import zero networking modules (`node:http`, `node:https`, `node:net`, `node:dns`, `fetch`); `npm test`, `npm run typecheck`, and `npm run build` pass 100% offline with zero env secrets set. |
| **`NFR-03`** | **Claim Honesty (`software_attested`, Not TEE)** | All proofs, schemas, and documentation MUST accurately represent the software-checksum trust boundary and never claim TEE, hardware enforcement, or compliance certification. | `PerimeterProof.claimLevel` is locked to literal `"software_attested"`; automated schema test rejects alternative claim levels; `README.md`, `src/prove/perimeter.ts`, and `docs/requirements.md` state recorded-path semantics and obey §1 language guardrails. |
| **`NFR-04`** | **Privacy-by-Default (No Raw Payload Storage)** | Raw request payloads MUST NOT be stored on `IngressTag`, `LineageGraph`, `PerimeterProof`, or `GET /graph` output; `payload` remains optional so callers can omit raw prompt bytes completely. | Automated canary test passes `"CANARY_PRIVATE_PAYLOAD_123"` into `traceRequest()` and asserts the canary appears 0 times across `JSON.stringify(result)` and `JSON.stringify(mod.getGraph())`, while `sha256:` digest is present. |
| **`NFR-05`** | **Determinism & Offline Verification Speed** | Digests, policy decisions, and test outcomes MUST be deterministic and fast for tight council iteration. | Running `npm run typecheck && npm run build && npm test` twice consecutively offline yields 100% pass rate in **< 10 seconds** total; identical inputs with injected `now` and `correlationId` yield identical `contentDigest`, `RouteDecision`, and canonical proof payload hashes. |
| **`NFR-06`** | **Minimal Footprint & Packaging Hygiene** | Module MUST stay lean, strictly typed, single-VM / Docker-friendly, and cleanly packaged. | `tsconfig.json` enforces `strict: true` and `noUncheckedIndexedAccess: true`; production runtime dependencies <= 3 (v1 target: `zod` only); `package.json` `exports` and `bin` resolve after `npm run build`; demo server baseline RSS **< 128 MB**; `Dockerfile` builds cleanly; `Apache-2.0` `LICENSE` present. |
| **`NFR-07`** | **Demo Server Loopback Default & Input Bounds** | Optional demo HTTP server MUST default to loopback (`127.0.0.1`), enforce request body size limits, and sanitize error responses. | Default `HOST === "127.0.0.1"`; request bodies exceeding 1 MiB return `413 Payload Too Large`; 4xx/5xx responses return JSON `{ error }` with zero stack traces (`at ` / file paths). |
| **`NFR-08`** | **Explicit In-Memory & Declared-Field Transparency** | Process-memory graph lifecycle, caller-declared input trust, and default-allow posture MUST be documented transparently. | `LineageGraph.clear()` resets memory deterministically; `README.md` and `docs/architecture.md` explicitly note in-memory persistence (lost on restart), caller-declared fields (`declaredResidency`, `leavesPerimeter`), and default-allow when zero rules match. |

---

## 7. v1 Acceptance Verification Matrix

`Current Code Status` reflects the vetted state of `/agent/repos/data-lineage` at commit `33251ea` (with `src/cli.ts`, tightened `config/residency-rules.json`, and `docs/devils-advocate.md` present).

| Pillar | Locked Req IDs | Verification Method | Current Code Status | Exit Gate (Pass Condition) |
| --- | --- | --- | --- | --- |
| **Ingress Tagging** | `FR-ING-01`–`04`, `NFR-04` | Unit tests (`tests/ingress.test.ts`) | **PASS** (expand negative & canary tests) | Valid tagging, UUID/clock injection, SHA-256 `contentDigest`, zero canary plaintext leakage, `ZodError` on invalid enums/labels. |
| **Residency Policy Hooks** | `FR-POL-01`–`05`, `NFR-01` | Unit + multi-rule + perf tests (`tests/policy.test.ts`) | **PARTIAL** (fix multi-rule `reroute` soundness) | All 4 decisions tested, priority order verified, `reroute` target satisfies *all* applicable rules, `"unknown"` residency rejected, atomic `replaceRules`, p95 < 1 ms. |
| **Egress / Lineage Graph** | `FR-GRF-01`–`04`, `NFR-08` | Unit tests (`tests/graph.test.ts`) | **PASS** (add dedicated graph & `tool_call` tests) | Referential integrity enforced, 6-node/5-edge hop recorded, `leavesPerimeter` accurate on allow vs. deny, `tool_call` edges & correlation-scoped `snapshot()` + `clear()` verified. |
| **Software-Attested Proofs** | `FR-PRV-01`–`04`, `NFR-03` | Unit + tamper tests (`tests/proof.test.ts`) | **GAP** (fix `tool_call`/empty-edge containment + add `verify()`) | `claimLevel === "software_attested"`, `tool_call` with `leavesPerimeter: true` sets `withinPerimeter: false`, empty-edge `allow` fails closed, `verify()` passes intact & fails tampered proofs. |
| **Facade, Server, Config & CLI** | `FR-MOD-01`–`04`, `NFR-01`, `NFR-06`, `NFR-07` | Integration + CLI smoke tests (`tests/lineage-module.test.ts`) | **PARTIAL** (CLI + config PASS; fix `400` status, 1 MiB cap, fail-closed `MIREVOX_LINEAGE_RULES`) | `traceRequest()` p95 < 2 ms; CLI traces sample request; server returns `400` on invalid input, `413` on oversized body, exits non-zero on invalid explicit rules file. |
| **Offline & Honesty Gate** | `NFR-02`, `NFR-03`, `NFR-05`, `NFR-06`, `NFR-08` | Offline CI (`typecheck`, `build`, `test`) + doc check | **PASS** (re-verify after hardening) | Zero network imports in core lib; full suite passes offline in < 10 s; README & docs obey §1 trust-boundary & language rules. |
