# Mirevox `data-lineage` — Locked v1 Requirements (FR / NFR)

- **Module:** `@mirevox/data-lineage` (`https://github.com/Mirevox/data-lineage`)
- **Status:** Locked for v1 Acceptance & Hardening
- **Date:** 2026-11-20
- **Runtime:** Router-side TypeScript / Node.js (>= 20, ESM) library + optional local HTTP sidecar
- **Inputs Vetted:**
  - `docs/problem-opportunity.md`
  - `docs/requirements-draft.md`
  - `docs/market-gap.md`
  - `src/` (`types.ts`, `ingress/tagger.ts`, `policy/residency.ts`, `graph/lineage.ts`, `prove/perimeter.ts`, `module.ts`, `server/main.ts`, `index.ts`)
  - `tests/` (`ingress.test.ts`, `policy.test.ts`, `lineage-module.test.ts`), `package.json`, `config/residency-rules.json`

---

## 1. Honest Trust-Boundary Note (Non-Negotiable)

> **What "perimeter-provable" means in v1:**
> A `PerimeterProof` emitted by `@mirevox/data-lineage` carries `claimLevel: "software_attested"`. It is a deterministic, SHA-256 digest-bound record of the **policy evaluation and egress hops recorded inside this module** on the router path.
>
> It is **NOT**:
> - hardware or confidential-computing attestation (no TEE / Nitro Enclave / SEV-SNP verification);
> - kernel, eBPF, or VPC egress-firewall enforcement (it cannot prove an application did not bypass the router directly to an external API);
> - cryptographic proof of physical GPU location, sub-processor routing, or retention inside an upstream AI provider.
>
> `IngressTag.declaredResidency` and `ProviderEndpoint.residency` are **declared metadata**, not independently verified physical locations. Stronger guarantees require pairing this module with network egress controls (restricting direct outbound traffic outside the router) and provider-side audit logs (e.g., CloudTrail `inferenceRegion`, deferred to v2+).

---

## 2. Draft-vs-Code Vetting Verdict

**Overall Verdict: `FAIL` (Draft Requirements vs. Shipped v1 Code)**

`docs/requirements-draft.md` specifies a heavyweight multi-subsystem service (SQLite WAL hash-chained ledger, Ed25519 signing, HTTP egress proxy with TLS leaf-certificate fingerprinting and 3xx redirect interception, built-in regex PII/secrets DLP classifier, YAML policy DSL with `CONSTRAIN`/`AUDIT_ONLY`, dynamic target discovery registry, OTel/Prometheus/Mermaid exporters, and offline `verify-evidence`/`policy test` CLIs).

The actual v1 TypeScript codebase (`@mirevox/data-lineage` v0.1.0, ~460 LOC, single runtime dependency `zod`) ships a much leaner, shippable **in-process router-side TypeScript module** (`IngressTagger`, `ResidencyPolicyEngine`, `LineageGraph`, `PerimeterProver`, `DataLineageModule`) plus a minimal loopback HTTP sidecar (`src/server/main.ts`). Per `docs/market-gap.md`, building a DLP engine, another policy DSL, or an observability backend in v1 is explicitly the wrong scope.

### 2.1 Major Draft-vs-Code Divergences Resolved in This Spec

| Draft Area | Draft Expectation | Shipped v1 Code (`src/`) | Locked v1 Resolution |
| --- | --- | --- | --- |
| **Ingress Schema** | `X-Mirevox-*` HTTP headers, identity mapping table, `jurisdictions[]`, single `data_class` ladder, provenance precedence, regex DLP hook | `IngressTagger.tag()` with `tenantId`, `sourceId`, `declaredResidency` enum, `dataClasses[]`, `labels`, optional `contentDigest` | **Lock to code schema.** Header parsing, identity lookup, and external DLP classifiers belong to the host router or v2 adapters. |
| **Target Registry** | `TargetResidencyRegistry` with YAML config, discovery sync API, `registry_snapshot_sha256`, `declared_zdr` | Stateless `ProviderEndpoint` passed into `evaluate()` per call (`providerId`, `modelId`, `residency`, `endpoint`, `leavesPerimeter`) | **Lock to stateless `ProviderEndpoint` input.** Host router (`smart-router`) owns discovery and passes candidate + alternatives. |
| **Policy Engine** | `ALLOW\|DENY\|CONSTRAIN\|AUDIT_ONLY`, YAML DSL, `policy test` CLI, multi-hop re-invocation | `ResidencyPolicyEngine` with JSON `ResidencyRule[]`, `allow\|deny\|reroute\|require_local`, `createRoutePolicyHook`, `replaceRules` | **Lock to 4-state `PolicyDecision` and JSON rules.** Tighten multi-rule `reroute` soundness and unknown-residency handling. |
| **Egress & Graph** | SQLite WAL / JSONL store, live IP + TLS cert SHA-256 observation, 3xx redirect blocking, filtered query API, Mermaid/DOT/OTel | In-memory `LineageGraph` (`client -> ingress -> router -> policy -> provider -> region`, plus `tool`/`tool_call` types) | **Lock to pure in-memory graph.** Core library performs zero network I/O; transport observation and durable stores are v2+. |
| **Perimeter Proofs** | Hash-chained ledger (`seq`, `prev_hash`), Ed25519 signing, tar bundle export, `verify-evidence` CLI | `PerimeterProver.build()` emitting `claimLevel: "software_attested"` + canonical SHA-256 `digest` | **Lock to per-request `software_attested` proof + add offline digest verification.** Chained ledger & Ed25519 move to v2. |

### 2.2 Concrete Hardening Gaps Found in Current `src/` Code

Vetting the existing v1 code against tight acceptance criteria uncovered **6 concrete gaps** that must be closed before Acceptance Council sign-off:

1. **Multi-rule `reroute` bypass (`src/policy/residency.ts`):** `evaluate()` returns immediately on the first rule that finds an alternative endpoint (`reroute`) without verifying that `suggestedEndpoint` satisfies all *other* applicable rules (e.g., a higher-priority tenant rule could reroute `secrets` traffic to an external endpoint that a lower-priority `denyLeavePerimeter` rule forbids).
2. **`tool_call` edges ignored by `PerimeterProver` (`src/prove/perimeter.ts`):** `build()` filters only `e.kind === "egress"`. A trace containing an allowed `tool_call` edge with `leavesPerimeter: true` would erroneously report `withinPerimeter: true`. In addition, `egress.every(...)` returns `true` vacuously if `decision === "allow"` and zero egress edges were supplied.
3. **No exported proof verifier (`src/prove/perimeter.ts`):** `PerimeterProver` computes a canonical SHA-256 `digest` but exports no `verify()` function to validate proof integrity offline.
4. **Silent fail-open rule loading in HTTP sidecar (`src/server/main.ts`):** If `MIREVOX_LINEAGE_RULES` is explicitly set to a missing or malformed file, `loadRules()` logs a warning and silently falls back to `demoRules()` instead of failing closed on startup.
5. **Wrong HTTP status on validation errors (`src/server/main.ts`):** Invalid JSON bodies or `ZodError` failures on `POST /v1/trace` fall into the generic `catch` block and return `500` instead of `400 Bad Request`.
6. **Broken `bin` entry (`package.json`):** `"bin": { "mirevox-lineage": "./dist/cli.js" }` points to a file that does not exist (`src/cli.ts` is absent).

---

## 3. Explicit v1 Scope

### 3.1 IN Scope for v1

1. **Ingress Tagging (`IngressTagger`, `digestPayload`, `parseIngressTag`):**
   - Validate and stamp AI-bound requests with `correlationId`, `tenantId`, `sourceId`, `declaredResidency`, `dataClasses`, `labels`, `taggedAt`, and optional SHA-256 `contentDigest` without storing raw payload content.
2. **Residency Route Policy Hooks (`ResidencyPolicyEngine`, `createRoutePolicyHook`):**
   - Pure, synchronous, priority-ordered evaluation of a candidate `ProviderEndpoint` and optional `alternatives` against validated `ResidencyRule[]`, returning `allow | deny | reroute | require_local` with deterministic `reason`, `matchedRuleId`, `suggestedEndpoint`, and `blockedResidencies`.
   - Runtime rule inspection (`listRules`) and atomic validated replacement (`replaceRules`).
3. **In-Memory Egress / Lineage Graph (`LineageGraph`):**
   - Referential-integrity node/edge store supporting `client`, `ingress`, `router`, `policy`, `provider`, `region`, and `tool` nodes and `ingress`, `route`, `policy_eval`, `egress`, and `tool_call` edges.
   - Standard hop recording (`recordAiHop`), correlation-scoped edge lookup (`edgesFor`), snapshot export (`snapshot`), and reset (`clear`).
4. **Software-Attested Perimeter Proofs (`PerimeterProver`):**
   - Deterministic `PerimeterProof` generation with `claimLevel: "software_attested"`, `withinPerimeter` evaluation over all perimeter-leaving hops (`egress` and `tool_call`), canonical sorted-key SHA-256 `digest`, and offline digest verification.
5. **Facade & Minimal Loopback HTTP Sidecar (`DataLineageModule`, `src/server/main.ts`):**
   - Single-call `traceRequest` facade plus `policyHook` and `getGraph` for direct TypeScript embedding in `smart-router`.
   - Zero-framework `node:http` sidecar on `127.0.0.1:3847` (`GET /`, `GET /health`, `GET /rules`, `GET /graph`, `POST /v1/trace`) with Docker-friendly packaging (`Dockerfile`) and Apache-2.0 `LICENSE`.
6. **Offline Deterministic Test Suite:**
   - Vitest unit and integration tests covering all four primitives, the facade, edge cases, and negative validation paths with zero network calls.

### 3.2 OUT of Scope for v1 (Explicit Non-Goals / Deferred to v2+)

- **No network egress proxy or transport-level interception:** No outbound HTTP client, DNS/IP capture, TLS peer certificate fingerprinting, SSE stream proxying, or HTTP 3xx redirect interception inside the core library.
- **No durable database or hash-chained ledger:** No SQLite/Postgres persistence, append-only JSONL ledger, monotonic `seq`/`prev_hash` chaining, or Ed25519 cryptographic signing in v1 (graph is explicitly in-memory per process).
- **No built-in DLP or ML classifiers:** No regex PII/secret scanners, LLM classifiers, or prompt redaction pipelines (integrate external classifiers upstream before calling `tag()`).
- **No custom policy DSL or external PDP:** No YAML rule parser, CEL, or OPA/Rego engine, and no `AUDIT_ONLY` shadow-mode engine in v1.
- **No standalone Target Residency Registry or discovery polling loop:** Host routers maintain target catalogs and pass `ProviderEndpoint` objects into hooks.
- **No provider-side audit log correlation:** No AWS CloudTrail `inferenceRegion`, Azure Monitor, or Vertex audit ingestion in v1.
- **No OTel exporter, Prometheus `/metrics`, Mermaid/DOT exporter, or Web UI dashboard.**
- **No CLI binary (`verify-evidence`, `policy test`):** Deferred to v2; remove or do not ship a dangling `bin` pointer in v1.
- **No TEE / enclave attestation, eBPF host bypass prevention, or raw prompt archiving.**

---

## 4. Normative v1 Data Contracts

All public inputs and outputs MUST conform to strict Zod schemas exported from `@mirevox/data-lineage` (`src/types.ts`):

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
`IngressTagger.tag(input)` MUST validate all inputs via `IngressTagSchema` and return a normalized `IngressTag`. `parseIngressTag(raw)` MUST validate arbitrary unknown JSON objects against `IngressTagSchema`.
- **Acceptance Criteria:**
  1. Valid input `{ tenantId, sourceId, declaredResidency, dataClasses?, labels?, correlationId? }` returns a schema-valid `IngressTag` with `dataClasses` defaulting to `[]` and `labels` defaulting to `{}`.
  2. Missing or empty `tenantId` / `sourceId`, an unsupported `declaredResidency` (e.g., `"mars"`), or an unsupported `dataClasses` entry (e.g., `"top_secret"`) throws a `ZodError` synchronously without producing a tag.
  3. `parseIngressTag(validObject)` returns the typed `IngressTag`; `parseIngressTag(invalidObject)` throws `ZodError`.

#### `FR-ING-02` — Privacy-Preserving Payload Digesting
When optional `payload` (`string | Uint8Array`) is supplied to `IngressTagger.tag()`, the module MUST compute `contentDigest = digestPayload(payload)` in the format `sha256:<64-lowercase-hex>` using SHA-256 over UTF-8 bytes (for strings) or raw bytes (for `Uint8Array`), and MUST NOT retain the raw `payload` on the returned `IngressTag`.
- **Acceptance Criteria:**
  1. `digestPayload("patient note")` and `digestPayload(new TextEncoder().encode("patient note"))` return identical strings matching `/^sha256:[a-f0-9]{64}$/`.
  2. When `payload` is omitted (`undefined`), `tag.contentDigest` is `undefined`.
  3. Serializing `JSON.stringify(tag)` for a request with canary payload `"CANARY_SECRET_XYZ_999"` contains `contentDigest` and contains `"CANARY_SECRET_XYZ_999"` zero times.

#### `FR-ING-03` — Deterministic Correlation & Injectable Clock
`IngressTagger.tag()` MUST preserve a caller-provided non-empty `correlationId` or generate a UUIDv4 when omitted, and MUST stamp `taggedAt` as an ISO-8601 UTC timestamp using `input.now?.() ?? new Date()`.
- **Acceptance Criteria:**
  1. Calling `tag()` with `correlationId: "corr-1"` and `now: () => new Date("2026-11-20T00:00:00.000Z")` returns `correlationId === "corr-1"` and `taggedAt === "2026-11-20T00:00:00.000Z"`.
  2. Calling `tag()` twice without `correlationId` produces two distinct valid UUID strings.

#### `FR-ING-04` — Extensible Labels for Cross-Module Correlation
`IngressTag.labels` (`Record<string, string>`) MUST accept arbitrary string metadata so Mirevox sibling modules (e.g., `appcode` from `shadow-versioning`, `sourceRef` from `context-engine`, `evalRunId` from `evals`) can attach correlation labels without schema changes.
- **Acceptance Criteria:**
  1. Passing `labels: { appcode: "appcode-xyz-0", sourceRef: "repo:mirevox/core" }` preserves both key-value pairs verbatim on `IngressTag` and inside `PerimeterProof.ingressTag.labels`.
  2. Passing non-string label values (e.g., nested objects or numbers) is rejected with `ZodError`.

---

### 5.2 Residency Route Policy Hooks (`FR-POL`)

#### `FR-POL-01` — Pure Synchronous Route Evaluation & Router Hook
`ResidencyPolicyEngine.evaluate({ tag, candidate, alternatives?, now? })` MUST be a pure, synchronous function (zero I/O, zero mutation of inputs or engine state) returning a schema-valid `RouteDecision` with `decision` in `{"allow", "deny", "reroute", "require_local"}`. `createRoutePolicyHook(engine)` MUST expose the concise router-middleware signature `(tag, candidate, alternatives?) => RouteDecision`.
- **Acceptance Criteria:**
  1. Evaluating a candidate and alternatives never mutates `tag`, `candidate`, `alternatives`, or `engine.listRules()`.
  2. Invalid `candidate` or `alternatives` endpoints (e.g., invalid URL scheme neither `http(s)://` nor `local://`, or invalid `residency`) throw `ZodError` before any decision is returned.
  3. Calling `createRoutePolicyHook(engine)(tag, candidate, alternatives)` produces the same `decision`, `matchedRuleId`, `suggestedEndpoint`, and `blockedResidencies` as `engine.evaluate(...)`.

#### `FR-POL-02` — Deterministic Rule Matching & Priority Semantics
Rules MUST be sorted by ascending integer `priority` (lower number = higher precedence; ties preserve declaration order). A rule matches `tag` iff:
- `rule.tenants` is empty OR `rule.tenants.includes(tag.tenantId)`, AND
- `rule.whenDataClasses` is empty OR at least one element of `rule.whenDataClasses` is present in `tag.dataClasses`.

For each matching rule, evaluation MUST enforce:
1. **`denyLeavePerimeter: true` + `candidate.leavesPerimeter === true`:** return `reroute` with an eligible local alternative (`!leavesPerimeter`) if one exists, otherwise `require_local` with `blockedResidencies: [candidate.residency]`.
2. **`candidate.residency` not in `rule.allowResidencies`:** return `reroute` with an eligible alternative if one exists, otherwise `deny` with `blockedResidencies: [candidate.residency]`.
3. **`preferLocal: true` + `candidate.leavesPerimeter === true`:** return `reroute` with an eligible local alternative if one exists, otherwise continue evaluation (candidate permitted if no other rule blocks it).
4. **Zero matching rules:** return `allow` with explicit reason stating no rules matched (default-allow when unconfigured; operators requiring default-deny attach a catch-all rule with `tenants: []`, `whenDataClasses: []`).
- **Acceptance Criteria:**
  1. Given rule `eu-pii-stay` (`allowResidencies: ["eu", "onprem"]`, `whenDataClasses: ["pii"]`, `denyLeavePerimeter: true`, `priority: 10`), candidate `bedrock/us` (`leavesPerimeter: true`), and alternative `local/onprem` (`leavesPerimeter: false`), `evaluate()` returns `{ decision: "reroute", matchedRuleId: "eu-pii-stay", suggestedEndpoint: local, blockedResidencies: ["us"] }`.
  2. With the same rule and `alternatives: []`, `evaluate()` returns `{ decision: "require_local", matchedRuleId: "eu-pii-stay", blockedResidencies: ["us"] }`.
  3. Given a rule with `denyLeavePerimeter: false`, `allowResidencies: ["ca", "onprem"]`, candidate `us`, and `alternatives: []`, `evaluate()` returns `{ decision: "deny", blockedResidencies: ["us"] }`.
  4. Given two matching rules with priorities `20` and `10`, the priority-`10` rule is evaluated first regardless of constructor input array order.

#### `FR-POL-03` — Multi-Rule Soundness on `reroute` & Unknown-Residency Safety
Any `suggestedEndpoint` returned in a `reroute` decision MUST satisfy **all** applicable rules for `tag` (not solely the first rule that rejected `candidate`), preventing a higher-priority rule from suggesting an endpoint forbidden by another matching rule. A candidate with `residency: "unknown"` MUST be rejected (`deny` or `reroute` to a compliant alternative) whenever any applicable rule does not explicitly include `"unknown"` in `allowResidencies`.
- **Acceptance Criteria:**
  1. Given Rule A (`priority: 10`, `tenants: ["acme"]`, `allowResidencies: ["eu", "onprem"]`, `denyLeavePerimeter: false`) and Rule B (`priority: 20`, `whenDataClasses: ["secrets"]`, `allowResidencies: ["onprem", "eu"]`, `denyLeavePerimeter: true`), evaluating a `tag` for tenant `"acme"` with `dataClasses: ["secrets"]`, candidate `us/cloud`, and alternatives `[eu/cloud (leavesPerimeter: true), local/onprem (leavesPerimeter: false)]` MUST NOT suggest `eu/cloud`; it MUST suggest `local/onprem` (or return `require_local`/`deny` if only `eu/cloud` is offered).
  2. Evaluating a candidate with `residency: "unknown"` against any rule whose `allowResidencies` is `["eu", "onprem"]` returns `deny` (or `reroute` to an eligible alternative) with `"unknown"` in `blockedResidencies`.

#### `FR-POL-04` — Atomic Validated Rule Management
`ResidencyPolicyEngine` MUST expose `listRules()` (returning a defensive shallow copy so callers cannot mutate internal state) and `replaceRules(rules)` which validates all incoming rules against `ResidencyRuleSchema` before activating them.
- **Acceptance Criteria:**
  1. Mutating the array returned by `listRules()` (e.g., `.pop()`) does not alter subsequent `evaluate()` behavior.
  2. Calling `replaceRules()` with an array containing one valid rule and one invalid rule (e.g., `allowResidencies: []`) throws `ZodError` and leaves the previously active rules completely unchanged.

#### `FR-POL-05` — Multi-Hop, Fallback & Tool-Call Re-Evaluation Contract
Because `evaluate()` is stateless per call, a host router performing fallbacks, fan-out sub-requests, or remote tool calls MUST be able to invoke `policyHook(tag, hopCandidate, hopAlternatives)` independently for every hop using the same `IngressTag` (preserving `tenantId`, `dataClasses`, and `correlationId`).
- **Acceptance Criteria:**
  1. Calling `policyHook` sequentially for 3 hops sharing one `IngressTag` (`dataClasses: ["pii"]`) — Hop 1 (`local/onprem`), Hop 2 (`bedrock/us`), Hop 3 (remote tool endpoint in `us`, `leavesPerimeter: true`) — deterministically returns `allow`, `require_local`, and `require_local` respectively with zero state leakage between calls.

---

### 5.3 Egress / Lineage Graph (`FR-GRF`)

#### `FR-GRF-01` — Typed Node & Edge Store with Referential Integrity
`LineageGraph` MUST validate nodes via `LineageNodeSchema` and edges via `LineageEdgeSchema`, and MUST enforce referential integrity on `addEdge()`: adding an edge whose `from` or `to` node does not exist MUST throw an `Error`.
- **Acceptance Criteria:**
  1. Calling `upsertNode()` with a valid node stores it and returns the parsed `LineageNode`; calling again with the same `id` updates the node in place without creating duplicates.
  2. Calling `addEdge()` when either `from` or `to` is missing throws an error naming the missing reference and leaves `edges` unchanged.

#### `FR-GRF-02` — Standard AI Hop Recording (`recordAiHop`)
`LineageGraph.recordAiHop({ tag, routerId?, candidate, decision, now? })` MUST record the canonical 6-node / 5-edge path for an evaluated AI hop:
- Nodes: `client:<sourceId>`, `ingress:<correlationId>`, `<routerId>` (default `"router:default"`), `policy:<correlationId>`, `provider:<providerId>:<modelId>`, `region:<residency>`
- Edges: `client -> ingress` (`ingress`), `ingress -> router` (`route`), `router -> policy` (`policy_eval`), `policy -> provider` (`egress`), `provider -> region` (`egress`)
- Perimeter flag: `leavesPerimeter` MUST be `true` on the `egress` edges **if and only if** `decision.decision === "allow" && candidate.leavesPerimeter === true`; on `deny`, `reroute`, or `require_local`, `leavesPerimeter` MUST be `false` and `meta.decision` MUST record the decision value.
- **Acceptance Criteria:**
  1. Recording an allowed external hop (`decision: "allow"`, `leavesPerimeter: true`) creates 6 nodes and 5 edges where both `egress` edges have `leavesPerimeter === true` and all 5 edges carry `tag.correlationId`.
  2. Recording a denied external hop (`decision: "deny"`, `leavesPerimeter: true`) creates edges where every edge has `leavesPerimeter === false` and the `policy -> provider` edge records `meta.decision === "deny"`.
  3. Recording an allowed local hop (`decision: "allow"`, `leavesPerimeter: false`) creates edges where every edge has `leavesPerimeter === false`.

#### `FR-GRF-03` — Multi-Hop & Tool-Call Extensibility
`LineageGraph` MUST support recording additional `tool` nodes and `tool_call` edges (or follow-up rerouted hops) linked to an existing `correlationId` via `upsertNode()` / `addEdge()` without losing earlier edges for that `correlationId`.
- **Acceptance Criteria:**
  1. After `recordAiHop()` for `correlationId: "c-1"`, adding a `tool` node (`kind: "tool"`, `residency: "us"`) and a `tool_call` edge (`from: "router:default"`, `to: "tool:mcp-search"`, `correlationId: "c-1"`, `leavesPerimeter: true`) results in `edgesFor("c-1")` returning all 6 edges (5 primary + 1 `tool_call`) and `snapshot("c-1")` including the `tool` node.

#### `FR-GRF-04` — Scoped Snapshots & Reset Controls
`LineageGraph` MUST expose `edgesFor(correlationId)`, `snapshot(correlationId?)` returning a schema-valid `LineageGraphSnapshot`, and `clear()` to reset in-memory state.
- **Acceptance Criteria:**
  1. After recording two requests (`corr-A` and `corr-B`), `snapshot("corr-A")` returns **only** edges matching `corr-A` and **only** nodes referenced by those edges (zero cross-correlation leakage).
  2. `snapshot()` with no argument returns all stored nodes and edges across correlations.
  3. `clear()` empties both nodes and edges so subsequent `snapshot()` returns `{ nodes: [], edges: [], capturedAt }`.

---

### 5.4 Software-Attested Perimeter Proofs (`FR-PRV`)

#### `FR-PRV-01` — Software-Attested Proof Construction
`PerimeterProver.build({ tag, decision, edges, nodes, now? })` MUST emit a schema-valid `PerimeterProof` containing:
- `proofId` (UUIDv4), `correlationId`, `tenantId`, `issuedAt` (ISO-8601 UTC)
- `claimLevel`: literal `"software_attested"` (no other value permitted by schema)
- `egressHops`: array of all perimeter-relevant hops (`edge.kind === "egress"` or `edge.kind === "tool_call"`), each with `{ edgeId, to, residency?, leavesPerimeter }`
- `withinPerimeter`: boolean
- `policyDecision`: the `RouteDecision`
- `ingressTag`: the `IngressTag`
- `digest`: `sha256:<64-lowercase-hex>`
- **Acceptance Criteria:**
  1. `PerimeterProofSchema.parse(proof)` succeeds and `proof.claimLevel === "software_attested"`.
  2. Attempting to validate a proof object with `claimLevel: "tee_attested"` or `"hardware_enforced"` against `PerimeterProofSchema` fails with `ZodError`.

#### `FR-PRV-02` — Honest Perimeter Containment Semantics (`withinPerimeter`)
`PerimeterProver.build()` MUST compute `withinPerimeter` as follows:
- If `decision.decision !== "allow"` (`deny`, `require_local`, `reroute`) AND no recorded `egress`/`tool_call` edge has `leavesPerimeter === true`: `withinPerimeter = true`.
- If ANY recorded `egress` OR `tool_call` edge has `leavesPerimeter === true`: `withinPerimeter = false` (regardless of `decision`).
- If `decision.decision === "allow"` and `egressHops.length === 0`: `withinPerimeter` MUST NOT vacuously attest containment without evidence — either throw an error or set `withinPerimeter = false` (fail-closed; must be consistent and tested).
- **Acceptance Criteria:**
  1. Allowed local hop (`leavesPerimeter: false` on all egress edges) -> `withinPerimeter === true`.
  2. Allowed external hop (`leavesPerimeter: true` on egress edge) -> `withinPerimeter === false`.
  3. Denied / `require_local` / `reroute` hop (zero edges with `leavesPerimeter: true`) -> `withinPerimeter === true`.
  4. Allowed local model hop combined with an allowed external `tool_call` edge (`leavesPerimeter: true`) -> `withinPerimeter === false` and the `tool_call` hop appears in `egressHops`.
  5. Calling `build()` with `decision: "allow"` and `edges: []` does NOT return `withinPerimeter === true`.

#### `FR-PRV-03` — Canonical SHA-256 Digest & Offline Verification
`PerimeterProof.digest` MUST be computed as `sha256:<hex>` over a recursively key-sorted JSON serialization (`stableStringify`) of the proof payload excluding `digest`. The module MUST export an offline verification helper (e.g., `verifyPerimeterProof(proof)` / `prover.verify(proof)`) that validates schema conformance and recomputes the canonical digest.
- **Acceptance Criteria:**
  1. Given a `proof` produced by `PerimeterProver.build()`, `verify(proof)` and `verify(JSON.parse(JSON.stringify(proof)))` both return `{ valid: true }` (or `true`).
  2. Mutating any single field of `proof` (e.g., flipping `withinPerimeter` from `false` to `true`, altering `ingressTag.declaredResidency`, changing `policyDecision.decision`, or removing an `egressHops` entry) causes `verify()` to return invalid (`false`) deterministically.
  3. Reordering object keys in the serialized JSON representation of `proof` before parsing does not break verification (canonical key-order independence).

#### `FR-PRV-04` — Explicit Claim Boundary (No Overclaiming)
Neither `PerimeterProof` nor any module export/API response may present `declaredResidency` or `ProviderEndpoint.residency` as verified physical processing location. Documentation and schema descriptions MUST explicitly state that `software_attested` covers only the recorded policy path inside `@mirevox/data-lineage`.
- **Acceptance Criteria:**
  1. `PerimeterProofSchema` enforces `claimLevel: z.literal("software_attested")`.
  2. Repository `README.md` and `docs/requirements.md` both state the trust boundary explicitly (recorded policy path, not TEE or network enforcement).

---

### 5.5 Module Facade & Optional Local HTTP Sidecar (`FR-MOD`)

#### `FR-MOD-01` — End-to-End `DataLineageModule` Facade
`DataLineageModule` MUST compose `tagger`, `policy`, `graph`, `prover`, and `policyHook` and expose:
- `traceRequest(input: TraceRequestInput): TraceRequestResult` executing `tag -> evaluate -> recordAiHop -> buildProof` synchronously and returning `{ tag, decision, graph, proof }`.
- `getGraph(correlationId?): LineageGraphSnapshot`.
- **Acceptance Criteria:**
  1. Calling `traceRequest()` once returns a `TraceRequestResult` where `tag.correlationId === proof.correlationId`, `decision === proof.policyDecision`, `graph.edges` contains only edges for `tag.correlationId`, and `proof.digest` verifies cleanly offline.

#### `FR-MOD-02` — Minimal Loopback HTTP Sidecar API
The optional HTTP server (`src/server/main.ts`) MUST expose:
- `GET /` — service metadata and endpoint index (`200`)
- `GET /health` — liveness (`200`, `{ ok: true, service: "@mirevox/data-lineage", version }`)
- `GET /rules` — active `ResidencyRule[]` (`200`)
- `GET /graph?correlationId=<id>` — full or filtered `LineageGraphSnapshot` (`200`)
- `POST /v1/trace` — runs `traceRequest()` and returns `TraceRequestResult` (`200`)
- **Acceptance Criteria:**
  1. Missing required fields, malformed JSON, or Zod schema violations on `POST /v1/trace` return `400 Bad Request` with JSON `{ error: string }` (NOT `500`), and never include stack traces.
  2. Unknown routes return `404 Not Found` with JSON `{ error: "not found" }`.

#### `FR-MOD-03` — Fail-Closed Explicit Rule Loading in Sidecar
When `MIREVOX_LINEAGE_RULES` is explicitly configured in the environment, the sidecar MUST fail fast (non-zero exit with a clear error message) if the file cannot be read, is not valid JSON array, or fails `ResidencyRuleSchema` validation. Built-in demo rules may load ONLY when `MIREVOX_LINEAGE_RULES` is unset and no default `config/residency-rules.json` exists.
- **Acceptance Criteria:**
  1. Starting the sidecar with `MIREVOX_LINEAGE_RULES=/nonexistent/rules.json` or a file containing invalid JSON / invalid rule schema exits non-zero rather than silently serving traffic with `demoRules()`.
  2. Starting the sidecar with valid `config/residency-rules.json` loads all rules and exposes them via `GET /rules`.

---

## 6. Non-Functional Requirements (NFR)

| ID | Category | Requirement | Measurable Acceptance Criterion |
| --- | --- | --- | --- |
| **`NFR-01`** | **In-Process Latency Budget** | Core synchronous router-path calls (`evaluate`, `traceRequest`) MUST add negligible overhead inside a host router event loop. | Benchmarked in-process on a standard 2-vCPU Linux VM (Node >= 20) over 1,000 iterations with 100 residency rules and a 16 KiB payload: `ResidencyPolicyEngine.evaluate()` **p95 < 1.0 ms** (median < 0.2 ms); `DataLineageModule.traceRequest()` **p95 < 2.0 ms** (median < 0.5 ms). |
| **`NFR-02`** | **Zero Network Required for Core Library** | Importing and using the library exports (`@mirevox/data-lineage`) and running the full unit/integration test suite MUST require zero network connectivity, zero external daemons, and zero cloud SDKs/credentials. | Core modules under `src/` (excluding optional `src/server/main.ts`) import zero networking modules (`node:http`, `node:https`, `node:net`, `node:dns`, `fetch`); `npm test`, `npm run typecheck`, and `npm run build` pass 100% offline with zero env secrets set. |
| **`NFR-03`** | **Claim Honesty (`software_attested`, Not TEE)** | All proofs, schemas, and documentation MUST accurately represent the software-attested trust boundary and never overclaim hardware/network enforcement. | `PerimeterProof.claimLevel` is locked to literal `"software_attested"`; automated schema test rejects alternative claim levels; README and docs explicitly state proofs cover the recorded policy path in this module, not TEE or network firewall enforcement. |
| **`NFR-04`** | **Privacy-by-Default (No Raw Payload Storage)** | Raw request prompts/payloads MUST NOT be persisted in `IngressTag`, `LineageGraph`, `PerimeterProof`, or HTTP `/graph` responses. | Automated canary test passes `"CANARY_PRIVATE_PAYLOAD_123"` into `traceRequest()` and asserts the canary string appears 0 times across `JSON.stringify(result)` and `JSON.stringify(mod.getGraph())`, while `sha256:` digest is present. |
| **`NFR-05`** | **Determinism & Offline Verification Speed** | Digests, policy decisions, and test outcomes MUST be deterministic and fast for CI and council iteration. | Running `npm run typecheck && npm run build && npm test` twice consecutively offline yields 100% pass rate in **< 10 seconds** total; identical inputs with fixed `now` and `correlationId` yield identical `contentDigest`, `RouteDecision`, and canonical proof payload hashes. |
| **`NFR-06`** | **Minimal Footprint & Packaging Hygiene** | Module MUST stay lean, strictly typed, single-VM / Docker-friendly, and cleanly packaged. | `tsconfig.json` enforces `strict: true` and `noUncheckedIndexedAccess: true`; production runtime dependencies <= 3 (v1 target: `zod` only); `package.json` contains zero dangling `bin`/`exports` paths; sidecar baseline RSS **< 128 MB**; Apache-2.0 `LICENSE` present. |
| **`NFR-07`** | **Sidecar Loopback Default & Input Bounds** | Optional HTTP sidecar MUST default to loopback binding (`127.0.0.1`), enforce request body size limits, and sanitize error responses. | Default `HOST === "127.0.0.1"`; request bodies exceeding 1 MiB return `413 Payload Too Large`; 4xx/5xx responses return JSON `{ error }` with zero stack traces (`at ` / file paths). |
| **`NFR-08`** | **Explicit In-Memory Lifecycle Bounds** | Because v1 `LineageGraph` is in-memory, its lifecycle and memory behavior MUST be transparent and controllable. | `LineageGraph.clear()` resets memory deterministically; docs explicitly state v1 graph storage is ephemeral per process and advise bounding or clearing in long-running routers until v2 durable storage ships. |

---

## 7. v1 Acceptance Verification Matrix

The Acceptance Council and parallel builders/testers MUST verify every row below before v1 sign-off. `Current Code Status` reflects the vetted state of `/agent/repos/data-lineage/src/` at lock time.

| Pillar | Locked Req IDs | Verification Method | Current Code Status | Exit Gate (Pass Condition) |
| --- | --- | --- | --- | --- |
| **Ingress Tagging** | `FR-ING-01`–`04`, `NFR-04` | Unit tests (`tests/ingress.test.ts`) | **PASS** (expand negative/canary tests) | Valid tagging, UUID/clock injection, SHA-256 `contentDigest`, zero canary plaintext leakage, `ZodError` on invalid enums/labels. |
| **Residency Policy Hooks** | `FR-POL-01`–`05`, `NFR-01` | Unit + multi-rule + perf tests (`tests/policy.test.ts`) | **PARTIAL** (fix multi-rule `reroute` soundness) | All 4 decisions tested, priority ordering verified, `reroute` target satisfies *all* applicable rules, `"unknown"` residency rejected, atomic `replaceRules`, p95 < 1 ms. |
| **Egress / Lineage Graph** | `FR-GRF-01`–`04`, `NFR-08` | Unit tests (`tests/graph.test.ts`) | **PASS** (add dedicated graph & `tool_call` tests) | Referential integrity enforced, 6-node/5-edge hop recorded, `leavesPerimeter` accurate on allow vs. deny, `tool_call` edges & correlation-scoped `snapshot()` + `clear()` verified. |
| **Software-Attested Proofs** | `FR-PRV-01`–`04`, `NFR-03` | Unit + tamper tests (`tests/proof.test.ts`) | **GAP** (fix `tool_call`/empty-edge containment + add `verify()`) | `claimLevel === "software_attested"`, `tool_call` with `leavesPerimeter: true` sets `withinPerimeter: false`, empty-edge `allow` fails closed, `verify()` passes intact & fails tampered proofs. |
| **Facade & HTTP Sidecar** | `FR-MOD-01`–`03`, `NFR-01`, `NFR-06`, `NFR-07` | Integration tests (`tests/lineage-module.test.ts`, server tests) | **GAP** (fix `400` validation status, fail-closed `MIREVOX_LINEAGE_RULES`, 1 MiB cap, broken `bin`) | `traceRequest()` p95 < 2 ms; sidecar returns `400` on invalid input, `413` on oversized body, exits non-zero on invalid explicit rules file; no dangling `package.json` `bin`. |
| **Offline & Honesty Gate** | `NFR-02`, `NFR-03`, `NFR-05`, `NFR-06` | Offline CI run (`typecheck`, `build`, `test`) + doc check | **PASS** (re-verify after hardening) | Zero network imports in core lib; full suite passes offline in < 10 s; README & docs explicitly state `software_attested` trust boundary. |
