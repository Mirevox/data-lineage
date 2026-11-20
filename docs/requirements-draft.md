# Mirevox `data-lineage` — Draft Requirements (v1)

**Module:** `data-lineage` (https://github.com/Mirevox/data-lineage)
**Status:** Draft (input to Requirements Vetter, Architect, and FR/NFR Author)
**Target Runtime:** Single Linux cloud VM (Docker-friendly later; no full homelab cluster)

---

## 1. System Context & Integration Boundary

`data-lineage` sits on the request/egress path of Mirevox `smart-router` (or any host AI gateway) as either an **in-process middleware/library** or a **local HTTP sidecar**.

```text
Client / Harness (VS Code, Chatbot, Workflow)
        │
        ▼  [1] Ingress request (+ optional headers / context refs)
┌──────────────────────────────────────────────────────────┐
│                 smart-router / Host Gateway              │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │            Mirevox data-lineage module             │  │
│  │  1. Ingress Tagger (headers + identity + hooks)    │  │
│  │  2. Target Residency Registry (sync/static)        │  │
│  │  3. Residency Route Policy Hook (ALLOW/DENY/...)   │  │
│  │  4. Egress Observer + Lineage Graph + Hash Ledger  │  │
│  └────────────────────────────────────────────────────┘  │
└───────────────────────────┬──────────────────────────────┘
                            │  [2] Allowed egress only
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
   Regional Cloud       Local Model      MCP / Workflow
(Foundry/Bedrock/Vertex)  (Ollama)      (Remote or Local)
```

### Core Domain Concepts (Draft Data Model)
- **`LineageContext`**: `{ lineage_id, trace_id, span_id, parent_span_id, hop_depth }` propagated across router fan-out and MCP calls.
- **`TagSet`**: normalized fields `{ jurisdictions[], data_class, project_id (appcode), source_refs[], retention_req, activity_type }` where every tag entry records its `provenance` (`caller-asserted`, `identity-derived`, `classifier-inferred`, `system-default`).
- **`TargetResidencyProfile`**: `{ target_id, target_type (model|mcp|workflow), provider, endpoint_url, jurisdiction, region, deployment_tier (on-prem|vpc-private|cloud-regional|cloud-global), declared_zdr, allowed_data_classes[], allowed_jurisdictions[] }`.
- **`PolicyDecision`**: `{ decision (ALLOW|DENY|CONSTRAIN|AUDIT_ONLY), eligible_target_ids[], denied_targets[{target_id, rule_id, reason}], policy_bundle_version, policy_bundle_sha256, matched_rule_ids[], evaluated_at }`.
- **`LineageEvent`**: immutable ledger record with `{ seq, prev_hash, event_hash, signature?, timestamp, lineage_id, span_id, parent_span_id, event_type, observed: {...}, declared: {...} }`.

---

## 2. Functional Requirements (FR)

### 2.1 Ingress Tagging (`FR-ING`)

- **`FR-ING-01` Explicit Header & Envelope Extraction**
  The module SHALL extract lineage and residency tags from incoming HTTP headers and/or router request envelopes, supporting at minimum:
  - `X-Mirevox-Jurisdiction` (ISO/region code(s), e.g., `EU`, `DE`, `US`, `CA`, `UK`, `ON-PREM`)
  - `X-Mirevox-Data-Class` (ordered sensitivity ladder: `public` < `internal` < `confidential` < `restricted`)
  - `X-Mirevox-Project` (e.g., `appcode-xyz-0`, compatible with `shadow-versioning`)
  - `X-Mirevox-Source-Refs` (comma/JSON list of repo, document, or corpus identifiers, e.g., from `context-engine`)
  - `X-Mirevox-Retention` (`zdr-required` | `standard`)
  - W3C `traceparent` / `X-Mirevox-Lineage-Id` for correlation (generating a new `lineage_id` and `span_id` when absent).

- **`FR-ING-02` Identity- and Route-Derived Defaults**
  Because IDE clients and chatbots often cannot set custom headers per request, the module SHALL support deriving baseline tags from caller identity (API key ID, workspace ID, user/service principal) or router route configuration via a declarative mapping table.

- **`FR-ING-03` Tag Provenance & Non-Downgrade Precedence**
  Every resolved tag SHALL carry a provenance label (`caller-asserted`, `identity-derived`, `classifier-inferred`, `system-default`). When multiple sources supply conflicting values for the same dimension, the resolver SHALL apply a deterministic **most-restrictive-wins** rule (e.g., a caller header `data_class=public` MUST NOT downgrade an identity-derived `data_class=restricted` or a classifier-detected `restricted` finding; jurisdiction constraints SHALL intersect or require explicit rule resolution, never widen silently).

- **`FR-ING-04` Pluggable Deterministic Classifier Hook**
  The module SHALL expose a synchronous pre-policy ingress classifier hook interface (`classify(payloadMetadata, contentView) -> InferredTag[]`). v1 SHALL ship lightweight, zero-ML built-in detectors (configurable regex/pattern matchers for secrets/API keys, common PII patterns, and explicit inline residency markers such as `@residency:EU`).

- **`FR-ING-05` Privacy-Preserving Payload Fingerprinting**
  The module SHALL compute a SHA-256 digest of the canonicalized request payload (messages/prompt/tool arguments) plus byte length and estimated/reported token counts. Raw prompt and response bodies SHALL NOT be persisted to the lineage store by default.

- **`FR-ING-06` Missing & Malformed Tag Handling**
  The module SHALL support configurable handling per route when required tags are absent or malformed:
  - `fail_closed` (default for regulated routes): reject ingress with HTTP `400`/`403` and record a `DENY` lineage event.
  - `strict_default`: assign configured strictest fallback tags (e.g., `data_class=restricted`, `jurisdiction=ON-PREM`).
  - `audit_only`: tag as `UNKNOWN` and record a policy warning without blocking.

#### Acceptance Criteria Stubs (`AC-ING`)
- `AC-ING-01`: Given a request with `X-Mirevox-Jurisdiction: EU`, `X-Mirevox-Data-Class: confidential`, and `X-Mirevox-Project: appcode-fin-1`, ingress tagging returns a normalized `TagSet` with provenance `caller-asserted` and generates a valid `lineage_id` and `span_id`.
- `AC-ING-02`: Given an IDE request with no `X-Mirevox-*` headers authenticated by an API key mapped to `{jurisdiction: EU, data_class: restricted}`, the resolved `TagSet` inherits those tags with provenance `identity-derived`.
- `AC-ING-03`: Given an identity mapped to `data_class=restricted` and a caller header sending `X-Mirevox-Data-Class: public`, the resolved tag remains `restricted` and records the attempted downgrade in event metadata.
- `AC-ING-04`: Given a prompt containing a configured secret pattern (e.g., `AKIA...` or marker `@residency:ON-PREM`), the built-in classifier appends the inferred tag with provenance `classifier-inferred` before policy evaluation.
- `AC-ING-05`: After processing a request containing a sentinel plaintext string `SENSITIVE_CANARY_999`, inspecting all persisted store files/tables confirms the SHA-256 payload digest is present and `SENSITIVE_CANARY_999` appears zero times on disk.
- `AC-ING-06`: Given a malformed jurisdiction header `X-Mirevox-Jurisdiction: ???` on a `fail_closed` route, the request is rejected before routing and an ingress-rejection event is appended to the ledger.

---

### 2.2 Target Residency Registry (`FR-REG`)

- **`FR-REG-01` Declarative Target Residency Profiles**
  The module SHALL maintain a registry of candidate egress targets (`model`, `mcp`, `workflow`) capturing: `target_id`, `provider`, `endpoint_url`, `jurisdiction`, `region`, `deployment_tier` (`on-prem`, `vpc-private`, `cloud-regional`, `cloud-global`), `declared_zdr` (`true` | `false` | `unknown`), `allowed_data_classes`, and `allowed_jurisdictions`.

- **`FR-REG-02` Router Discovery Sync & Static Config**
  The registry SHALL accept target definitions from:
  1. Static YAML/JSON configuration files (standalone mode / baseline).
  2. Programmatic registration/sync API from `smart-router`'s discovery/polling loop.
  Registry updates SHALL compute a `registry_snapshot_sha256` referenced in lineage events.

- **`FR-REG-03` Unknown / Unregistered Target Fail-Closed**
  Any candidate target absent from the registry, or missing required residency fields (`jurisdiction`, `deployment_tier`), SHALL be classified as `jurisdiction=UNKNOWN, deployment_tier=unknown` and MUST be ineligible for any request carrying a jurisdiction constraint or `data_class > public`.

#### Acceptance Criteria Stubs (`AC-REG`)
- `AC-REG-01`: Loading a valid YAML target registry containing Foundry EU, Bedrock US, local Ollama, and a remote MCP server exposes queryable profiles and computes a deterministic `registry_snapshot_sha256`.
- `AC-REG-02`: Calling the sync API with a newly polled model target updates the active snapshot digest without dropping concurrent policy evaluations.
- `AC-REG-03`: Routing a `jurisdiction=EU` request to a target ID missing from the registry (or missing `jurisdiction`) results in `DENY` with reason `UNREGISTERED_OR_INCOMPLETE_TARGET`.

---

### 2.3 Residency-Aware Route Policy Hooks (`FR-POL`)

- **`FR-POL-01` Synchronous Pre-Egress Route Evaluation Hook**
  The module SHALL expose a synchronous pre-egress hook (`evaluateRoute(lineageCtx, tagSet, activity, candidateTargets) -> PolicyDecision`) invoked by `smart-router` prior to dispatching any upstream request. Supported decisions:
  - `ALLOW`: all or specified candidate targets permitted.
  - `CONSTRAIN`: returns a strictly filtered/ordered subset of eligible targets (e.g., drop US cloud targets, keep EU regional + on-prem fallback).
  - `DENY`: zero eligible targets or explicit deny rule matched; router MUST abort egress and return a structured error with `lineage_id`, `rule_id`, and machine-readable reason code.
  - `AUDIT_ONLY`: evaluate and record what `DENY`/`CONSTRAIN` *would* have done, while allowing routing to proceed (for staged rollout).

- **`FR-POL-02` Declarative Residency Policy Ruleset**
  Policies SHALL be authored in versioned, human-readable YAML/JSON rules matching on:
  - Ingress attributes: `jurisdiction`, `data_class`, `project_id` (`appcode`), `source_refs`, `retention_req`, `activity_type`.
  - Target attributes: `target_type` (`model`, `mcp`, `workflow`), `provider`, `jurisdiction`, `region`, `deployment_tier`, `declared_zdr`.
  - Actions: `allow`, `deny`, `require_tier` (e.g., `on-prem`), `require_jurisdiction_match`, `require_zdr`, `audit_only`.

- **`FR-POL-03` Deterministic Precedence & Policy Version Pinning**
  Rule evaluation SHALL be deterministic with **explicit `deny` overriding `allow`** and default-deny when no rule permits a restricted/jurisdiction-tagged request. Every `PolicyDecision` SHALL record `policy_bundle_version`, `policy_bundle_sha256`, and `matched_rule_ids`.

- **`FR-POL-04` Multi-Hop, Fan-Out & MCP Constraint Inheritance**
  When `smart-router` splits a prompt into parallel sub-requests or dispatches an outbound MCP/workflow call, the policy hook SHALL be re-invoked for **each child hop** with a child `span_id` linked to `parent_span_id`. Child hops SHALL inherit all parent `TagSet` restrictions and MUST NOT widen allowed jurisdictions or downgrade `data_class`.

- **`FR-POL-05` Offline Policy Simulation (`policy test`)**
  The CLI SHALL provide a `policy test --policy <file> --registry <file> --fixtures <file>` command that runs fixture requests against a policy bundle and asserts expected decisions without starting the router or making network calls.

- **`FR-POL-06` Atomic Policy Reload with Validation**
  Policy updates SHALL validate schema, rule references, and syntax before activation. Invalid bundles MUST be rejected while keeping the last valid policy bundle active.

#### Acceptance Criteria Stubs (`AC-POL`)
- `AC-POL-01`: Given a request tagged `{jurisdiction: EU, data_class: confidential}` and candidates `[bedrock-us-east-1, foundry-eu-west, local-ollama]`, `evaluateRoute` returns `CONSTRAIN` with `eligible_target_ids: [foundry-eu-west, local-ollama]` and records `bedrock-us-east-1` as denied with the matched `rule_id`.
- `AC-POL-02`: Given a request tagged `{data_class: restricted}` with rule `restricted -> on-prem only` and only cloud candidates available, `evaluateRoute` returns `DENY`, zero bytes are sent to any mock upstream server, and the response contains `lineage_id` and `rule_id`.
- `AC-POL-03`: Given a parent request tagged `{jurisdiction: EU}` that `smart-router` fans out into 2 model sub-calls (`foundry-eu-west` and `vertex-us-central1`) plus 1 remote MCP call (`mcp-us-docs`), the EU model call is `ALLOW`, while both US sub-calls are `DENY` under inherited parent tags.
- `AC-POL-04`: In `AUDIT_ONLY` mode on a route, a violating request is permitted to hit the mock upstream, and the ledger records `decision=AUDIT_ONLY` plus `would_have_decided=DENY` and the violated `rule_id`.
- `AC-POL-05`: Running `policy test` against a fixture set of 10 allow/constrain/deny cases exits `0` when all match and exits non-zero with a per-case diff when any rule regresses.
- `AC-POL-06`: Attempting to reload a syntactically invalid YAML policy leaves the previously loaded `policy_bundle_sha256` active and returns a structured validation error.

---

### 2.4 Egress Observation & Lineage Graph (`FR-LIN`)

- **`FR-LIN-01` Lifecycle Event Recording**
  The module SHALL record structured, causally ordered lifecycle events per `lineage_id` / `span_id`:
  - `INGRESS_TAGGED`
  - `POLICY_DECIDED`
  - `EGRESS_BLOCKED` (when denied)
  - `EGRESS_DISPATCHED` (pre-send intent)
  - `EGRESS_COMPLETED` or `EGRESS_FAILED` (post-response observation)
  - `FANOUT_SPAWNED` / `TOOL_INVOKED` (for child hops)

- **`FR-LIN-02` Directed Lineage Graph Model**
  Events SHALL materialize or resolve into a Directed Acyclic Graph (DAG) with typed nodes (`Caller`, `SourceRef`, `IngressRequest`, `PolicyDecision`, `SubRequest`, `EgressTarget`, `ResponseArtifact`) and typed edges (`INGESTED_FROM`, `TAGGED_WITH`, `EVALUATED_BY`, `SPLIT_INTO`, `ROUTED_TO`, `BLOCKED_FROM`, `INVOKED_TOOL`, `RETURNED_AS`).

- **`FR-LIN-03` Transport-Level Egress Observation**
  On every executed outbound call, the egress observer SHALL capture:
  - Target ID and configured `endpoint_url`
  - Observed remote IP address and port (post-DNS resolution)
  - TLS SNI hostname and peer leaf certificate SHA-256 fingerprint (when HTTPS and accessible from the HTTP transport; explicitly marked `unavailable` if plain HTTP or proxied without TLS inspection)
  - HTTP status code, latency (ms), request byte count, response byte count, and streaming/buffered response SHA-256 digest.

- **`FR-LIN-04` Egress Redirect Guard**
  The egress wrapper/adapter SHALL disable automatic following of HTTP `3xx` redirects to different hosts or ports (or re-run target registry + policy validation on the redirect target before following), preventing a registered regional endpoint from silently redirecting traffic to an unapproved host/region.

- **`FR-LIN-05` Single-VM Lightweight Persistence**
  v1 SHALL persist events and graph indices locally using an embedded single-node store (SQLite in WAL mode or append-only JSONL + SQLite index) behind a clean storage interface (`LineageStore`) so Postgres or external stores can be added later without changing core logic.

- **`FR-LIN-06` Query & Export APIs**
  The module SHALL expose HTTP API endpoints and matching CLI commands to query and export lineage data:
  - Query by `lineage_id` / `trace_id` (returns full DAG JSON)
  - Filter queries by `project_id` (`appcode`), `jurisdiction`, `data_class`, `target_id`, `region`, `decision`, and `[from, to]` timestamp window
  - Export formats: canonical JSON graph (`nodes` + `edges`), NDJSON/JSONL event stream, Mermaid/DOT graph text, and OpenTelemetry-compatible span attributes/links.

#### Acceptance Criteria Stubs (`AC-LIN`)
- `AC-LIN-01`: A single-hop routed request produces linked `INGRESS_TAGGED -> POLICY_DECIDED -> EGRESS_DISPATCHED -> EGRESS_COMPLETED` events sharing one `lineage_id` and `span_id`.
- `AC-LIN-02`: A task-split request fanning out to 2 models and 1 MCP tool reconstructs a DAG with 1 parent `IngressRequest`, 3 child `SubRequest`/`ToolCall` nodes, and accurate `SPLIT_INTO` / `INVOKED_TOOL` / `ROUTED_TO` / `BLOCKED_FROM` edges.
- `AC-LIN-03`: Against a local HTTPS mock upstream server, `EGRESS_COMPLETED` records the observed remote IP (`127.0.0.1`), TLS peer cert SHA-256 matching the mock cert, HTTP status `200`, byte counts, and SHA-256 of the response body (including chunked/SSE streaming responses).
- `AC-LIN-04`: When a mock upstream returns `302 Found` pointing to an unregistered external host, the egress adapter blocks the redirect, sends zero bytes to the redirect target, and records a `REDIRECT_BLOCKED` event.
- `AC-LIN-05`: Querying `/v1/lineage/query?project_id=appcode-xyz-0&from=...&to=...` returns all matching egress targets and regions with pagination; exporting `--format mermaid` produces valid Mermaid flowchart syntax.

---

### 2.5 Perimeter-Provable Claims & Audit Verification (`FR-PRV`)

- **`FR-PRV-01` Tamper-Evident Hash-Chained Ledger**
  Each persisted `LineageEvent` SHALL receive a strictly monotonic sequence number `seq` (starting at `1`), the `prev_hash` of `seq - 1` (or fixed genesis hash for `seq = 1`), and `event_hash = SHA-256(prev_hash || canonical_json(event_without_hash_and_sig))`. Canonical JSON serialization MUST be deterministic (sorted keys, UTF-8, no insignificant whitespace).

- **`FR-PRV-02` Optional Router-Boundary Cryptographic Signing**
  When configured with an Ed25519 signing key, the module SHALL sign either each `event_hash` or exported checkpoint/bundle roots with the router's private key and publish the corresponding `key_id` and public key for offline verification.

- **`FR-PRV-03` Perimeter Evidence Bundle Export**
  The module SHALL provide an export command/endpoint (`export-evidence --from T1 --to T2 [--project ... | --jurisdiction ...]`) that outputs a self-contained JSON/tar bundle containing:
  - Chain window metadata (`first_seq`, `last_seq`, `anchor_prev_hash`, `head_hash`, optional Ed25519 signature + `key_id`)
  - All hash-chained events in the slice (and inclusion/continuity context so chain integrity is verifiable)
  - Referenced policy bundle digests (and optional policy snapshots)
  - Referenced target registry snapshots
  - Summary attestation block answering: total requests, allowed/constrained/denied counts, distinct observed egress targets & regions, and any policy/integrity anomalies.

- **`FR-PRV-04` Offline Verification Tool (`verify-evidence`)**
  A standalone CLI command `verify-evidence <bundle> [--pubkey <path>]` SHALL verify:
  1. Sequence continuity (no missing or duplicated `seq` within the window)
  2. Hash-chain recomputation for every event (`event_hash` and `prev_hash` linkage)
  3. Ed25519 signature validity (when signed or when `--require-signature` is passed)
  4. Policy and registry digest consistency across referenced events
  5. Absence of unverified/unknown egress targets on restricted/jurisdiction-pinned requests.
  It SHALL emit a structured pass/fail report (JSON + human-readable summary) and exit `0` only on full pass, non-zero otherwise.

- **`FR-PRV-05` Strict Separation of `observed` vs. `declared` Claims**
  Every `LineageEvent` and `EvidenceBundle` SHALL structurally separate:
  - `observed`: router-measured facts (ingress tags, payload digest, policy digest/decision, resolved IP, TLS peer cert fingerprint, redirect status, byte counts).
  - `declared`: registry/contractual metadata (provider-claimed region label, `declared_zdr`, contractual DPA notes).
  Reports and bundle headers SHALL include a machine-readable `claim_scope: "perimeter-only"` disclaimer stating that provider-internal processing/retention is not verified by the router.

#### Acceptance Criteria Stubs (`AC-PRV`)
- `AC-PRV-01`: Writing 50 sequential events produces contiguous `seq` `1..50` where every event's `prev_hash` equals the prior `event_hash` and `verify-evidence` exits `0`.
- `AC-PRV-02`: Modifying a single field (e.g., changing `region: "US"` to `"EU"` or flipping `DENY` to `ALLOW`) in an exported bundle causes `verify-evidence` to fail with a non-zero exit code identifying the exact `seq` of the hash mismatch.
- `AC-PRV-03`: Deleting a middle event (`seq=25`) from an exported bundle causes `verify-evidence` to fail with `SEQUENCE_GAP` / `CHAIN_BROKEN` at `seq=26`.
- `AC-PRV-04`: Exporting a bundle with an Ed25519 signing key and verifying with the matching public key exits `0`; verifying with a wrong public key or tampered bundle root exits non-zero with `SIGNATURE_INVALID`.
- `AC-PRV-05`: Schema validation of any exported `EvidenceBundle` confirms `claim_scope == "perimeter-only"` and that `declared_zdr` appears strictly under `declared`, never under `observed`.

---

## 3. Non-Functional Requirements (NFR)

### 3.1 Performance & Latency (`NFR-PERF`)
- **`NFR-PERF-01` Low Synchronous Router Overhead**: Ingress tagging + target filtering + policy evaluation (excluding optional external classifier webhooks) SHALL add **< 10 ms at p95** (target < 3 ms median) on a standard 2-vCPU cloud VM for policy bundles up to 200 rules.
- **`NFR-PERF-02` Non-Blocking Streaming Support**: Observing streaming (SSE/chunked) LLM responses SHALL hash chunks incrementally in-stream without buffering the entire response body in memory.

### 3.2 Reliability & Fail-Closed Safety (`NFR-REL`)
- **`NFR-REL-01` Fail-Closed on Policy or Ledger Failure (Strict Mode)**: If the policy engine errors, fails to load a bundle, or cannot commit a pre-egress audit record in strict mode, the module MUST fail closed (`DENY`) for any request tagged with a jurisdiction constraint or `data_class > public`.
- **`NFR-REL-02` Crash Consistency**: Committed ledger events in SQLite WAL / append-only log MUST survive process restart without breaking hash-chain continuity on the next sequence number.
- **`NFR-REL-03` Concurrency Safety**: Concurrent router requests (including parallel fan-out branches) MUST serialize sequence assignment (`seq` + `prev_hash`) cleanly without race conditions or forked hash chains.

### 3.3 Security & Privacy (`NFR-SEC`)
- **`NFR-SEC-01` Privacy-by-Default Storage**: Zero raw prompt/response bodies persisted unless an operator explicitly enables debug capture on a non-restricted route (disabled by default and forbidden for `data_class=restricted`).
- **`NFR-SEC-02` Secret Hygiene**: Authorization headers (`Authorization`, `x-api-key`, provider tokens) MUST be stripped/redacted before tagging, logging, or event serialization.
- **`NFR-SEC-03` Signing Key Protection**: Ed25519 private keys SHALL be loaded via environment variable or file path with permission checks (warn/refuse world-readable key files) and NEVER written to logs or exported bundles.
- **`NFR-SEC-04` API Access Control**: Query and evidence-export HTTP endpoints SHALL bind to `127.0.0.1` by default and require bearer token authentication if bound to a non-loopback interface.

### 3.4 Modularity & Portability (`NFR-MOD`, `NFR-OPS`)
- **`NFR-MOD-01` Dual Integration Mode**: Core engine (`tagger`, `registry`, `policy`, `ledger/graph`, `verifier`) SHALL be usable both as an importable library inside `smart-router` and as a standalone HTTP sidecar service.
- **`NFR-MOD-02` Zero Mandatory Vendor Lock-in**: v1 MUST NOT require AWS, Azure, GCP SDKs or external SaaS services to build, run, or test.
- **`NFR-OPS-01` Single Cloud VM Footprint**: Runs cleanly on a single Linux VM with **< 256 MB baseline RSS** under normal load and zero external database daemon required in default mode.
- **`NFR-OPS-02` Docker-Friendly Packaging**: Configuration via env vars + mounted YAML/JSON config directory; all persistent state isolated to one data directory (`/data`) so Dockerizing later requires no architectural rework.

### 3.5 Observability & Testability (`NFR-OBS`, `NFR-QA`)
- **`NFR-OBS-01` Metrics & Structured Logs**: Emit structured JSON logs and Prometheus-format metrics (`mirevox_lineage_requests_total{decision,jurisdiction,data_class}`, `mirevox_lineage_eval_duration_ms`, `mirevox_lineage_ledger_errors_total`).
- **`NFR-OBS-02` OpenTelemetry Interoperability**: Accept and propagate W3C `traceparent`; expose helper to attach Mirevox lineage attributes (`mirevox.lineage_id`, `mirevox.jurisdiction`, `mirevox.policy_decision`, `mirevox.egress_region`) onto router spans.
- **`NFR-QA-01` Offline Deterministic Test Suite**: 100% of v1 unit and integration tests (including mock HTTPS upstreams, fan-out, MCP stubs, redirect attacks, and ledger tamper tests) SHALL run offline without live LLM API keys.
- **`NFR-QA-02` Open Source Licensing**: Repository ships with `Apache-2.0` (or `MIT`) `LICENSE` and clear README documenting standalone usage and `smart-router` composition.

---

## 4. Cross-Module Integration Stubs

| Mirevox Module | Direction | v1 Contract Stub |
| --- | --- | --- |
| **`smart-router`** | Bidirectional (primary host) | Calls `tagIngress` -> `evaluateRoute` before every model/MCP/fan-out dispatch; syncs discovered targets into `TargetResidencyRegistry`; calls `recordEgress` with transport metadata after response/error. |
| **`context-engine`** | Inbound metadata | Passes repo/document provenance IDs via `X-Mirevox-Source-Refs` (or envelope field) so lineage graph links source corpora to egress endpoints. |
| **`shadow-versioning`** | Inbound metadata | Passes `appcode` project ID via `X-Mirevox-Project` so queries can answer *"where did project X's AI data go?"* |
| **`evals`** | Outbound consumption | Polls query API or reads NDJSON event stream to compute residency compliance rates and surface `AUDIT_ONLY` / `DENY` anomalies. |

---

## 5. Open Questions for Next Council Stages

These trade-offs should be resolved by the **Requirements Vetter**, **Architect**, and **Devil's Advocate**:

1. **Implementation Stack Alignment**: Should `data-lineage` match `smart-router`'s primary runtime language (TypeScript/Node vs. Python) so in-process embedding works natively, while still exposing the local HTTP sidecar API for polyglot gateways?
2. **Policy Language Trade-off**: Is a minimal, purpose-built YAML rule schema preferable for v1 simplicity and zero dependencies, or should we evaluate CEL / OPA (Rego) for expressive conditions?
3. **Ledger Durability vs. Throughput**: In strict mode, should every `EGRESS_DISPATCHED` / `POLICY_DECIDED` commit synchronously with SQLite WAL `synchronous=FULL`, or allow configurable `NORMAL` vs. `FULL` durability?
4. **TLS Fingerprint Availability**: How reliably can the chosen HTTP client runtime expose resolved remote IP and TLS peer leaf cert SHA-256 on both standard and streaming SSE requests (and how should corporate egress proxies be represented in `observed`)?
5. **Dual-Event Order on Egress**: Should `EGRESS_DISPATCHED` be committed to the ledger *before* sending bytes on the wire (proving intent even if the process crashes mid-request), paired with `EGRESS_COMPLETED` after?
6. **Evidence Bundle Redaction / Scope**: When exporting a filtered evidence bundle (e.g., for a single `project_id`), how should hash-chain verification handle non-matching events between `first_seq` and `last_seq` (e.g., include hash-only stubs for unrelated `seq` entries, or maintain per-project sub-chains / Merkle checkpoints)?
