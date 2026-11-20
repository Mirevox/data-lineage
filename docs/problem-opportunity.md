# Mirevox `data-lineage` — Problem & Opportunity

**Module:** `data-lineage` (https://github.com/Mirevox/data-lineage)
**Umbrella:** Mirevox (open-source modular agentic control plane)
**Placement:** Router-side control-plane module on the `smart-router` request/egress path (also usable standalone with any OpenAI-compatible or custom AI gateway)
**Stage:** v1 Draft — Requirements Gathering

---

## 1. Summary

When an engineering team or solo builder routes AI traffic across multiple model providers (Azure Foundry, AWS Bedrock, Google Vertex, local models) and remote MCP tools through a unified gateway, visibility into **where data actually went** breaks down immediately. A single user prompt can be split into parallel sub-tasks, enriched with context from multiple repositories, forwarded to a remote MCP tool, and completed across different cloud regions.

Mirevox `data-lineage` is an open-source, router-side control-plane module that solves the perimeter half of this problem without competing on foundation models or requiring a heavyweight enterprise compliance stack. For v1, it provides four composable primitives on the router path:

1. **Ingress tagging** of AI-bound requests with jurisdiction, data classification, project (`appcode`), and source provenance.
2. **Residency-aware route policy hooks** that deterministically allow, constrain, reroute, or fail-closed deny outbound model and MCP calls before bytes leave the perimeter.
3. **An egress and lineage graph** capturing single-hop, task-split fan-out, and MCP tool-call flows on a single lightweight VM store.
4. **Perimeter-provable audit evidence** (tamper-evident hash-chained ledger + optional router-boundary signatures + offline verifier) that cleanly separates what the router observed from what upstream providers only declare.

---

## 2. Problem Statement

### 2.1 Multi-provider routing breaks data-location visibility
Unified AI routers (such as Mirevox `smart-router` or LiteLLM-class gateways) deliberately abstract upstream backends behind a single endpoint for IDE agents (VS Code), chatbots, and automation harnesses. That abstraction solves developer ergonomics while creating an operational blind spot: callers no longer know which provider, cloud region, or deployment tier (`on-prem` vs. regional cloud vs. global endpoint) actually received a given prompt or file snippet.

### 2.2 Fan-out and MCP tool calls create hidden secondary egress
Modern agentic traffic is no longer a single request-response pair:
- A router can **split multi-part prompts** and fan them out across multiple backends in parallel.
- An agent can invoke **remote MCP servers** or external workflows mid-turn, sending derived context or repository excerpts outside the original model's region.
- Context engines inject chunks from multiple repositories (`appcode` projects) into a single turn, mixing data classifications.

Without lineage propagation across every hop and child span, enforcing residency only on the primary chat completion call still leaks sensitive context through fan-out branches or remote tool calls.

### 2.3 Policy exists in slide decks, not on the egress path
Most teams rely on static Wiki rules ("EU customer data stays in `eu-central-1` or local Ollama"), provider portal toggles, or manual developer discipline. None of those stop a misconfigured fallback route, a newly polled model in a US region, or an HTTP redirect from sending restricted payloads across jurisdictions.

### 2.4 Existing tooling forces an unworkable trade-off
- **Hyperscaler governance tools** (Azure AI Content Safety/Foundry logging, Bedrock CloudTrail, Vertex audit logs) only see traffic inside their own cloud. They cannot trace a workflow that starts in VS Code, hits a local model, calls an MCP tool, and falls back to Bedrock.
- **Enterprise CASB / AI-DLP suites** are closed-source, expensive, heavyweight to deploy, and built around generic HTTP inspection rather than agentic task-splitting, MCP invocations, or router-native policy hooks.
- **Generic LLM observability tools** focus on prompt latency, token cost, and quality traces; they typically store full prompt plaintext (creating a new privacy liability) and do not enforce fail-closed residency routing or produce tamper-evident egress proofs.

### 2.5 Teams cannot answer basic provenance questions with verifiable evidence
When a security reviewer, enterprise customer, or regulator asks:
- *"Did any payload tagged `jurisdiction=EU` or `data_class=restricted` leave `EU` or `on-prem` between date A and date B?"*
- *"Which external providers, regions, and MCP servers received code from project `appcode-xyz-0`?"*
- *"Can you prove the residency policy was actually active and evaluated on routed traffic?"*

Teams today answer with ad-hoc log greps and trust-me screenshots rather than reproducible, tamper-evident records.

---

## 3. Opportunity

### 3.1 Chokepoint leverage on the router path
Because Mirevox `smart-router` already terminates client traffic, holds centralized provider credentials, discovers/polls upstream targets, and orchestrates fan-out, placing `data-lineage` directly on that control plane gives 100% coverage of routed AI egress with zero SDK changes in upstream models and minimal integration overhead in clients.

### 3.2 Practical, single-VM, open-source primitive
There is a clear gap for a lightweight, self-hostable, Apache-2.0/MIT control-plane module that runs cleanly on a single Linux cloud VM (no Kafka, Neo4j, or full homelab cluster required for v1), stays Docker-friendly for later packaging, and works either embedded in `smart-router` or as a standalone HTTP sidecar.

### 3.3 Native composability across the Mirevox control plane
`data-lineage` multiplies the value of sibling Mirevox modules without coupling into a monolith:
- **`smart-router`**: primary enforcement point for ingress tags, target residency metadata, fan-out propagation, and egress observation.
- **`context-engine`**: supplies repository/document provenance IDs so lineage ties egress back to source codebases.
- **`shadow-versioning`**: binds requests to `appcode` project IDs so non-technical stakeholders and engineers share one project identifier across documents and AI egress traces.
- **`evals`**: consumes lineage events and shadow-mode (`AUDIT_ONLY`) violation counts alongside live conversation evaluations.

### 3.4 Durable add-on value
Hyperscalers will keep improving single-cloud compliance tooling, but they have weak incentives to build vendor-neutral, cross-cloud + local + MCP lineage that makes switching away from their cloud easier. As an open-source module under the Mirevox charity umbrella, teams can run it as-is, embed it in internal platforms, or commercialize managed layers around it.

---

## 4. Who Cares (Target Users & Concrete Needs)

| Persona | Environment | Concrete Pain | What v1 Solves |
| --- | --- | --- | --- |
| **Platform / AI Infra Engineer** | Operates an internal gateway (`smart-router` or similar) across Foundry, Bedrock, Vertex, local models, and MCP servers | Needs deterministic regional routing rules, safe fallback (e.g., force local when restricted), and debuggable fan-out traces | Declarative residency policy hook, target residency registry, queryable DAG per `trace_id` |
| **Security / Privacy Engineer** | Regulated or cross-border org (EU/GDPR, UK, Canada, healthcare/finance, B2B SaaS with residency clauses) | Must prevent accidental cross-border egress and avoid storing raw prompts in audit logs | Fail-closed policy evaluation, hash-only payload fingerprinting by default, tamper-evident ledger |
| **Solo Builder / Engineering Lead** | Runs VS Code / local chatbot / agent harnesses across client and personal repos (`appcode` projects) | Wants sensitive client code pinned to local/in-region models while keeping frontier cloud models available for public/generic tasks | Identity/project-derived ingress tags + per-project routing constraints without manual model switching |
| **Compliance / Internal Auditor** | Periodic customer security reviews or internal governance checks | Needs reproducible proof of what left the perimeter and under which policy version | Exportable Perimeter Evidence Bundles + offline `verify-evidence` CLI |

---

## 5. Why Now

1. **Agentic routing and MCP exploded the egress surface.** Moving from one-shot chat APIs to multi-model routers, task fan-out, and remote MCP tools means a single user interaction routinely crosses multiple vendors and jurisdictions.
2. **Regional and local backends are now viable substitutes.** Foundry regional deployments, Bedrock regional inference profiles, Vertex regional endpoints, and strong local models make residency-constrained routing operationally practical—the missing piece is the policy and lineage layer that governs them uniformly.
3. **Contractual and regulatory scrutiny is shifting from policy docs to technical evidence.** GDPR transfer assessments, EU AI Act record-keeping expectations, and enterprise B2B data-residency addenda increasingly ask for verifiable egress controls rather than static architecture diagrams.
4. **Cross-cloud neutrality is still unserved in OSS.** Developers adopting open gateways have routing and cost tracking, but lack an open, lightweight, tamper-evident residency and lineage module designed for multi-hop AI traffic.

---

## 6. Trust Boundary: What "Perimeter-Provable" Means

Being honest about the cryptographic and network trust boundary is a core requirement for this module. Once bytes leave the router's egress interface to an external provider API, a router-side module **cannot** cryptographically prove what happens inside the vendor's GPU cluster or internal logging stack.

`data-lineage` explicitly separates **perimeter-provable facts** from **provider-declared metadata**:

| Category | What `data-lineage` Claims | Basis |
| --- | --- | --- |
| **Perimeter-Provable (Observed)** | Which tags, project/source refs, and canonical payload SHA-256 entered the router | Measured directly at ingress |
| **Perimeter-Provable (Observed)** | Which exact `policy_bundle_sha256` evaluated the request, what decision (`ALLOW`/`DENY`/`CONSTRAIN`) was produced, and that zero bytes egressed on `DENY` | Deterministic local evaluation before egress socket write |
| **Perimeter-Provable (Observed)** | Which exact upstream URL, resolved remote IP, TLS SNI / peer certificate fingerprint (when exposed), byte counts, and HTTP status were observed on egress—plus blocking of unvalidated 3xx redirects | Measured at the router egress client |
| **Perimeter-Provable (Observed)** | Every fan-out sub-request and routed MCP call linked to its parent `lineage_id` | Context propagation across router hops |
| **Perimeter-Provable (Tamper-Evident)** | Recorded lineage events were not silently deleted or modified after commit | Append-only SHA-256 hash chain + optional Ed25519 boundary signing + offline verifier |
| **Provider-Declared (Not Proven)** | Whether an upstream regional endpoint actually processes/retains data strictly inside that jurisdiction or honors Zero Data Retention (ZDR) | Recorded from target registry as `declared` contractual metadata, never presented as cryptographic proof |

---

## 7. Non-Goals (Explicitly Out of Scope for v1)

To keep v1 focused, runnable on a single cloud VM, and honest about scope, the following are **explicitly out of scope**:

1. **No foundation models or heavy ML DLP engines.** v1 ships only lightweight deterministic taggers/classifiers (headers, identity defaults, regex/pattern hooks) and a pluggable interface for external classifiers.
2. **No full cloud compliance suite or Terraform/IAM portal.** We are not building a SOC 2 / ISO 27001 portal, cloud-account posture scanner, or approved-pattern infrastructure provisioning UI.
3. **No claims of vendor-internal attestation.** Confidential computing (TEE/nitro enclave attestation) and verification of provider-internal retention or sub-processors are out of scope for v1.
4. **No kernel/eBPF/host-firewall interception of bypass traffic.** v1 governs and traces traffic traversing the router/module path. Preventing developers from bypassing the router directly to `api.openai.com` is the responsibility of network egress firewalls / VPC controls, which complement this module.
5. **No distributed cluster or full homelab dependency.** v1 must not require Kafka, Neo4j, ClickHouse, or a multi-container homelab stack to run or test. Single-node embedded storage (e.g., SQLite / append-only JSONL) is the v1 default; Docker and external storage adapters come cleanly via interfaces.
6. **No web UI dashboard in v1.** v1 delivers library hooks, HTTP API, CLI query/export/verify commands, and machine-readable graph formats (JSON, Mermaid/DOT, OTel attributes). Visual UI lives later in the Mirevox showcase/control-plane shell.
7. **No default plaintext prompt/response archiving.** Storing raw sensitive prompts by default turns the lineage store into a high-risk data honeypot. v1 stores digests, tags, and metadata by default.

---

## 8. v1 Definition of Done (High-Level Signals)

- A router-side module runs cleanly on a single Linux cloud VM with mock/stub backends (no live cloud keys required for tests) and exposes both an in-process hook API and a local HTTP sidecar API.
- Tagged requests (`jurisdiction`, `data_class`, `appcode`) are deterministically allowed, constrained to compliant targets, or fail-closed denied before any outbound network call occurs.
- Multi-hop traffic (task-split fan-out + MCP tool invocations) produces a complete, queryable directed lineage graph preserving parent-child edges and inheriting residency constraints.
- Exporting a Perimeter Evidence Bundle and running the offline verifier succeeds on intact logs and deterministically fails when any event, hash link, signature, or sequence number is altered or omitted.
