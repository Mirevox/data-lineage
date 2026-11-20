---
cursor:
  subagentId: "bc-fbedd29e-3cf1-56a4-a792-afd5feba4f4b"
---

# Market gap: AI traffic data lineage

_Research date: 2026-11-20_

## Bottom line

The market does **not** lack LLM request logs, regional routing, DLP, policy engines, or data-lineage graphs. It lacks a small, vendor-neutral evidence layer that connects all of them at the AI router boundary:

`ingress data tag → policy version and decision → transformation → chosen route and fallback → observed egress → provider/location claim`

That is a real gap, but a narrow one. Mirevox should ship it as an open-source module that emits interoperable evidence, not as another gateway, observability backend, DLP scanner, policy language, or lineage UI.

The phrase **“perimeter-provable” needs qualification**. A router can prove what passed through that router. It cannot prove that an application did not bypass the router, nor can it independently prove the physical processing location inside a provider. Strong claims require enforced network egress, correlation with cloud/provider audit records, and tamper-evident storage. Without those, this is useful audit evidence, not proof of all AI egress.

## README positioning one-liner

> **Mirevox Data Lineage records why AI-bound data was allowed to leave, where the router sent it, and the evidence linking ingress classification, residency policy, and egress—across cloud and local models.**

## Adjacent market

| Category / products | What they already do well | What they miss for this use case |
|---|---|---|
| **OpenTelemetry and GenAI semantic conventions** | Standard traces, metrics, context propagation, model/provider attributes, input/output message fields, and links to externally stored content. This is the right transport and correlation substrate. | Observability is not enforcement. `gen_ai.provider.name` may reflect the instrumentation's best knowledge rather than the actual processor. There is no standard chain from source classification to residency rule, route candidate set, fallback, actual egress observation, and provider-region evidence. Recording prompt bodies can also create a second data leak. |
| **OpenLineage / Marquez** | Mature dataset–job–run model, extensible facets, execution events, dataset metadata, and a lineage graph/backend. Excellent for pipelines and durable datasets. | An inference request is not naturally a batch job or a durable output dataset. The standard has no AI residency decision, egress endpoint, fallback, DLP transform, or network observation semantics. It can store custom facets, but Mirevox would still have to define and emit them. Marquez is a backend, not a router enforcement point. |
| **Cloud controls: AWS Bedrock, Azure/Microsoft Foundry, Vertex AI, VPC Service Controls, Macie, Google Sensitive Data Protection / Model Armor, Purview** | Hyperscalers provide the strongest controls inside their own boundary. Bedrock distinguishes in-region, geographic, and global inference and exposes the destination inference region in CloudTrail. Microsoft Foundry distinguishes global, data-zone, and regional processing. Vertex documents regional processing guarantees and warns against global endpoints for residency-sensitive workloads. VPC Service Controls can constrain exfiltration. DLP products classify, block, redact, and inventory sensitive data. | Controls and evidence are provider-specific and inconsistent. At-rest location, inference processing location, gateway location, log location, and support/metadata location are different concepts. These tools do not produce one normalized graph across Bedrock, Foundry, Vertex, SaaS APIs, and local models. Storage scanners such as Macie inspect S3 rather than the live cross-provider route. |
| **LiteLLM** | Open-source multi-provider proxy, retries/fallbacks, multi-region deployments, region-restricted routing guidance, callbacks, audit logs, and content-logging controls. Its own documentation correctly says location routing alone does not enforce residency and that providers, fallbacks, logs, and storage must all be bounded. | It is the closest open-source substrate, so Mirevox must integrate rather than duplicate it. LiteLLM can log route activity, but it does not provide a vendor-neutral ingress-to-egress lineage contract or independently correlate route decisions with network/provider evidence. A callback alone is not bypass proof or tamper evidence. |
| **Portkey** | Full AI gateway, multi-provider routing, guardrails, OTel-aligned observability, audit logs, regional routing, and hybrid/VPC deployment. Its hybrid data plane keeps request/response logs in the customer environment, with configurable control-plane analytics. | Commercial platform breadth exceeds Mirevox's intended scope. It primarily proves activity within Portkey's architecture; it is not a portable open evidence format for an arbitrary router. “Traffic stays in your VPC” still ends when the gateway forwards to an external model provider, so processing-residency evidence remains provider-dependent. |
| **Helicone** | Open-source gateway/observability, request tracing, costs, latency, retries, caching, US/EU data-region choice, self-hosting, and omit-body controls. It clearly documents that omit headers still send content through its backend in proxy mode, while async mode can avoid sending content. | Optimized for application observability and operations, not source-data lineage or residency-policy evidence. It does not establish that all AI traffic crossed the gateway, and region choice for Helicone's own data is not proof of the model provider's processing region. |
| **Cloudflare AI Gateway** | Provider-neutral gateway with real-time DLP on prompts and responses, blocking/flagging, request logs, and broad edge enforcement. It can inspect tool-call text. | A serious adjacent competitor, but its AI Gateway is not compatible with Cloudflare Regional Services or Geo Key Manager. DLP and logs do not by themselves form source-to-destination lineage. It is a hosted edge product rather than a portable module for existing routers. |
| **LangSmith LLM Gateway** | Routing, limits, traces, request-body storage policy, and outbound PII/secret redaction with placeholder restoration. | Redaction coverage has explicit gaps: provider responses are not scanned, some system/developer and tool-call content is skipped, direct trace ingestion bypasses gateway policy, and restored data may enter application traces. It does not solve cross-provider residency evidence. |
| **Privacy/DLP proxies: Skyflow + Kong, Nightfall, Private AI-style local/attested proxies** | Skyflow/Kong can fail closed, tokenize PII/PHI/secrets before an LLM or tool, re-identify under policy, and audit vault access. Nightfall can scan/block prompts and agent actions. Attested local proxies can prove a request went to a measured gateway implementation. These are stronger privacy controls than simple logging. | They answer “what sensitive content may leave?” or “which gateway binary handled it?”, not the full “which classified source flowed under which residency rule to which endpoint and provider region?” question. They should be attachable transform/evidence producers, not rebuilt. |
| **OPA and similar policy engines** | Versionable policy decisions, decision IDs, W3C trace correlation, bundle revisions, masking, and decision logs. Excellent as the policy decision point. | OPA does not observe or enforce the network hop by itself. It needs a router policy-enforcement point and a schema that binds the decision to the resulting route and egress observation. Mirevox should provide hooks and evidence adapters, not invent another policy language. |

## The actual gap

### 1. A normalized AI egress evidence contract

Existing tools each hold one piece of the story. The useful open artifact is a content-minimized event/graph schema containing:

- request/trace ID and parent lineage IDs;
- ingress principal, application, tenant, source system, and classification tag provenance;
- data-category tags and residency obligations, preferably without raw prompt content;
- policy engine, policy/bundle digest, inputs, decision, reason, and allowed destination set;
- transformations such as block, redact, tokenize, or de-identify, with detector/policy versions;
- selected provider, account/project, model, endpoint, route class, and fallback chain;
- router-observed DNS target, connection destination, TLS identity where available, and timestamps;
- provider-reported processing location or cloud audit-record reference, explicitly distinguished from router observation;
- logs/telemetry sinks and their own residency class;
- immutable export reference, signature/hash chain, and retention policy.

OpenTelemetry should carry request-level correlation. An OpenLineage-compatible custom facet/export can feed broader data catalogs. Neither standard should be forked.

### 2. Residency-aware hooks before routing and on every fallback

Gateways already route by provider, latency, cost, and sometimes region. The missing reusable behavior is:

1. accept an ingress classification/residency label;
2. evaluate every candidate endpoint, including retries and fallbacks;
3. fail closed when no compliant destination exists;
4. re-evaluate when route metadata changes;
5. emit the decision and the route actually taken under one correlation ID.

Fallback is the common failure mode. A primary EU route plus an unrestricted global fallback is not an EU-resident route.

### 3. Honest separation of evidence types

The graph must not collapse unlike claims into one `region` field:

- **configured**: region declared in router configuration;
- **allowed**: destinations permitted by policy;
- **observed**: endpoint/network destination seen by the router or egress sensor;
- **provider-reported**: destination region from CloudTrail or an equivalent provider record;
- **contractual**: provider documentation or agreement about processing/storage;
- **attested**: cryptographically verified runtime or signed evidence.

This distinction is more valuable than another dashboard. It prevents a regional hostname from being misrepresented as proof of regional processing.

### 4. Cross-provider graph and query surface

Security and compliance teams need queries such as:

- “Show every flow tagged `EU-personal` that left the local perimeter.”
- “Which requests used global inference or a non-EU fallback?”
- “Which policy revision allowed this Bedrock/Foundry/Vertex call?”
- “Which events have only configured-region evidence and no provider-reported location?”
- “Did prompt content enter an observability or DLP vendor outside the approved region?”

No reviewed product offers this as a lightweight, open, router-neutral module.

## Why ship this instead of wrapping existing tools?

The right answer is: **mostly wrap existing tools, and ship only the missing contract and router binding.**

### Reuse

- OpenTelemetry for trace context, spans, export, and existing GenAI attributes.
- OpenLineage facets/events when customers want catalog-level lineage.
- OPA (or an existing customer PDP) for policy decisions.
- LiteLLM/Mirevox smart-router hooks for routing and fallback enforcement.
- Cloud DLP, Skyflow, Nightfall, or customer classifiers for tagging and transforms.
- CloudTrail and equivalent provider logs for provider-side evidence.
- Customer object stores/SIEMs/ledger systems for retention and immutability.

### Build

- a minimal vendor-neutral schema for AI egress and residency evidence;
- router hooks that bind ingress tags, policy decisions, transforms, retries, and actual routes;
- adapters for provider endpoint metadata and provider audit records;
- OTel export plus optional OpenLineage facet/export;
- a small graph/query layer or reference projection;
- evidence-strength labels and explicit “unknown” values;
- tests that prove forbidden fallbacks fail closed and every accepted egress has a lineage event.

### Do not build

- another general-purpose LLM gateway;
- another tracing backend or dashboard-first observability platform;
- another DLP detector library;
- another policy language;
- a claim that application logs prove physical provider residency;
- raw prompt storage by default.

## Competitive reality

The strongest objection is valid: a disciplined team can assemble LiteLLM, OPA, OpenTelemetry, DLP callbacks, cloud audit logs, and a graph store. Mirevox earns its existence only if that assembly becomes a stable open contract with tested adapters and low operational weight.

The moat is not “AI lineage.” OpenLineage, cloud catalogs, and gateway observability already use that language. The defensible value is:

- correlation across source classification, route policy, fallback, and observed egress;
- explicit evidence strength rather than a vague regional label;
- portability across major clouds, SaaS providers, and local inference;
- composition with an existing router;
- content-minimized, self-hostable evidence.

If version one is merely a request log with `provider`, `model`, and `region`, **do not ship it**. LiteLLM, Portkey, Helicone, Cloudflare, LangSmith, and OTel already cover that territory.

## Recommended scope for an initial release

1. Define the evidence schema and threat model, including bypass and provider-trust limits.
2. Implement Mirevox smart-router middleware with fail-closed residency checks on primary routes, retries, and fallbacks.
3. Emit OTel spans/events without prompt bodies by default.
4. Add adapters for Bedrock, Microsoft Foundry, Vertex AI, and local endpoints.
5. Correlate at least Bedrock CloudTrail `inferenceRegion` as the first provider-reported proof source.
6. Export a deterministic graph projection and a signed/hash-chained JSONL evidence stream.
7. Publish conformance tests: prohibited global fallback, missing ingress tag, DLP failure, logging sink outside policy, direct-provider bypass simulation, and provider-audit mismatch.

Network enforcement is a deployment prerequisite for the strongest claim: route AI domains through the smart router and restrict direct egress. The module should report coverage gaps rather than imply completeness.

## Sources

Primary documentation, accessed 2026-11-20:

1. [OpenTelemetry GenAI semantic attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/)
2. [OpenLineage object model](https://openlineage.io/docs/spec/object-model/)
3. [OpenLineage JSON specification](https://github.com/OpenLineage/OpenLineage/blob/main/spec/OpenLineage.json)
4. [LiteLLM multi-region routing](https://docs.litellm.ai/docs/proxy/deploy/multi_region/routing)
5. [LiteLLM configuration and message-logging controls](https://docs.litellm.ai/docs/proxy/config_settings)
6. [Portkey hybrid deployment architecture](https://portkey.ai/docs/self-hosting/hybrid-deployments/architecture)
7. [Portkey observability](https://portkey.ai/docs/product/observability)
8. [Helicone compliance options](https://docs.helicone.ai/faq/compliance)
9. [Helicone omit-logs behavior](https://docs.helicone.ai/features/advanced-usage/omit-logs)
10. [Cloudflare AI Gateway DLP](https://developers.cloudflare.com/ai-gateway/features/dlp/)
11. [Cloudflare data-localization compatibility](https://developers.cloudflare.com/data-localization/compatibility/)
12. [LangSmith LLM Gateway data policies](https://docs.langchain.com/langsmith/llm-gateway-data-policy)
13. [Amazon Bedrock geographic cross-region inference](https://docs.aws.amazon.com/bedrock/latest/userguide/geographic-cross-region-inference.html)
14. [Amazon Bedrock regional inference modes](https://docs.aws.amazon.com/bedrock/latest/userguide/models-region-compatibility.html)
15. [Amazon Bedrock cross-region inference and CloudTrail destination evidence](https://docs.aws.amazon.com/bedrock/latest/userguide/cross-region-inference.html)
16. [Microsoft Foundry model deployment types](https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/deployment-types)
17. [Vertex AI data residency](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/learn/data-residency)
18. [Vertex AI locations and global-endpoint warning](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/learn/locations)
19. [Google Model Armor and Sensitive Data Protection](https://docs.cloud.google.com/model-armor/manage-templates)
20. [Amazon Macie overview](https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html)
21. [Microsoft Purview protections for generative AI](https://learn.microsoft.com/en-us/purview/ai-microsoft-purview)
22. [Skyflow LLM privacy pattern](https://docs.skyflow.com/docs/fundamentals/patterns/llm-privacy)
23. [Kong Skyflow AI Data Control plugin](https://developer.konghq.com/plugins/skyflow-ai-data-control/)
24. [Nightfall inference hooks and coverage limits](https://help.nightfall.ai/data-exfiltration-prevention/ai-agent-security/ai-governance/auditability-and-control/setup-and-installation/connect-inference-hooks)
25. [Open Policy Agent decision logs](https://www.openpolicyagent.org/docs/management-decision-logs)

---

## Second-pass validation (2026-11-20)

**Verdict (unchanged): narrow real gap; v1 is a partial answer.**

| Rank | OSS | Paid |
| --- | --- | --- |
| 1 | LiteLLM | Portkey |
| 2 | Helicone | Cloudflare AI Gateway |
| 3 | Langfuse | LangSmith LLM Gateway |
| 4 | OpenLineage + Marquez | Kong AI Gateway Enterprise |

v1 differentiates as an embeddable TypeScript **decision-record** (ingress tags → residency hook → graph → `software_attested` checksum), not as a gateway, DLP, or compliance suite. Position accordingly; do not claim provider-region proof or network enforcement.

Dark UI: this repo has **no product UI**. Showcase-site module pages should use the Mirevox dark palette (purple + neon-blue accents); keep this README/docs prose-only.

Full second-pass write-up: project store `internal/data-lineage-validation/market.md`.
