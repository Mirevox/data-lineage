---
cursor:
  subagentId: "bc-f1864a9d-d564-585d-aeaf-b1e9da70ab90"
---

# Devil's advocate: data-lineage

_2026-11-20. Against the product claim, `/cursor/stores/self/docs/product-synthesis.md` §6 and the deprioritized compliance bet, `docs/problem-opportunity.md`, `docs/market-gap.md`, and the code in `src/`._

## Verdict

Do not ship a perimeter-proof product. Ship a **router decision record**: a pure function the future smart-router calls, which returns `allow` or `deny` and a payload-free hop record of **what the router decided**.

"Perimeter-provable" is false for a userspace library on a cloud VM. Qualifying the phrase, then keeping it in the title, the type names, and the tests, is how the lie ships. Delete the phrase.

The sponsor already deprioritized "betting the umbrella on a full cloud compliance product vs hyperscalers" (`product-synthesis.md`). `docs/problem-opportunity.md` §1 item 4, §4's auditor persona, §5.3 (GDPR / EU AI Act), and §6's evidence table are that bet. Cut them before requirements lock.

What is in the tree today does not match even the honest half of the problem statement. It mints a "proof" from caller-supplied JSON.

## What is already false in this tree

| Claim in docs or names | What the code actually does |
| --- | --- |
| Perimeter-provable observed facts: ingress measurement, "zero bytes egressed on DENY", resolved IP, TLS SNI, cert fingerprint, byte counts, redirect blocking (`problem-opportunity.md` §6) | None of these are measured. No socket is opened. |
| Tamper-evident hash-chained ledger, Ed25519 boundary signature, offline `verify-evidence` (`problem-opportunity.md` §1, §4, §8) | `PerimeterProver.build` SHA-256s its own object and puts the hex on the object (`src/prove/perimeter.ts`). No chain, no key, no verifier, no disk. |
| `claimLevel: "software_attested"` | A checksum the issuer computes is not attestation. Attestation needs a verifier and a trust anchor the issuer does not control. The comment in `perimeter.ts` admits "Not TEE / network-enforced" and still says "proves". |
| `withinPerimeter: true` means the bytes stayed inside | For every decision other than `allow`, the flag is forced true (`perimeter.ts`). `tests/lineage-module.test.ts` locks this in: "keeps denied traffic within perimeter in the proof". A deny is a suggestion that a send should not happen. The module never sees whether it happened. |
| Fail-closed before bytes leave (`problem-opportunity.md` §1.2, §8) | No rules matched → `"default allow"` (`src/policy/residency.ts`). Empty `dataClasses` matches no class rule, so untagged traffic is allowed. `require_local` and `reroute` do not block a socket; they return JSON. |
| Egress graph of where traffic went, including fan-out and MCP (`problem-opportunity.md` §1.3, §8) | `LineageGraph.recordAiHop` always draws `policy → provider → region`, including on deny. `tool_call` exists on the edge enum and is never written. Nothing is fanned out. Store is a `Map` in the process. Restart deletes the "VM store". |
| Region is an observed jurisdiction | One enum: `eu \| us \| uk \| ca \| apac \| global \| onprem \| unknown` (`src/types.ts`). That cannot answer "did EU-tagged data leave EU". Bedrock in-region vs geographic vs global inference, Foundry regional vs data-zone vs global, and Vertex global endpoints do not fit in `eu`. |
| `leavesPerimeter` is a fact | Boolean on the candidate, set by the caller. `POST /v1/trace` (`src/server/main.ts`) parses that body and returns a proof. `https://api.openai.com` with `residency: "onprem"` and `leavesPerimeter: false` is an allow and a within-perimeter proof. The URL is never checked against the label. |
| 100% coverage of routed AI egress (`problem-opportunity.md` §3.1) | Coverage equals "callers who remembered to call `traceRequest`". Non-goal §4 admits bypass is someone else's firewall. Those two claims cannot both be in the requirements. |
| Hash-only payload fingerprint, measured at ingress | `IngressTagger` and `POST /v1/trace` accept raw `payload`. The lineage process is then a second copy of the prompt. Short-prompt SHA-256 is dictionary-reversible. |
| Standalone sidecar for any OpenAI-compatible gateway | The HTTP server is not a proxy. It does not sit on the request path. It is a proof oracle with no auth, `access-control-allow-origin: *`, and a payload field. Default bind is loopback; the CORS header shows the intent is already sloppy. |
| Demo rule "secrets stay local" (`src/server/main.ts`) | `allowResidencies` for secrets includes `us`, `uk`, `ca`, and `apac`. The only brake is the caller-controlled `leavesPerimeter` flag. |

Market research (`docs/market-gap.md`) is righter than the problem draft: it says the phrase needs qualification and lists LiteLLM, OTel, OPA, Portkey, Helicone, Cloudflare, and cloud audit logs. It then recommends the balloon anyway: Bedrock/Foundry/Vertex adapters, CloudTrail `inferenceRegion` correlation, a signed hash chain, and a graph projection, in v1. That is a second product. Do not lock it.

## 1. "Perimeter-provable" is oversold

Yes. Kill it. There is no perimeter in this design.

A perimeter is a boundary you can force: default-deny egress, workload identity, and a path that is the only way out. A library that returns JSON is not that boundary. A cloud VM is a hypervisor you do not operate. Docker later does not create a perimeter either.

"Provable" and "attested" mean a skeptical party can check a statement against an anchor you cannot rewrite. This module has none of:

- a network choke point (security group, firewall, VPC service controls, forced proxy);
- a measurement of the socket (DNS answer, remote IP, SNI, cert);
- a provider-side record (CloudTrail `inferenceRegion`, Foundry deployment type, Vertex location), fetched independently and stored as a different field;
- a TEE / TPM / Nitro quote of the router binary;
- an append-only log anchored outside the VM (another party, a transparency log, an HSM whose key is not on the disk being protected).

A SHA-256 of a document, stored in the document, on the same disk as the writer, proves that the writer can hash. An Ed25519 key on that same VM signs whatever the operator, or anyone who copies the disk, wants. An offline verifier will verify the forgery. Building that CLI is theater. Do not put it in v1.

Even a real network choke point would not prove residency inside the provider. Region on a hostname is a **declared** label. Global and geographic cross-region inference exist specifically so a regional URL can run elsewhere. Subprocessors, abuse monitoring, support access, and the provider's own logs are outside the router's sight. Record them as unknown, or do not record them. Never fold them into one `region` or one `withinPerimeter` bit.

The strongest sentence this module can ever say, including after smart-router exists and a firewall forces traffic through it:

> The router recorded an allow or a deny under policy hash H for a caller-supplied tag, and it recorded the declared region of the candidate it selected. This is not evidence of where the provider processed the data, and it says nothing about traffic that did not pass through the router.

v1 cannot say the second clause about the firewall, because v1 will not ship the firewall. So v1's sentence stops at "the router recorded its decision."

`software_attested` must not appear in a JSON response. Reviewers will screenshot the field and drop the comment above it.

## 2. This duplicates OpenTelemetry and policy engines

Mostly yes. The residue that is not a duplicate is small, and it is a schema plus a fail-closed predicate, not a platform.

Already done by other tools:

- **OpenTelemetry GenAI semantic conventions** already carry provider, model, request identity, and token counts, and they propagate context across fan-out. A residency decision is a handful of attributes on the router's existing span (`gen_ai.provider.name`, plus `mirevox.policy.hash`, `mirevox.decision`, `mirevox.declared_region`). Shipping a collector, a graph store, or an OTel SDK dependency to hold those fields is a worse Jaeger.
- **OPA (and Cedar, and the cloud's own authorizers)** already return versioned decisions, bundle digests, and decision logs. `ResidencyPolicyEngine` is a priority-ordered list with default allow. That is not a policy engine worth maintaining. If a rule needs more than an allow-list, call OPA and store OPA's decision id. Do not grow Rego-lite.
- **OpenLineage / Marquez** already own dataset-job lineage. An inference hop is not a dataset job. A custom facet in v1 burns the schedule to look compatible with a standard this product should not implement. Defer forever or until a catalog team asks.
- **LiteLLM** already routes, falls back, and calls back. Its own docs say region routing is not residency enforcement. A LiteLLM callback that logs `{tag, policy_hash, decision, declared_region}` is a weekend. If that callback is shorter than this package's public API, this package should be a markdown schema, not a service. Portkey, Helicone, Cloudflare AI Gateway, and LangSmith already sell the gateway-shaped version.
- **Cloud audit logs** are what an auditor already accepts inside one cloud. A home-grown ledger that disagrees with CloudTrail loses.

The market-gap doc's chain (`tag → policy version → transform → route and fallback → observed egress → provider claim`) is a real gap **as a checklist of fields that must not be collapsed**. It is not a gap that justifies a new server. v1 has no transform pipeline, no observed egress, and no provider claim. Pretending to fill the whole chain with empty or copied fields recreates the collapsed `region` the checklist was meant to prevent.

Do not build in this repo: an OTel backend, a policy language, an OpenLineage emitter, a DLP classifier, a graph database, a query UI, or CloudTrail ingestion. Document a flat attribute map so the router can copy fields onto a span. Take no OpenTelemetry dependency until a second consumer needs it.

## 3. Who needs this before smart-router exists

Nobody who needs enforcement.

| Persona in `problem-opportunity.md` §4 | Reality before smart-router is a choke point |
| --- | --- |
| Platform / AI infra engineer | They already have, or can add, a callback on LiteLLM, Kong, APIM, or the cloud's gateway. They do not need a second process on port 3847 that cannot see the socket. |
| Security / privacy engineer in a regulated org | They buy Bedrock geographic inference, Foundry data zones, Vertex regional endpoints, VPC Service Controls, PrivateLink, Purview, and a DPA. They will not accept `software_attested` from an unauthenticated POST. Putting GDPR and the EU AI Act in the problem statement recruits them into a claim this module cannot support. |
| Compliance auditor | There is no evidence bundle they can use. A self-hash is not workpaper. Drop this persona from v1. |
| Solo builder / home lab (the actual sponsor audience) | They want one answer: "this activity stayed on the local model" or "it was sent to a provider." That is a field on the router log. They do not want a proof type, a graph, or a sidecar. |

Product synthesis puts lineage **on the router path**. There is no router in this repo. `POST /v1/trace` does not become a path because it is HTTP. Until smart-router imports the function and refuses to open the upstream socket on `deny`, the module has no user and no coverage. Building it first produces a demo that stamps invented hops.

Evals, context-engine, and shadow-versioning are not v1 consumers. Do not block on `appcode`, MCP tool-call edges, or eval violation counts. Those are imaginary call sites.

The only legitimate pre-router artifact is a schema file the router authors can vendor. A running server is a liability: it accepts prompts, returns objects named proof, and will be copied into a README.

## 4. What v1 must not claim

Banned in README, site copy, HTTP responses, schema field names, and tests (this file may quote them to forbid them):

1. Perimeter-provable, perimeter proof, within-perimeter, software-attested, attested, tamper-evident, non-repudiable, evidence bundle, offline verifier.
2. Compliance, GDPR-safe, Schrems II, EU AI Act record-keeping, HIPAA-ready, SOC 2 evidence, "meets residency law."
3. That the provider processed, stored, or trained only in a region. That subprocessors, abuse review, or support access stayed in-region.
4. That bytes did not leave, that a deny was obeyed, or that coverage is complete or 100%.
5. That the module observed DNS, IP, SNI, certificates, HTTP status, or redirects. v1 does not open the socket.
6. That caller-supplied `dataClasses`, `declaredResidency`, or `leavesPerimeter` were classified or measured. They are declared. Name them `declared*`.
7. A lineage graph of AI traffic, MCP hops, or fan-out. A parent id on a record is not a graph product.
8. An audit log, ledger, or VM store. v1 persistence is whatever the router already writes. In-memory `Map` does not count.
9. Payload fingerprinting as a feature. v1 must not accept prompt or completion bytes. No `payload` argument.
10. That `eu` / `us` / `apac` are jurisdictions. v1 regions are opaque strings the operator typed into the catalog (`eu-central-1`, `foundry-swedencentral`, `local`). The module does not interpret them beyond equality with the allow-list.
11. A standalone gateway, sidecar enforcement, or drop-in proxy. Docker is out of v1, matching the sponsor note.
12. Hash-chain or signature security. Do not ship a key.
13. Default-allow described as a control. See the keep-scope below.

Also banned as soft substitutes: assurance, guarantee, sovereign, air-gapped, zero-trust, "where data actually went," "where the router sent it" (v1 does not send).

## 5. Kill criteria

Default outcome is **merge into smart-router**, not a long-lived sibling product. A separate repo is overhead until a second runtime imports the schema.

**Merge now (do not keep staffing this repo as a product) if any of these is true:**

1. The public surface is one predicate plus a JSON record. Put it in smart-router at `src/residency/` (or a tiny package that repo depends on). Delete `src/server`, `src/prove`, and `src/graph`.
2. Smart-router's first routed request does not call `decide`. A lineage module with no production call site is dead. Do not keep it warm with a demo server.
3. The only consumer is the person who wrote it.

**Stop and strip, rather than "fixing forward," if any of these happen:**

4. Requirements lock `problem-opportunity.md` §6 or §8 (evidence bundle, verifier, observed IP/SNI, complete fan-out DAG, hash chain). That scope is the hyperscaler-compliance bet. Reject the requirements draft.
5. v1 grows any of: CloudTrail or other provider-audit adapters, an OTel collector, a graph database, SQLite "lineage store," a policy DSL, DLP/regex classification, Ed25519, a web UI, MCP tracing. Each one is a product. None of them make the decision record true.
6. A LiteLLM (or equivalent) callback reproduces the record in less code than the exported API. Publish the schema as a doc and archive the package.
7. The README needs a banned word from §4 to sound interesting. The feature that required the word is the feature to delete.
8. Region metadata becomes a catalog the project must maintain by hand (which Bedrock profile is geographic this month). That data rots. The operator types declared region strings. If usefulness depends on a curated world map, abandon it.

**Abandon the control story, keep a log line, if:**

9. After the router actually forwards traffic, nobody passes a residency constraint. Then the router logs `provider` and `model` like every other gateway, and this module is deleted.
10. Tests continue to expect `withinPerimeter === true` on deny, or `claimLevel === "software_attested"`. Those tests are acceptance of a false claim. They are not a safety net. Delete them before any tag.

**Do not wait for a time box.** The kill signal is a sentence or a type name, and it is already in the tree.

## Must-keep scope

v1 is this function and nothing else. No HTTP server. No graph class. No prover. No Docker.

```ts
decide(input: {
  tag: {
    correlationId: string;
    tenantId: string;
    sourceId: string;
    declaredDataClasses: string[]; // caller-supplied, untrusted
    // opaque operator strings, not the eu|us|apac enum
  };
  policy: {
    hash: string; // sha256 of the canonical policy JSON
    rules: Array<{
      id: string;
      tenants: string[];          // empty = all tenants
      whenDataClasses: string[];  // empty = all classes
      allowDeclaredRegions: string[];
      denyIfDeclaredLeaves: boolean;
    }>;
  };
  candidate: {
    id: string;
    declaredRegion: string;
    declaredLeavesOperatorNetwork: boolean;
    endpoint: string; // recorded, not verified
  };
}): {
  outcome: "allow" | "deny";
  reason: string;
  matchedRuleId: string | null;
  record: HopRecord; // the return value is the record; the caller persists it
}
```

`HopRecord` fields: `correlationId`, optional `parentId` (the router sets this when it fans out), the tag, `policy.hash`, the candidate's declared fields, `outcome`, `reason`, `matchedRuleId`, `evaluatedAt`. No prompt, no completion, no content digest, no `withinPerimeter`, no `claimLevel`.

Fail closed:

- No matching rule → `deny`, reason `no_rule`. Exception: a tag whose `declaredDataClasses` is exactly `["public"]` may default to allow, and the record must say `default: "allow_public"`.
- Candidate `declaredRegion` not in the matched rule's allow-list → `deny`.
- `denyIfDeclaredLeaves` and `declaredLeavesOperatorNetwork` → `deny`.
- Missing `declaredRegion` → `deny`.
- There is no `reroute` and no `require_local`. The router walks candidates and calls `decide` on each. A suggestion API is how fallbacks bypass the check.

Enforcement contract, written in the README in one paragraph: the router must not open the upstream connection when `outcome` is `deny`. This function cannot detect a router that ignores it. A unit test that expects `deny` is a test of the predicate, not of a perimeter. Say that next to the test.

Evidence strength in v1 is one literal: `router_decision`. Do not add `observed`, `provider_reported`, or `attested` until a different code path fills them from a different source and a test shows `decide` cannot set them.

Policy JSON is configuration. Hash it so the record names the policy. If the allow-list is not expressive enough, stop and call OPA; do not add rule types.

OTel: a table in the README mapping record fields to span attributes. No exporter in v1.

Honest README one-liner:

> Mirevox data-lineage is a function a router calls to deny a candidate whose declared region is outside the hashed allow-list, and to return a payload-free record of that decision.

## Required edits before requirements lock or a README

These are deletions, not follow-up features. The current tests certify the bad behavior; change the tests with the code.

1. Delete `src/prove/perimeter.ts`, `PerimeterProof`, `PerimeterProver`, `claimLevel`, and `withinPerimeter`.
2. Delete `src/graph/lineage.ts` until a real caller queries stored records. Do not draw an egress edge for a deny. Do not invent client → ingress → router → policy → provider → region from one input object.
3. Delete `src/server/main.ts` or stop it returning a proof. A demo server that accepts `payload` and stamps `software_attested` will be the thing people run. Prefer no server.
4. Remove `payload` from the tagger. The library never sees prompt bytes.
5. Replace the `eu|us|apac` enum with opaque `declaredRegion` strings. Drop `unknown` as a fake region.
6. Rename `leavesPerimeter` to `declaredLeavesOperatorNetwork`. Do not treat it as a measurement. Do not claim the URL was checked.
7. Change no-match from allow to deny, except the explicit public default above. Rewrite `tests/policy.test.ts` and `tests/lineage-module.test.ts` accordingly. Delete "keeps denied traffic within perimeter".
8. Put `policy.hash` on every record. `replaceRules` without a new hash is an unaccounted policy change.
9. Rewrite `docs/problem-opportunity.md` §1.4, §2.5, §3.1, §4 auditor row, §5.3, §6, and §8 so they match the keep-scope. Until that rewrite, the problem draft is not a requirements source.
10. Cut market-gap "recommended initial release" items 4–6 (cloud adapters, CloudTrail, signed JSONL, graph projection). Keep items that are a schema, a fail-closed check, and a threat-model paragraph.

If those edits do not land, do not describe the module as router-side, as lineage, or as evidence. Describe it as a demo that prints a hash of its input.
