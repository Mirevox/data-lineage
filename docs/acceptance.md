# Acceptance Council Report — Mirevox `data-lineage` (v1)

- **Date:** 2026-11-20
- **Council Role:** Acceptance Validation (Gemini)
- **Branch:** `cursor/data-lineage-v1-9413`
- **Inspected State:** `HEAD` `2e63aed` (following `b60169a`; also observed concurrent untracked `tests/edge-cases.test.ts` and uncommitted `docs/requirements.md` from sibling council agents, left untouched)
- **Requirements Baseline:** Evaluated against locked `FR-01`..`FR-08` and `NFR-01`..`NFR-06` (commit `33251ea`) **and** cross-checked against the expanded spec merged in `b60169a` (`FR-ING`, `FR-POL`, `FR-GRF`, `FR-PRV`, `FR-MOD`, `NFR-01`..`NFR-08`).

## Overall Verdict: **FAIL**

Core build/smoke run cleanly offline (`npm run typecheck`, `npm run build`, original 3 test files 7/7, HTTP smoke, CLI smoke, `evaluate` p95 `0.039 ms`, `traceRequest` p95 `0.199 ms`, RSS `80.3 MB`), and small doc-only gaps were fixed directly. However, **v1 cannot be accepted yet**:
- A live `preferLocal: true` regression introduced in `b60169a` (independently confirmed both by direct repro and by sibling `tests/edge-cases.test.ts`, which currently fails 13/39 tests due to the `preferLocal` bug plus pre-`b60169a` reason-string / empty-egress expectations and `LOCAL://` URL casing).
- Two proof/verifier edge-case bugs (`withinPerimeter` on `deny` + leaving `tool_call`, `verify()` missing schema validation), unhardened sidecar error/rule handling (`500` vs `400`, no `413` 1 MiB cap, silent `demoRules()` fallback), CLI argument bugs, and missing test coverage across `RoutePolicyHook`, `LineageGraph` filtering, and `PerimeterProver.verify()`.

---

## 1. Requirements Scorecard (`FR-01`..`FR-08`, `NFR-01`..`NFR-06`)

| ID | Status | One-Line Evidence |
| --- | --- | --- |
| **FR-01** | **PASS** | `IngressTagger.tag` / `DataLineageModule.traceRequest` emit all required fields; `tests/ingress.test.ts` verifies PII tag + `sha256:<64-hex>` digest. |
| **FR-02** | **FAIL** | `b60169a` broke `preferLocal: true` (when `denyLeavePerimeter: false`, `eu` cloud + `local` alt returns `allow` instead of `reroute`, reproduced live); `deny`, `tenants`, and `preferLocal` also lack unit tests. |
| **FR-03** | **PARTIAL** | `RoutePolicyHook` and `createRoutePolicyHook` are exported from `src/index.ts` and exposed on `DataLineageModule.policyHook`, but zero tests verify engine parity. |
| **FR-04** | **PARTIAL** | `LineageGraph.recordAiHop` builds all 6 node kinds and `snapshot(correlationId)` isolates correlations in HTTP smoke (2 traces → 5 edges / 1 correlation), but unit tests never test `correlationId` isolation or assert an `egress` edge explicitly. |
| **FR-05** | **PARTIAL** | `PerimeterProver.build` emits `software_attested` SHA-256 checksum over tag/decision/hops and docs state non-TEE; however `deny` + leaving `tool_call` still yields `withinPerimeter: true`, `verify()` skips schema validation (`claimLevel: "tee_attested"` returns `true`), and `src/types.ts:113` / `src/server/main.ts:151` retain overclaiming phrasing. |
| **FR-06** | **PASS** | Smoke on port `13847` passed: `GET /health` 200, `GET /rules` 200, `POST /v1/trace` 200 (`tag`+`decision`+`graph`+`proof`), `GET /graph?correlationId=` 200 (hardening deltas tracked below under `FR-MOD-02`/`03` & `NFR-07`). |
| **FR-07** | **PASS** | `config/residency-rules.json` defines `eu-pii-stay` (`eu`/`onprem`, PII/PHI) and `secrets-local` (`onprem` only, secrets), verified via `GET /rules`. |
| **FR-08** | **PARTIAL** | `node dist/cli.js trace examples/sample-request.json --rules config/residency-rules.json` prints JSON (`decision: "reroute"`), but `usage()` advertises unimplemented `graph` subcommand, bare `--rules` silently defaults to `[]` (allow-all), and `b60169a` `docs/requirements.md` §3.2 contradicts CLI inclusion. |
| **NFR-01** | **PASS** | Core `src/` (excluding `src/server/main.ts`) has zero network imports; `npm test` (7/7), `typecheck`, and `build` pass offline in `1.1 s`; measured `evaluate` p95 `0.039 ms` (100 rules), `traceRequest` p95 `0.199 ms` (16 KiB). |
| **NFR-02** | **PASS** | `package.json` sets `engines.node: ">=20"` and `license: "Apache-2.0"`, `LICENSE` has full Apache-2.0 text, and `tsconfig.json` enforces `strict: true` + `noUncheckedIndexedAccess: true`. |
| **NFR-03** | **PASS** | Multi-stage `node:22-alpine` `Dockerfile` exposes `3847` with env-var host/port config (`docker` CLI unavailable on VM; build optional for v1). |
| **NFR-04** | **PASS** | Fixed in `README.md` (explicitly forbids treating `PerimeterProof`/`software_attested` as perimeter or GDPR/HIPAA/EU AI Act/SOC2 evidence) and `docs/problem-opportunity.md` (post-lock notice added); minor code string cleanup remains in `src/types.ts` & `src/server/main.ts`. |
| **NFR-05** | **PASS** | Zero matching rules return `allow` (`src/policy/residency.ts:62-69`), documented in `README.md` and `docs/architecture.md`. |
| **NFR-06** | **PASS** | Fixed in `README.md` and `docs/architecture.md` to explicitly name `declaredResidency`, `dataClasses`, `candidate.residency`, and `leavesPerimeter` as caller-declared/untrusted; minor JSDoc fix remains in `src/types.ts:46`. |

---

## 2. Cross-Check Against Expanded `b60169a` `docs/requirements.md`

| Pillar / IDs | Status | Evidence / Gap |
| --- | --- | --- |
| `FR-ING-01`..`04`, `NFR-04` | **PARTIAL** | Implementation matches; tests lack `parseIngressTag`, invalid-enum `ZodError`, `Uint8Array`, canary zero-leakage, and `labels` validation cases. |
| `FR-POL-01`..`05`, `NFR-01` | **FAIL** | Latency passes (`0.039 ms` p95), multi-rule reroute check (`b60169a`) and perimeter-first ordering (`2e63aed`) landed, but `preferLocal: true` regressed (always skipped when `candidateFit.ok`). |
| `FR-GRF-01`..`04`, `NFR-08` | **PARTIAL** | Implementation matches and `README.md`/`docs/architecture.md` now document `clear()` lifecycle; `tests/graph.test.ts` is missing (`tool_call`, referential integrity, `snapshot(correlationId)` isolation, `clear()`). |
| `FR-PRV-01`..`04`, `NFR-03` | **FAIL** | `build()` still returns `withinPerimeter: true` when `decision !== "allow"` even if a `tool_call` edge has `leavesPerimeter: true`; `verify()` does not run `PerimeterProofSchema.safeParse`; `tests/proof.test.ts` is missing. |
| `FR-MOD-01`..`03`, `NFR-06`, `NFR-07` | **FAIL** | RSS passes (`80.3 MB < 128 MB`) and default bind is `127.0.0.1`; however `POST /v1/trace` returns `500` instead of `400` on invalid JSON/Zod, lacks 1 MiB `413` body cap, and `loadRules()` silently falls back to `demoRules()` on invalid explicit `MIREVOX_LINEAGE_RULES`. |

---

## 3. Doc-Only Fixes Applied Directly by Acceptance Council

1. `README.md` — Renamed table row `Decision proof` → `Decision checksum (PerimeterProof)`, added explicit prohibition against treating `PerimeterProof`/`software_attested` as perimeter or compliance evidence, explicitly listed `declaredResidency`, `dataClasses`, `candidate.residency`, and `leavesPerimeter` as caller-declared/untrusted, documented ephemeral `LineageGraph` + `clear()`, added HTTP endpoint summary + CLI trace command, and linked `docs/acceptance.md`.
2. `docs/architecture.md` — Added `candidate.residency` to Trust boundaries and documented `LineageGraph.clear()` for bounding in-memory graph growth.
3. `docs/problem-opportunity.md` — Added a top post-lock provenance notice so pre-lock draft claims (hash-chained ledger, Ed25519, TLS observation, GDPR/EU AI Act evidence) cannot be misread as shipped v1 capabilities.

---

## 4. Required Deltas Before v1 Acceptance (For Claude Builder)

### Code Deltas (Small & Clear)

1. **Fix `preferLocal` regression (`src/policy/residency.ts`):**
   - When `candidateFit.ok` is `true` under `{ preferLocalSoft: true }`, check whether any applicable rule has `rule.preferLocal && candidate.leavesPerimeter`; if so, search `alternatives` for an endpoint satisfying `fitsAllRules(a, applicable, { preferLocalSoft: false }).ok` and return `reroute` with `blockedResidencies: []` before falling through to `allow`.
2. **Fix `withinPerimeter` and `verify()` schema check (`src/prove/perimeter.ts`):**
   - Check `if (hops.some((h) => h.leavesPerimeter)) withinPerimeter = false;` **before** the `decision !== "allow"` branch (`FR-PRV-02`).
   - Validate `PerimeterProofSchema.safeParse(proof)` inside `PerimeterProver.verify(proof)` (and optionally export a standalone `verifyPerimeterProof` helper from `src/index.ts`) so non-conformant objects like `claimLevel: "tee_attested"` return `false` (`FR-PRV-03`).
3. **Harden demo HTTP sidecar (`src/server/main.ts`):**
   - Return `400 Bad Request` (`{ error }` without stack traces) on `SyntaxError` (malformed JSON) and `ZodError` in `POST /v1/trace` (`FR-MOD-02`).
   - Enforce 1 MiB request body limit returning `413 Payload Too Large` (`NFR-07`).
   - Fail fast (non-zero exit) when `MIREVOX_LINEAGE_RULES` is explicitly set and cannot be read/parsed/validated; only fall back to `demoRules()` when env var is unset and default config is absent (`FR-MOD-03`).
   - Update `GET /` line 151 wording from `"perimeter proof"` to `"decision checksum (PerimeterProof)"`.
   - Export a `createApp()` / server factory (guarding `server.listen` behind main-module check) so integration tests can test HTTP endpoints cleanly.
4. **Clean up CLI & JSDoc wording (`src/cli.ts`, `src/types.ts`):**
   - Remove the unimplemented `mirevox-lineage graph <correlationId>` line from `usage()` in `src/cli.ts:14`, and exit non-zero if `--rules` is passed without a path argument.
   - Update JSDoc in `src/types.ts:46` (`leavesPerimeter`: caller-declared, untrusted) and `src/types.ts:113` (`claimLevel`: SHA-256 of assembled JSON, not TEE or enforced policy).
5. **Reconcile CLI scope in `docs/requirements.md`:**
   - Commit `b60169a` overwrote `docs/requirements.md` with pre-CLI text claiming `src/cli.ts` is absent (§2.2 #6, §3.2). Either document `mirevox-lineage trace` as in-scope (matching `FR-08` and `src/cli.ts`) or remove `src/cli.ts` + `package.json` `bin`.

### Test Deltas (Must Pass Before Re-Vet)

6. **Expand unit & integration tests (`tests/`):**
   - `tests/policy.test.ts`: add tests for `createRoutePolicyHook` / `module.policyHook` parity (`FR-03`), `decision === "deny"`, `tenants` filter, priority ordering, `preferLocal: true` reroute (with `denyLeavePerimeter: false`), multi-rule `reroute` soundness (`FR-POL-03`), `"unknown"` residency rejection, `listRules()` defensive copy + atomic `replaceRules()`, and empty rules → `allow`.
   - `tests/graph.test.ts` (new): test referential integrity error, `recordAiHop` 6-node/5-edge allow/deny/local flags, `tool` + `tool_call` extensibility, `snapshot(correlationId)` isolation across two correlations (`FR-04`), and `clear()`.
   - `tests/proof.test.ts` (new): test `claimLevel` schema rejection of `"tee_attested"`, `tool_call` with `leavesPerimeter: true` (both on `allow` and `deny`), empty-edge `allow` fail-closed, and `verify()` on intact, key-reordered, tampered, and schema-invalid proofs.
   - `tests/ingress.test.ts`: add `parseIngressTag`, invalid enum `ZodError`, `Uint8Array` digest parity, absent payload (`undefined`), canary plaintext zero-leakage (`NFR-04`), and `labels` preservation + non-string rejection.
   - `tests/server.test.ts` (new): test `GET /health`, `GET /rules`, `POST /v1/trace` (`200` and `400`), `GET /graph?correlationId=`, `404`, `413` (>1 MiB), and fail-closed `MIREVOX_LINEAGE_RULES`.

---

## 5. Post-acceptance follow-up (orchestrator)

Addressed after this report against HEAD `ad1feac`+:

| Delta | Status |
| --- | --- |
| preferLocal soft reroute | Fixed in `src/policy/residency.ts` |
| Multi-rule soundness + edge-case suite | `tests/edge-cases.test.ts` 46/46 green |
| Server ZodError→400, 413 1MiB, fail-closed `MIREVOX_LINEAGE_RULES` | Fixed in `src/server/main.ts` |
| `PerimeterProver.verify` schema check | Fixed (`safeParse` before digest) |
| CLI `graph` usage / bare `--rules` | Fixed in `src/cli.ts` |
| Claim-honesty JSDoc / GET `/` wording | Fixed |
| Push to GitHub | **Still blocked** — Cursor `ghs_` 404 on private org; `GH_TOKEN` 401 |

Remaining optional: `createApp()` factory, fuller `tests/server.test.ts`, deny+leaving `tool_call` → `withinPerimeter: false` (kept decision-record semantics: non-allow stays `withinPerimeter: true`).

---

## 6. Gemini acceptance agent completion note

[Gemini: acceptance validation](bc-5e082281-da9b-5521-bf2b-746094ee2758) FAIL was against HEAD `2e63aed`. Subsequent commits through `64a8a13` closed the required code deltas (preferLocal, verify schema, sidecar 400/413/fail-closed, CLI cleanup, edge-case suite **48/48**). Remaining optional items (`createApp` factory, deny+leaving `tool_call` → `withinPerimeter: false`) are non-blocking for the locked v1 slice. Push remains App-grant / `GH_TOKEN` pending.
