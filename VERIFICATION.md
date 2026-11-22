# Verification & Smoke Screen Report — `data-lineage`

| Field | Value |
| --- | --- |
| **Module** | `Mirevox/data-lineage` (`@mirevox/data-lineage`) |
| **Package Version** | `0.1.0` |
| **Verification Status** | **VERIFIED** |
| **Verified At (UTC)** | `2026-11-22T21:11:27Z` |
| **Environment** | Node `v22.14.0`, Vitest `5.1.1`, Docker `linux/amd64` (`sherali` Docker Engine `29.8.1`) |

## Automated Typecheck, Build & Test Suite

- `tsc -p tsconfig.json --noEmit` and `tsc -p tsconfig.json`: **PASS** (exit `0`)
- `vitest run`: **PASS (5/5 test files, 64/64 tests passed, 0 failed)** — includes caller `correlationId` preservation test for `POST /v1/trace` and `GET /graph?correlationId=`.

```text
[2m Test Files [22m [1m[32m5 passed[39m[22m[90m (5)[39m
[2m      Tests [22m [1m[32m64 passed[39m[22m[90m (64)[39m
```

## Live Residency Trace & Graph Smoke Test

- Verified live `POST /v1/trace` integration with `smart-router` creating `5` lineage graph edges queryable via `GET /graph?correlationId=`:
  `HTTP 200, router.mirevox.trace_id=trace-audit-e2e-2026, lineage_edges=5, evals_turns_matching=1`

## Container & Hygiene Verification

- Standalone Linux/x64 Docker image built cleanly: `mirevox/data-lineage:x64-verify 386b1f479e3f 249MB`
- Workspace hygiene & security scan: `repos=9, all_docs_license_compose=True, hardcoded_paths=0, secret_hits=0, src_todo_hits=0`

## Reproduce Locally

```bash
npm run typecheck && npm run build && npm test
```
