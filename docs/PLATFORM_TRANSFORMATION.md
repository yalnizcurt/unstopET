# Historical implementation notes — before anonymous public access

This source-bound document retains the prior shared-access-code release and its original measurements. Current access and SDK migration are documented in [API integration](API_INTEGRATION.md); shared-token statements below are historical, not setup instructions.
Baseline: source `79e2d4f`, deployed API `1d953ac`, branch `codex/integration-platform`.
G0 passed on 11 October 2026: exact-source Linux Docker suite 82 pass / two Mac-only skips / zero failures or errors; frontend tests and production build pass; hosted Linux health and a real synthetic Groq call pass. Evidence: `integration-baseline-report.json`. Existing fixtures and prior reports are retained.

The change reaches the existing profiles, API task orchestration, mandatory broker, isolated runtime, acceptance tests, Docker evidence manifest, Python client/example, console navigation/pages and release documentation. Existing API callers and contained A/B/C fixtures remain compatible. Redeploy resets temporary history; public measured archives retain their original timestamps. No new privileges, paid infrastructure or microservices are introduced.

| Gate | Work | Status |
|---|---|---|
| G0 | Code/document audit, source snapshot, existing Linux/frontend/Groq/deployment baseline | PASS |
| M1 | Server-owned integration registry, truthful verification and compatible API | CODE / LINUX PASS |
| M2 | Dependency-free Python client and independent procurement application | CLIENT TESTS PASS; HOSTED PROOF PENDING |
| M3 | Maximum three model turns, narrow tools through existing broker, inspected receipts | LINUX PASS |
| M4 | Correlated run/event evidence, including failures and unknown outcomes | API / FAILURE TESTS PASS |
| M5 | Protected Agents / Runtime / Incidents / Lab / Integrations console | COMPONENTS / BUILD PASS; BROWSER PROOF PENDING |
| M6 | Real procurement, research and developer demonstrations | REAL LINUX SMOKES PASS; HOSTED PENDING |
| M7 | Matched A/B/C preservation, semantic positive/miss/benign and nine-category crosswalk | PENDING |
| M8 | Source-bound Linux acceptance, CI, existing Vercel/Render and SDK/UI production verification | PENDING |

Known baseline limits: one demo principal, temporary 24-hour SQLite, authored evaluation, imperfect English OCR, unsupported binary/media regions, bounded DLP, no live effects or persistent memory. This transformation does not turn an inspection-only client into mandatory external runtime enforcement. Verification requires version-matching test evidence, not a health response.

Milestones 1–4 reuse profiles, `Firewall.handle`, current snapshots/permits, parser workers, `Store`, Groq and real Linux isolation. New registry/SDK/runtime/event checks give 99 Linux passes, two existing Mac-only skips, no failures/errors in `integration-runtime-acceptance-report.json`. A catalog-label regression reintroduced a quarantined filename; the unchanged existing test caught it and the source label was fixed. All prior 82 checks remain passing. The 60-second bounded multi-step launch uses the existing task deadline; legacy fixtures keep their original one-response path. No model chain-of-thought is stored.

The final predeployment gate passes 108 Linux checks, with two Mac-only skips and zero failures/errors. Real procurement returns the expected missing-currency table; research returns a cited Orion/Vega brief; developer makes a brokered read and inert patch request across three model turns. Native Groq proposals remain inert, namespaced declared function names are normalized, malformed/empty completions fail safely, and redundant research reads are constrained. Protocol failures remain separate from correctness claims. See `integration-real-predeployment-report.json`. Frontend navigation/inventory tests and the production build pass. CI for the first implementation commit passed; the final source revision is rechecked before promotion.

Hosted testing retained four failed native research completions on backend `4eefbc1`. The constrained text-completion correction passes an actual two-turn Groq research workflow and the full updated suite: 109 Linux passes, two Mac skips, zero failures/errors. It preserves Context Builder ownership and rejects native calls after the approved read. The Vercel same-origin route independently passes 401/403/422 and private/no-store checks. These corrections do not relax broker permissions; the prior hosted attempt remains in `integration-platform-prior-deployment-report.json`.

Terminal completion was also corrected for procurement and the last developer turn, with server-owned instructions and a rejection test for native calls when functions are disabled. Current backend `91e06d6` passes 110 Linux checks (112 total, two Mac-only skips) and both GitHub CI runs. Its independent hosted SDK passes eleven checks. Subsequent research calls hit the 20B daily token quota; complete failed runs are retained in `integration-platform-20b-quota-report.json`, with bounded diagnostic categories in `integration-provider-quota-report.json`. Model compatibility and final hosted acceptance are reported separately.

All three real Linux workflows pass with the compatible 120B configuration before promotion; the retained initial 120B developer finishing failure is in `integration-120b-predeployment-attempt.json`, and the corrected developer pass is in `integration-real-linux-120b-developer-smoke.json`. Backend `8a412ab` has 110 Linux passes and successful main/branch CI, and Render is live with that source. Final hosted comparisons use 120B consistently; no model upgrade grants a capability.
