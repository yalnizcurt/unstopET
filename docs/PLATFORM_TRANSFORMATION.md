# Integration-first platform implementation

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
| M6 | Real procurement, research and developer demonstrations | PENDING |
| M7 | Matched A/B/C preservation, semantic positive/miss/benign and nine-category crosswalk | PENDING |
| M8 | Source-bound Linux acceptance, CI, existing Vercel/Render and SDK/UI production verification | PENDING |

Known baseline limits: one demo principal, temporary 24-hour SQLite, authored evaluation, imperfect English OCR, unsupported binary/media regions, bounded DLP, no live effects or persistent memory. This transformation does not turn an inspection-only client into mandatory external runtime enforcement. Verification requires version-matching test evidence, not a health response.

Milestones 1–4 reuse profiles, `Firewall.handle`, current snapshots/permits, parser workers, `Store`, Groq and real Linux isolation. New registry/SDK/runtime/event checks give 99 Linux passes, two existing Mac-only skips, no failures/errors in `integration-runtime-acceptance-report.json`. A catalog-label regression reintroduced a quarantined filename; the unchanged existing test caught it and the source label was fixed. All prior 82 checks remain passing. The 60-second bounded multi-step launch uses the existing task deadline; legacy fixtures keep their original one-response path. No model chain-of-thought is stored.
