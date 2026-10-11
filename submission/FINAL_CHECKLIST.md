# Final submission checklist

Release assessment: **scoped prototype; general detector reliability is not established**. Keep the measured misses, false positives, failed provider runs and unsupported channels in the package. Team identity remains a human submission prerequisite.

## Quality gates

| Gate | Status | Evidence and qualification |
|---|---|---|
| A — Technical correctness | PASS | 122 Linux tests: 120 passed, zero failures/errors, two Mac-only skips. Frontend tests/build and actual browser checks are recorded separately. |
| B — Useful agent workflows | PASS FOR BOUNDED SMOKE / QUALITY LIMITS | Procurement, Research and Developer completed with real model calls and inspected tool receipts; the independent SDK succeeded after an archived 429. Supplier/page facts were checked. Developer’s inert proposal contains explanation/type-check issues and was not executed; see manual review in production acceptance. |
| C — Security evidence | PARTIAL / RELIABILITY OPEN | Mandatory containment and incomplete-channel withholding pass. First-use B/C detection is 4/48 with 6/16 benign flags; public subset 0/32. General reliability and benign preservation targets are unmet. |
| D — Production | PASS FOR TESTED RELEASE | Exact deployed versions and bundle equality, authorized proxy checks, credential rotation and bounded credential scans are recorded in `evidence/final-production-audit.json`, `final-deployment.json` and `access-rotation-report.json`. Actual provider failures remain archived. |
| E — Product usability | PASS FOR TESTED FLOWS | Browser checks cover desktop/mobile navigation, explicit failures, upload retries and archive/live distinctions. Tests do not constitute an independent first-time-user comprehension study. |
| F — Submission materials | TEAM / RECORDING PENDING | Twelve editable slides, twelve-page PDF, attributed metrics and actual product captures are ready. Final recording verification and real team details remain required. No submission portal upload is claimed. |

## Required deliverables

| # | Deliverable | Location |
|---|---|---|
| 1 | Deployed frontend | [Existing Vercel product](https://agent-trust-firewall.vercel.app), public `#Walkthrough` |
| 2 | Deployed backend | [Existing Render service](https://agent-trust-firewall-api.onrender.com) |
| 3 | Three working bounded agents | `evidence/production-acceptance.json`; profile constraints in `../AGENTS.md` and `../agents.py` |
| 4 | Reusable independent integration | `../examples/external_procurement_client/`, `../sdk/python/README.md`; fresh actual run in production acceptance |
| 5 | Security/runtime evidence | Actual run timelines, inspected receipts, denied forced probe and security summary in production acceptance |
| 6 | Public product walkthrough | [Read-only walkthrough](https://agent-trust-firewall.vercel.app/#Walkthrough), labelled historical results and live limitations |
| 7 | Architecture diagram | [PNG](architecture.png), [editable Mermaid](ARCHITECTURE.md), editable slide 7 |
| 8 | Threat model | `../docs/THREAT_MODEL_RESEARCH.md` and `../SECURITY.md` |
| 9 | Tested security invariants | `evidence/final-linux-acceptance.json`, `evidence/compromise-containment-report.json` |
| 10 | Frozen first-use corpus documentation | `../evaluation/heldout/README.md`, `FREEZE.json`, pinned public attribution/license |
| 11 | Detection / false-positive report | `../evaluation/heldout/routed-classifier-report-v1.json` and deterministic baseline; familiar-format results separately archived |
| 12 | Compromised-model containment | `evidence/compromise-containment-report.json`; forced proposals are not described as model-generated attacks |
| 13 | Legitimate-task success | Fresh distinctive workflows in production acceptance; authored A/B/C outcomes in `evidence/authored-production-metrics.json` |
| 14 | Known limitations | `../docs/KNOWN_LIMITATIONS.md` and first-use evaluation README |
| 15 | CI / deployment verification | Final deployment/proxy/credential-scan evidence in `evidence/`; [tested backend CI](https://github.com/yalnizcurt/unstopET/actions/runs/38158569138) |
| 16 | Exact production commits | Backend `aca81e6a06fcb36104d101298eb7162f0a4534ca`; frontend `cbedb770eb65d2cf2732e6cf4ae4975f8c0a83ce`. Confirmed deployment receipts govern these claims; later documentation commits do not become served code automatically. |
| 17 | Editable pitch deck | [PowerPoint](pitch/Agent-Trust-Firewall.pptx), twelve slides; visible team placeholders |
| 18 | Submission PDF | [PDF](pitch/Agent-Trust-Firewall.pdf), twelve pages |
| 19 | Real product screenshots | `screenshots/` for final captures; source-labelled historical captures remain in `../docs/assets/` |
| 20 | Actual browser MP4 | `video/Agent-Trust-Firewall-demo.mp4` after recording verification; evidence `evidence/production-video-report.json` |
| 21 | Demo narration | [Shot list](../docs/DEMO_VIDEO_SCRIPT.md), `video/NARRATION.md` and matching SRT |
| 22 | Updated setup README | `../README.md`, SDK/client examples and declared Linux prerequisite |
| 23 | Final checklist | This document |

## Measurement and source rules

The 64-case corpus was frozen before first scoring. Its reports preserve the original source hashes. The final empty-answer availability fix changes model-generation handling and failed-run accounting; it does not change inspection rules, router, semantic classifier, thresholds or corpus. The challenge was not rerun or retuned after seeing its misses. Its inspection-only results are not an attack-prevention percentage.

The 8a412ab authored hosted experiment is historical: 30 configurations completed, one actual baseline wrong-vendor objective was observed, and four baseline attacker outcomes were unknown. Its forced email probes are separate from model behavior. Current workflow smoke evidence does not turn those familiar fixtures into an unseen benchmark.

Before submission, enter the actual team name, members and contributions in `pitch/deck-data.json`, regenerate the deck/PDF, and review them. Do not submit visible placeholders as completed team information.
