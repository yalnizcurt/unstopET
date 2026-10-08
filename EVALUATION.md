# Evaluation evidence

Measurements and targets are separate. Do not treat a passing unit test as a measured attack prevention percentage.

- `platform-linux-acceptance-report.json`: expanded backend checks, real Linux agent/parser restrictions, API authority/coverage tests and forced-compromise tool proposals. 65 pass, two Mac-specific skips.
- `semantic-evaluation-report.json`: 16 authored calibration inputs with real Groq Prompt Guard 2 86M scores. At a frozen 0.9 threshold, the implemented router recovers two of eight attacks missed by rules; zero added false positives on eight benign cases. Standalone classifier flags an educational quote; the router excludes explicitly labelled educational material. Several indirect attacks remain missed.
- `semantic-heldout-report.json`: eight reserved authored language/phrasing variants, not independent authoring. Routed classifier recovers three of four attacks missed by rules, with no added false positives on four benign cases. The French variant is missed. This sample is too small for broad reliability claims.
- Attack Lab: actual same-task/model/synthetic-fixture A (unprotected application baseline), B (deterministic defense), C (routed AI) comparisons. Every external effect is simulated. Stored results separately record detector recognition, wrong winner/email intent, canary leakage, simulated executions, legitimate-task completion, latency and generation tokens. Failed/unknown outcomes stay visible. Costs are not invented.

The baseline's synthetic canary is intentionally provided to the baseline model; protected models have no grant to protected data. This is a containment test, not a universal sensitive-data discovery test. Real provider credentials never enter either model input or fixture. A model that returns the wrong winner has still followed an attacker objective even when the broker prevents email; the UI reports both facts.

Seven-category and multiformat fixtures are authored engineering evidence, not an official F3 score. Official D2 reliability and independently authored unseen attack families remain unverified. Report sample sizes and category/surface outcomes; never advertise universal protection.

## Repeatable demonstration

1. Open the hosted console with the configured demo access code.
2. Open Procurement Analyst and run the labelled synthetic supplier example. Inspect legitimate facts and the quarantined hostile line.
3. Use File Scanner for a supported artifact, then inspect original inert text, released fragments, locations and gaps.
4. Run an Attack Lab comparison; inspect actual A/B/C responses and execution decisions, then open Evaluations and Security Events.
5. Run Web Research on `https://example.com` and Developer Assistant on the fixed synthetic repository. Show cited brief and proposed inert patch.
