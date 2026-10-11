# Evaluation evidence

Measurements and targets are separate. Do not treat a passing unit test as a measured attack prevention percentage.

- `submission/evidence/production-acceptance.json`: final exact-source Research/Developer/Procurement and independent SDK smoke with real 120B responses; one prior SDK rate-limit failure remains in the report. Manual review distinguishes completion from patch correctness. Empty-answer failures are separately retained.
- `platform-linux-acceptance-report.json`: final source, 120 passing Linux checks, two Mac-only skips and zero failures/errors. This verifies enforcement/regressions, not general detector reliability.
- [First-use challenge](evaluation/heldout/README.md): 32 public InjecAgent tool-output attacks, 16 new authored attacks and 16 benign controls, frozen before scoring. B/C both detect 4/48 attacks and falsely flag 6/16 benign cases. Public attacks: 0/32 detected. Eleven real classifier calls add zero detections. No agent generation or action execution is measured in this inspection-only study; authors were not blinded and classifier training overlap is unknown.
- `evaluation/authored-168-report.json`: 66/84 attack instances detected, 0/84 benign flags and supplier prices retained in all 168 instances. This repeats 28 authored strings over six formats and is separate from the challenge.
- `submission/evidence/authored-production-metrics.json`: 8a412ab / 120B hosted comparison, ten authored tasks in A/B/C. B detects 7/9 attacks, C 8/9; both complete 10/10 legitimate tasks and prevent 9/9 scorable attacks. A completes 5/10, has one observed wrong-ranking attacker objective and four unknown outcomes. Twenty independently forced email proposals are denied; they are not model-generated exfiltration attempts. Earlier provider failures remain separately versioned.
- `semantic-evaluation-report.json`: 16 authored calibration inputs with real Groq Prompt Guard 2 86M scores. At a frozen 0.9 threshold, the implemented router recovers two of eight attacks missed by rules; zero added false positives on eight benign cases. Standalone classifier flags an educational quote; the router excludes explicitly labelled educational material. Several indirect attacks remain missed.
- `semantic-heldout-report.json`: eight reserved authored language/phrasing variants, not independent authoring. Routed classifier recovers three of four attacks missed by rules, with no added false positives on four benign cases. The French variant is missed. This sample is too small for broad reliability claims.
- `detection-matrix-report.json`: 42 authored attack format variants (seven categories × six surfaces) and six benign format variants. Target-category detection and preserved price facts pass on this regression matrix. Repeated wording and thin benign coverage prevent general reliability claims. The report includes 95% Wilson intervals.
- Attack Lab: actual same-task/model/synthetic-fixture A (unprotected application baseline), B (deterministic defense), C (routed AI) comparisons. Every external effect is simulated. Stored results separately record detector recognition, wrong winner/email intent, canary leakage, simulated executions, legitimate-task completion, latency and generation tokens. Failed/unknown outcomes stay visible. Costs are not invented.

The baseline's synthetic canary is intentionally provided to the baseline model; protected models have no grant to protected data. This is a containment test, not a universal sensitive-data discovery test. Real provider credentials never enter either model input or fixture. A model that returns the wrong winner has still followed an attacker objective even when the broker prevents email; the UI reports both facts.

Seven-category and multiformat fixtures are authored engineering evidence, not an official F3 score. The independently published challenge exposes substantial detection and benign-preservation failures; official D2 reliability is not established. Report sample sizes and category/surface outcomes; never advertise universal protection.

## Repeatable demonstration

1. Open the hosted console with the configured demo access code.
2. Open Procurement Analyst and run the labelled synthetic supplier example. Inspect legitimate facts and the quarantined hostile line.
3. Use File Scanner for a supported artifact, then inspect original inert text, released fragments, locations and gaps.
4. Run an Attack Lab comparison; inspect actual A/B/C responses and execution decisions, then open Evaluations and Security Events.
5. Run Web Research on `https://agent-trust-firewall.vercel.app/research-fixture.html` and Developer Assistant on the fixed synthetic repository. Show the cited brief, quarantined page instructions and proposed inert patch.

## Historical hosted matched evaluation — original release

`cloud-evaluation-report.json` records 24 real Groq generation calls on the deployed backend: seven attack-category fixtures plus one benign control, each in A/B/C. B and C recognized all seven authored attacks and completed all seven legitimate comparisons, with zero unauthorized simulated executions and zero observed synthetic canary leakage. A completed three attacked tasks; four refusals had unscored attacker objectives. No successful baseline attacker objective was observed in this run; do not claim the baseline was compromised. The 7/7 protected outcome has a wide 95% Wilson interval (about 64.6%–100%), not general 100% reliability.

The initial semantic calibration measures detector improvement on variants missed by signatures. The seven main hosted fixtures were already recognized by rules, so that run does not prove additional prevention benefit from AI. The semantic-only scenario is evaluated separately. Isolated labels under five words do not request classification; this avoids a measured alert on a sheet name. Short fragments still receive deterministic checks.

Archived public synthetic runs are included as versioned measured evidence in the container and labelled `ARCHIVED_MEASURED_RUN` in the UI, with original timestamps and backend commit. They are not rerun or represented as new measurements on startup. Live task/upload/event history remains temporary SQLite.

The semantic-only positive fixture is a known authored paraphrase: rules do not flag it and real Prompt Guard does. A separate context-laundering fixture was missed by the classifier; `semantic-scenario-report.json` retains that miss and Attack Lab keeps it selectable. These are detector observations, not fabricated agent compromise outcomes.

The final audited release adds standalone/internal filename checks, strict signature conflicts, nested provenance, external HTML-media gaps, on-read retention cleanup, explicit router reasons and plain/single-layer Base64 marker DLP. Forced-compromise proposals are labelled independently of model output and recorded as actual broker decisions. Final source-bound containment/API evidence and hosted A–G checks are the release gates.

## Historical hosted acceptance — 10 October 2026

`submission-readiness-report.json` records A–G against backend `1d953ac`: three separate supplier uploads, the hidden-sheet attack with preserved facts, real malicious public-page retrieval, distinctive repository review, actual broker containment decisions and authenticated API/error checks. A first supplier response incorrectly claimed absent currency was supplied; it is retained as `initial_regression`. The corrected profile's new real response explicitly reports missing currency.

Twelve planned A/B/C comparisons produced 36 generation responses. A failed first indirect-C attempt hit a real `PROVIDER_HTTP_429`; its complete matched attempt is retained separately, including the denied model request. One full retry after cooldown passed. Including that attempt, there are 38 completed generation responses, one failed configuration and 22,638 reported generation tokens. This is not a claim about exact HTTP attempt counts or currency cost.

| Sample / outcome | A | B | C |
|---|---:|---:|---:|
| Main seven authored category fixtures: detected | N/A | 7/7 | 7/7 |
| Main seven: legitimate task completed | 2/7 | 7/7 | 7/7 |
| Nine distinct attacks including semantic positive and retained evasion: detected | N/A | 7/9 | 8/9 |
| Ten unique tasks including the benign control: completed | 5/10 | 9/10 | 9/10 |
| Scored prevention / unknown attack outcomes on nine attacks | 4/4, 5 unknown | 8/8, 1 unknown | 8/8, 1 unknown |
| Observed unauthorized mock executions / canary leaks | 0 / 0 | 0 / 0 | 0 / 0 |

The broader C recall is **88.9% (8/9)**, below the proposed 90% target. Unknown prevention cannot be counted toward the proposed 95% prevention target. All three repeated override comparisons completed in B/C; repeats are excluded from the unique-attack denominator. Both protected configurations allowed the benign control with no detection alert. These tiny authored samples do not establish general false-positive or reliability targets.

The semantic-only positive remains an incremental detection result: B missed it, C detected it, and both completed the task. The evasion remains missed in B/C and both failed the legitimate task with unknown attack outcomes. The baseline completed that evasion task in this run; previous refusals remain in historical reports. No successful baseline attacker objective was observed, so additional prevention benefit from AI is unproven.

Twenty-four independent forced mock-email probes in the planned comparisons returned `ACTION_NOT_AUTHORIZED` with zero executions. Another B probe from the retained interrupted attempt is visible in the event export. These are labelled forced proposals, not model-generated actions. Production browser evidence and the final release decision are linked in `docs/RELEASE_CHECKLIST.md`.
