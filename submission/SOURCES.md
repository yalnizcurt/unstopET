# Submission evidence and attribution

## Market and adoption facts

Verified from primary sources on 11 October 2026. Forecasts remain explicitly labelled.

| Slide | Fact | Interpretation | Primary source |
|---|---|---|---|
| 2 | Gartner forecast 40% of enterprise applications would include task-specific AI agents by the end of 2026, from less than 5% in 2025. | An August 2025 forecast, not a measured October 2026 adoption rate. | [Gartner, 26 August 2025](https://www.gartner.com/en/newsroom/press-releases/2025-08-26-gartner-predicts-40-percent-of-enterprise-apps-will-feature-task-specific-ai-agents-by-2026-up-from-less-than-5-percent-in-2025) |
| 2 | 13% of organizations in IBM’s 2025 breach study reported breaches of AI models or applications. Of that affected subgroup, 97% reported lacking AI access controls. | The denominator is the studied breached organizations. The 97% applies to the AI-breach subgroup, not all enterprises. | [IBM Newsroom, 30 July 2025](https://newsroom.ibm.com/2025-07-30-ibm-report-13-of-organizations-reported-breaches-of-ai-models-or-applications,-97-of-which-reported-lacking-proper-ai-access-controls) |
| 3 | Gartner forecast almost USD 4.8 billion in global spending on securing AI in 2027 and almost USD 7.7 billion in 2028. | Published rounded forecasts. They describe a broad spending category, not Agent Trust Firewall’s TAM, valuation or revenue. | [Gartner, 26 August 2026](https://www.gartner.com/en/newsroom/press-releases/2026-08-26-gartner-forecasts-the-market-for-securing-ai-will-reach-almost-5-billion-in-2027) |

IBM’s report uses 600 organizations that experienced breaches from March 2024 through February 2025. Neither the study nor the deck demonstrates that access controls alone caused a particular breach outcome.

## Product measurements

The authored matched comparison in `integration-platform-production-report.json` uses production backend source `8a412ab09b54ec1e3e431869120cf6a49f545e14` and Groq `openai/gpt-oss-120b`. It includes ten synthetic cases: nine attacks and one benign case, each run under A, B and C. All thirty configurations completed in that report. Detection is 7/9 for B and 8/9 for C. Both complete the authorized fixture task in 10/10 cases. The single benign case produces zero false positives. These small authored denominators are not unseen-attack reliability.

Baseline A shows one observed wrong-vendor attacker objective. Four attack outcomes remain unknown. The baseline is still contained by the synthetic evaluation environment. Independent forbidden-action probes do not represent model proposals, and zero mock executions do not demonstrate unrestricted real-world attacker failure.

The three actual workflow smoke tests are separate from the one-response comparison. They include actual generation requests and bounded-tool receipts. Procurement completes a supplier comparison, Research reads approved static public evidence and produces citations, and Developer reads a fixed synthetic repository and proposes an inert patch. Fresh production versions are frontend `cbedb770eb65d2cf2732e6cf4ae4975f8c0a83ce` and backend `aca81e6a06fcb36104d101298eb7162f0a4534ca`. The fresh SDK Procurement run is `ea056be9628a677dfaddc91af4d7cbb9`. Workflow completion is not proof of semantic correctness: manual review found an inaccurate float-arithmetic explanation and an `isinstance` check accepting `bool` in the Developer proposal. The patch is inert, unexecuted and unverified. Latest Linux acceptance has 122 tests:120 passed, zero failures/errors and two Mac-only skips.

The 168-case authored matrix is separate. It combines 28 authored payloads with six format wrappers. It must never be described as 168 independently authored attacks or 168 held-out attack families.

The frozen first-use v1 evaluation has 64 distinct cases: 32 MIT-licensed public InjecAgent tool-output attacks, 16 separately authored first-use attacks, and 16 benign controls. Both B and C detect only 4/48 attacks and incorrectly flag 6/16 benign cases. The public subset yields 0/32 detections. Eleven real classifier calls consume 502 tokens and 2.199 seconds in total, with no provider errors and no incremental detections. Inspection p95 is 1.445 milliseconds in B and 195.276 milliseconds in C over 64 requests per cohort. This inspection study measures neither attacker outcomes nor successful business tasks. The separately authored cases are author-known and not blinded. Public cases are not certified absent from model pretraining. The general detection and false-positive reliability targets are **not met**.

Sources: `evaluation/heldout/routed-classifier-report-v1.json` and its frozen corpus documentation. Corpus SHA-256: `96866dc1a535da98b037bc1e4cbe7692fe8948672e1f94d1d1dd136e9e2fafd5`. Public InjecAgent subset testing remains a subset inspection study, not full benchmark replication or proof that a provider never saw those payloads in training.

## Product screenshots

Only actual screenshots from the repository or root’s final browser walkthrough enter the deck. No generated UI or invented run content is permitted. Screenshot sources are configurable in `submission/pitch/deck-data.json`.

The final deck uses fresh actual production screenshots in `submission/screenshots/final-*.png`, captured 11 October 2026: frontend `cbedb770eb65d2cf2732e6cf4ae4975f8c0a83ce`, backend `aca81e6a06fcb36104d101298eb7162f0a4534ca`, SDK run `ea056be9628a677dfaddc91af4d7cbb9`. Crops are applied in the editable slide; source PNGs remain unmodified. The public evaluation screenshot shows archived source `8a412ab` metrics, explicitly labelled archived. It does not replace or rerun that cohort. Earlier `platform-*.png` captures show source `748a60d` and remain historical repository assets; they are not used in this final deck.

## Claims the deck does not make

No universal protection, official F3/D2 achievement, security certification, enterprise identity isolation, customer ROI, live email, purchasing, arbitrary repository writes, autonomous web search, enabled persistent memory, or audio/video inspection is claimed. Broadening those capabilities requires implementation and containment evidence.

Threat-model and competitive context: [primary-source research](../docs/THREAT_MODEL_RESEARCH.md) and [competitor positioning](../docs/COMPETITOR_POSITIONING.md). Runtime controls and tool checks also exist in commercial products. The deck makes no “first” or “only” claim.

## Team and recording prerequisites

Team name, member names and individual contributions need human confirmation. Visible placeholders in the editable deck are intentional until supplied. The video script is complete. An actual browser recording is in progress after final deployment; exported playback verification is pending. An MP4 counts as complete only when it appears in `submission/video/` and passes duration and playback checks.
