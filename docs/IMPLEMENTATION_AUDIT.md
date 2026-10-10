# Implementation audit

What this repo does: Agent Trust Firewall runs three Groq-powered agents behind one server-controlled inspection and execution boundary. A React console exposes file inspections, task results and contained A/B/C evaluations. This audit assumes one synthetic/public hackathon demonstration at a time; shared demo identity and temporary history are not enterprise multi-tenant infrastructure.

Audit baseline: deployed backend `e606ecb`, Vercel production console, source and its pending explicitly labelled containment experiment. Evidence: `platform-linux-acceptance-report.json` (70 passing, two Mac-only skips at audit), `cloud-platform-smoke-report.json` (three real agents, seven adapter uploads, rejected authority/private-network requests), authored detector/semantic reports and recorded browser navigation checks. Final revised-source deployment and walkthrough remain pending at this audit snapshot.

| Area | State | Evidence / remaining work |
|---|---|---|
| Shared input/context/action/output firewall | COMPLETE | `firewall.py`, `api.py`, Linux containment and API tests; all three agents share these paths |
| Context snapshots, role authority, expiry/resource checks | COMPLETE | Server roles only; forged roles, stale/cross-binding snapshots, revocation and payload mutation tests |
| Parser isolation and processing budgets | COMPLETE | Real credential-free Linux parser probes, seccomp/Landlock, timeout/expansion/fragment limits |
| Top-level filename inspection | MISSING | `extractors.py` inspects archive member names but misses a standalone hostile filename; P0 correction below |
| Strict extension/magic consistency | PARTIAL | PDF/OOXML/image adapters require magic, but a known binary signature renamed to text can use the text adapter; P0 correction below |
| Seven named attack-category fixtures | COMPLETE | 42 authored category/surface variants; actual hosted A/B/C seven-category run. Limited authored evidence, no official F3 certification |
| Semantic routing | COMPLETE | Real Prompt Guard scores; calibration/reserved authored variants and positive/missed hosted scenarios; substantial unseen-attack gaps |
| Contextual LLM escalation / correlation | MISSING | Optional advanced defenses remain disabled; no safety claim depends on them |
| Memory read/write | MISSING | Persistent memory disabled and writes denied; optional until enforcement tests pass |
| DLP / immutable permits / replay prevention | COMPLETE | Independent disclosure policy and exact-payload/revocation tests; limited patterns and confidential lineage |
| Groq gateway, retry, limits, usage | COMPLETE | Real `openai/gpt-oss-20b` and `llama-prompt-guard-2-86m`; bounded failures, tokens and HTTP retry tests |
| Procurement / Research / Developer | COMPLETE | Hosted distinct workflows: comparison, controlled public-page brief, synthetic repo bug review/inert patch |
| TXT/HTML/PDF/DOCX/XLSX/ZIP | COMPLETE | Declared-channel tests and live scans; complex/embedded/dynamic regions explicitly withheld |
| PNG/JPEG OCR | PARTIAL | Real English OCR detected an image attack; recognition uncertain, QR unsupported; always partial |
| Tier 3 media / test execution / live email | MISSING | Explicitly disabled; no unrestricted shell or paid capability added |
| Console navigation/workspaces/scanner/investigation | COMPLETE | Nine routes and desktop/mobile layout checks; actual workbook upload shows hidden attack and preserved facts |
| Policy/settings viewers | COMPLETE | Read-only server-managed values; no editable privilege controls |
| Attack Lab and measured A/B/C outcomes | COMPLETE | Actual model calls, containment and scoring; refusals stay unknown rather than fabricated success |
| Visible forced-compromise experiment | PARTIAL | `evaluation.py`, `api.py`, UI and test implemented and passing; production rollout pending |
| Authentication/resource access | PARTIAL | Enforced shared demo access code, HTTPS/CORS/strict schemas; multi-user identity is intentionally absent |
| SQLite retention | BROKEN | Reads can return a record older than 24 hours until a later write; P1 correction below |
| Durable live audit/user history | MISSING | No authorized suitable database provisioned; free Render filesystem temporary. Public measured archives survive image rebuilds |
| Rate limiting/jobs | COMPLETE | One admitted mutating job, 15/minute budget; explicit busy/outage errors; no unbounded queue |
| Deployment | PARTIAL | Existing Vercel/Render live and isolation verified; final source changes and A–G walkthrough pending |
| Submission documents/package | MISSING | Add requested audit/checklist/limits/integration/submission and six actual diagrams; no portal submission claimed |

## Must fix

1. **Standalone filename is never inspected** (`extractors.py`, `inspection.py`, parser tests).
   What this is: filenames are external evidence. Problem: `Ignore previous instructions.txt` creates no filename detector signal. Fix: inventory the filename through the shared inspector, preserving body coverage independently. If skipped: filename attack coverage is overstated. Verify a hostile root name, benign file and empty-content coverage.
2. **Known binary content can be relabelled as text** (`extractors.py`).
   What this is: the extension chooses a parser after signature checks. Problem: an ASCII PDF renamed `.txt` can receive complete text coverage rather than a format mismatch. Fix: reject known signature/extension conflicts and wrong signatures for declared binary formats. If skipped: declared format coverage is misleading. Verify PDF/text and PNG/JPEG mismatch cases.
3. **Retention is enforced only on writes** (`storage.py`).
   What this is: demo records promise a 24-hour lifetime. Problem: a read-only session can continue retrieving expired records. Fix: prune expired records under the existing store lock before reads. If skipped: retention statements are false. Verify expiry and another principal's isolation without a new write.
4. **The new containment change drops failed-run decisions** (`evaluation.py`).
   What this is: the pending change moved audit capture past the completion check. Problem: a failed protected run loses its denial timeline. Fix: capture actual audit before checking completion and after the labelled probe. If skipped: failures become less reviewable. Preserve failed outcomes and verify the final report.
5. **Required submission proof is unfinished** (`docs/`, `SUBMISSION.md`, hosted UI).
   What this is: working modules are not submission acceptance. Problem: three separate supplier uploads, malicious public tool output and final visible containment have not yet been verified on the final deployment. Fix: execute A–G and write the evidence-backed package. If skipped: release remains NOT READY TO SUBMIT.

## Should fix

6. **Malformed URL ports appear as service failures** (`network.py`, URL tests).
   What this is: URL parsing precedes destination validation. Problem: `https://example.com:bad/` raises outside the bounded denial handler. Fix: turn parse/port errors into an explicit invalid-URL denial. If skipped: user input causes a misleading unavailable-service response.
7. **Detector scores look like security percentages** (`frontend/src/main.tsx`).
   What this is: the investigator prints a percentage for every signal. Problem: a rule match or raw Prompt Guard score is not a calibrated safety probability. Fix: label rule matches and raw uncalibrated classifier scores explicitly. If skipped: evidence is easy to overinterpret.

8. **Released educational quotations were sanitized a second time** (`api.py`, `firewall.py`).
   What this is: the shared inspector allows labelled educational data. Problem: the legacy text importer replaces the same quotation afterward. Fix: let only the trusted application import already-inspected released fragments without repeating the legacy scanner. Runtime requests cannot choose this path. If skipped: legitimate security-analysis content is unnecessarily lost. Verify the exact quote reaches server-built evidence without gaining authority.

9. **Unknown browser hashes produce a blank workspace** (`frontend/src/routing.ts`).
   What this is: the route parser accepts arbitrary hash text. Problem: `#missing-page` has no enabled screen. Fix: fall back to Overview for unregistered routes; verify the routing helper. If skipped: direct links can appear broken.

10. **Extra selected files are silently dropped** (`frontend/src/main.tsx`).
   What this is: the uploader sliced selections to eight. Problem: selecting nine files showed no error while omitting one. Fix: reject oversized selections explicitly before network work; verify the visible error and unchanged scan count. If skipped: users can mistake omitted files for inspected evidence.

11. **External HTML media and nested ZIP locations understate coverage** (`extractors.py`).
   What this is: images/styles are outside static HTML extraction, and nested archives can repeat child names. Problem: image-only HTML did not show the omitted channel; two nested README files had indistinguishable locations and no retained nested inventory. Fix: declare media/style gaps and preserve full parent paths/child trees, including internal OOXML filenames. If skipped: investigation and completeness are misleading. Verify partial HTML media and a two-branch nested archive with a hostile child filename.

12. **Single-layer Base64 can hide a configured secret marker** (`firewall.py`, `inspection.py`).
   What this is: DLP originally matched plain configured markers only. Problem: a Base64-encoded `SYNTHETIC-SECRET-PAYROLL` could pass inspection/provider egress. Fix: share one bounded redaction check for plain and single-layer standard/URL-safe Base64 markers across inspection and egress; keep confidential-lineage restrictions independent. If skipped: a basic encoding bypass remains. Verify redacted stored artifacts, zero provider calls for encoded intent and denied encoded model output. This remains limited DLP, not universal decoding.

13. **Safe release labels dropped the fetched-page URL** (`api.py`).
   What this is: safe provenance labels are separately generated by the inspector. Problem: the read broker prefixed only the original location, leaving the model without the URL needed for citations. Fix: attach the approved source URL to both original and released locations. If skipped: research citations can lose their source. Verify the URL in actual server-built model evidence and the final hosted research report.

Verdict: preserve the working security architecture; fix the bounded input/retention/reporting defects and complete final hosted acceptance before release.

## Final-run regression

14. **Procurement invented complete currency/terms information** (`agents.py`).
    A real three-document Groq run returned correct prices/delivery/warranty but claimed absent currency was supplied. Its narrow-space supplier name also exposed an overly strict ASCII assertion. The server profile now explicitly requires "Currency not specified" and "Not provided" for absent fields. The acceptance check normalizes Unicode spacing, preserves the original response and requires the missing-currency disclosure in a fresh real run. This is a model-quality correction; no hardcoded answer replaces inference.

Not checked: third-party parser internals, independent unseen attack authoring, high-concurrency/multi-instance deployments, a submission portal or an external security certification. No dependency or infrastructure replacement is needed for the demonstrated scope.


15. **Reopening a task did not restore its sources** (`frontend/src/main.tsx`).
    History displayed the prior research result alongside the default example URL. The existing history action now restores actual broker URLs, repository selection and user-supplied artifacts. A production browser assertion verified the malicious research fixture URL was restored.

16. **Mobile table reasons became narrow vertical text** (`frontend/src/style.css`).
    The global table could squeeze long security reasons into a tiny column. A minimum-width rule and unbroken timestamp/decision labels keep evidence tables readable inside their existing horizontal scroll container; no page-wide overflow is permitted. Final mobile visual verification is recorded with the release evidence.

17. **Saved evaluation selectors did not match the displayed result** (`frontend/src/main.tsx`).
    Reopening a measured semantic comparison left the default override selected. The history action now restores the recorded agent, scenario and surface. Changing a selector clears the old comparison, and selectors are disabled during execution. A browser assertion verifies restored values and stale-result clearing.

## Final resolution

Findings 1–17 are corrected and verified for the disclosed synthetic/public demonstration scope. The initial state table above is the audit snapshot, not the final implementation state. Backend source hashes match the 82-pass Linux report. Hosted A–G evidence, the retained rate-limit failure, supplier-quality regression and browser evidence are in `submission-readiness-report.json`.

| Final capability group | State | Verified scope / limit |
|---|---|---|
| Mandatory input/context/action/tool-output/DLP controls | COMPLETE | Shared core, immutable permissions/payloads, actual Linux bypass probes, exact source-bound tests |
| Filename/magic/retention/provenance/router/reporting corrections | COMPLETE | Targeted regressions and hosted artifact/error checks |
| Three distinct protected Groq workflows | COMPLETE | Three clean supplier documents plus hostile workbook; public malicious page brief; fixed repository review |
| Enabled nine-screen console and Attack Lab | COMPLETE | Actual file upload/task/comparison, evidence drill-down, policy/history/theme/error controls; desktop/mobile checks |
| Seven engineering attack categories | COMPLETE | Authored seven-category hosted runs and 42 format variants; official F3 achievement remains unverified |
| Semantic generalization / D2 reliability | PARTIAL | Measured incremental detection; final broader C recall 8/9, retained evasion and unknown prevention; no independent reliability claim |
| Tier 1/Tier 2 declared parser channels | COMPLETE | Profile `atf-extract-v2`; gaps/unsupported regions explicitly withheld |
| Raster images | PARTIAL | Tested English OCR and metadata; QR/recognition guarantees absent |
| Shared demo authentication / temporary retention | COMPLETE | One authenticated principal, explicit origins, bounded temporary SQLite; not enterprise tenant identity |
| Durable live multi-user storage | MISSING | Not provisioned or claimed; public archived test evidence is versioned in Git |
| Optional memory / correlation / contextual LLM / Tier 3 / live effects | MISSING | Disabled; no direct network/shell/MCP escape route enabled |
| Deployment and submission preparation | COMPLETE | Verified Vercel/Render, actual reports, six diagrams, timed walkthrough and screenshots; portal submission/recording not performed |

Final decision: **READY WITH DISCLOSED LIMITATIONS** for the tested hackathon demonstration. The extended detection target and general reliability targets are not established. See `docs/RELEASE_CHECKLIST.md` and `EVALUATION.md` for denominators and unresolved capability limits.
