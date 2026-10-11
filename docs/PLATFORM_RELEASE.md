# Historical integration-first platform release — 11 October 2026

This page retains the 8a412ab release and its earlier screenshots. The final release, new challenge failures and current verification are indexed in [submission](../submission/README.md). The five captures below were taken from backend 748a60d; the separately preserved 8a412ab report has newer workflow evidence.

The target architecture extends the verified firewall rather than replacing it. Production proof, deployed source and outcomes are recorded in `integration-platform-production-report.json` after hosted acceptance. Historical submission measurements remain separately versioned.

## Module map

| Module | Implementation and reuse |
|---|---|
| `integrations.py` | Five server-owned registrations, declared boundaries/capabilities and source-matching Linux verification; no client-editable grants |
| `sdk/python` and external procurement application | Dependency-free HTTPS client and separate executable application; actual uploads and hosted execution, safe failures and central run inspection |
| `runtime_tools.py` | Exact per-profile schemas and deterministic comparison of released supplier facts; conflicting prices/currencies cannot be ranked, missing terms stay missing |
| `firewall.py` | Existing mandatory dispatcher, ownership/current snapshots, disclosure checks and immutable email permits reused; bounded tool receipts, source IDs and actual event metadata added |
| `agent_runtime.py`, `gate1.py`, `linux_guard.py` | Real sealed Linux process; at most three model turns/two model-selected tool requests; existing task deadline, no direct model/network/shell/files/credentials/MCP |
| `groq_ai.py` | Existing TLS/budget/error gateway; only declared local function proposals, exact argument validation, optional `functions.` namespace normalization and nonempty public completion data |
| `api.py` | Existing API/parser/store reused for registered hosted workflows, inspected tool receipts, new snapshots, correlated runs/incidents, retained failures and scoped verification |
| `runtime_events.py` | Server-generated chronology with run, integration, tool, artifact/fragment and snapshot references; no private reasoning or model-asserted security outcomes |
| Existing parsing/inspection/semantic modules | Same isolated extraction, completeness, deterministic rules, selective Prompt Guard, policy and fragment sanitization for inputs and tool results |
| `evaluation.py` | Matched A/B/C fixture preserved; actual per-configuration run traces and independent forced denials added, context differences disclosed |
| `frontend/src/app`, `pages`, `components` | React/Vite console organized around Protected Agents, Runtime Activity, Incidents, Policies, Lab, Integrations and Settings; existing workspaces, scanner, investigation and saved comparisons preserved |

## Authority and execution

Server policy controls instructions and capabilities. Authenticated intent is separate from pasted/attached evidence. The child can reference only its current server-issued context and narrow tools. A model proposal does not authorize execution. Released tool text is inspected before another model step. Mock email remains subject to the original independent authorization/permit/DLP path; public profiles do not receive a sending grant. Persistent memory always rejects writes.

Native Groq function declarations are local proposals, not Groq-hosted browser/code execution or remote MCP. The optional public finishing function is response data, not a side effect. Completed workflow operations and the last allowed model turn disable all function proposals and return public text through final-output DLP. Provider errors are bounded codes, and empty responses cannot become successful releases. Earlier malformed finishing proposals remain documented as availability failures; no security restriction was disabled to make a workflow pass.

## Verification

Current Linux acceptance: 110 passed checks, zero failures/errors, two Mac-only skips. The report hashes the actual backend modules; a missing or changed-source report cannot establish `PROTECTION_VERIFIED`. Startup repeats real containment before credentials/listening. The native Mac runtime remains unavailable.

Frontend route/inventory checks and the production build pass. Live acceptance additionally exercises the separate SDK application, useful procurement output, research/developer workflows, source-correlated timelines, actual denials, inspection completeness, A/B/C outcomes and desktop console operation; current mobile visual verification remains unavailable. A healthy endpoint alone is insufficient evidence.

## Measured scope and limitations

Read [coverage](../COVERAGE.md), [known limitations](KNOWN_LIMITATIONS.md), [evaluation](../EVALUATION.md) and the [nine-category crosswalk](OFFICIAL_CATEGORY_CROSSWALK.md). An inspection-only client is not external runtime enforcement. The hosted SDK protects our hosted agent; it does not secure arbitrary external tools. Inference proxy, MCP gateway, enterprise tenant identity, durable audit storage, live effects, persistent memory, broad correlation and contextual escalation remain unavailable.

History is temporary for 24 hours/300 total records and can disappear on Render restart. Public archived measurements retain their original source/time. The corpus is authored and small; unknown outcomes, classifier misses, provider failures and citation/patch-quality limits remain explicit. No universal immunity, official F3/D2 achievement, security certification or portal submission is claimed.

## Demonstration

Use [the five-minute walkthrough](PLATFORM_DEMO.md). The flagship sequence is external application → four documents → hidden workbook quarantine → brokered scoring → inspected result → next real model turn → useful recommendation → independent forbidden-email denial with zero executions. Open that same actual run in the console.

Architecture: [product flow and sequence diagrams](../ARCHITECTURE.md). Console: https://agent-trust-firewall.vercel.app. API: https://agent-trust-firewall-api.onrender.com. Documentation: https://agent-trust-firewall-api.onrender.com/api/docs.

## Console evidence

Screenshots are captured from the actual deployed console, not mockups: [registered agents](assets/platform-agents.png), [SDK onboarding](assets/platform-integrations.png), [runtime trace](assets/platform-runtime.png), [hidden-sheet quarantine](assets/platform-artifact.png) and [linked denial](assets/platform-incident.png). Retained screenshot/run versions are identified in the production report. Current mobile verification was attempted, but the enabled browser ignored the viewport override; no mobile pass is claimed.

## Deployed versions

Backend: `8a412ab09b54ec1e3e431869120cf6a49f545e14`, Render `dep-db5pi9gae00c739tr9r0`. Frontend: `55402d35244f6ec6228e2ad8e1a1f65878fea072`, Vercel `dpl_EE5k2ApCQLNXv4BHYbBQM8PRQtVA`; its frontend tree is unchanged in the backend commit. Current generation uses Groq `openai/gpt-oss-120b`; the semantic detector remains Prompt Guard 2 86M. The prior 20B SDK pass and daily-quota failures remain separately archived. Final comparisons report the actual configured model and do not combine models into one metric.

Both CI runs for the backend commit pass: [main acceptance](https://github.com/yalnizcurt/unstopET/actions/runs/38146156252) and [implementation branch acceptance](https://github.com/yalnizcurt/unstopET/actions/runs/38146154295). The current frontend build matches deployed `index-BLaz44sv.js` and `index-Le_FxxIE.css`. Linux acceptance and live startup containment remain the basis for scoped integration verification.

## Required deliverable index

| Requested artifact | Working source / evidence |
|---|---|
| Final architecture | `ARCHITECTURE.md`: integration flow and real tool/inspection sequence |
| Module-by-module summary | Table above; reused controls and enabled limits are explicit |
| SDK example | `sdk/python/README.md` and executable `examples/external_procurement_client/app.py` |
| Integration verification | Source-matching Linux report plus hosted registry/startup evidence in production report |
| Execution trace | Actual external SDK run, timeline, artifact and snapshot references in production report/console |
| Attack demonstration | Hidden workbook, independent broker denial and matched A/B/C results; unknowns remain visible |
| Security regressions | `platform-linux-acceptance-report.json`, 110 pass / two skips / zero failures; current CI links above |
| Known limitations | `docs/KNOWN_LIMITATIONS.md`, supported coverage and scoped verification |
| Vercel URL | https://agent-trust-firewall.vercel.app |
| Render API URL | https://agent-trust-firewall-api.onrender.com |
| Exact deployed version | Backend and frontend identities above; reported separately from later documentation commits |
| Five-minute demo | `docs/PLATFORM_DEMO.md`; external application first, real trace and useful task outcome |

## Optional capabilities excluded

No arbitrary registration endpoint, inference proxy, MCP gateway, enterprise identity, persistent memory, broad cross-source attack graph, contextual LLM escalation, live purchasing/email, test execution, dynamic web execution, QR decoder or unimplemented media adapter was enabled. They are not required for the demonstrated hosted SDK scope and need their own authorization/containment gates.
